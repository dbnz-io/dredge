"""Secret scanning across Huawei profiles and their accessible IAM projects."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import inspect
import os
import re

from ..secret_scanning import _SEVERITY_ORDER
from .auth import HuaweiAuthError
from .config import HuaweiAuthConfig
from .hunt import CONFIG_SCANNERS, HuaweiIRHunt, validate_scan_options
from .models import OperationResult
from .profiles import IamDiscovery, load_profiles
from .services import HuaweiServiceRegistry
from .profile_sweep import _identities, _safe_error, _selection


_PERMISSION_ACTIONS = {
    ("functiongraph", "list_functions"): "functiongraph:function:listFunctions",
    ("functiongraph", "show_function_config"): "functiongraph:function:getFunctionConfig",
    ("ecs", "list_servers_details"): "ecs:cloudServers:listServersDetails",
    ("ecs", "show_server"): "ecs:cloudServers:showServer",
    ("cae", "list_environments"): "cae:environment:listEnvironments",
    ("cae", "list_applications"): "cae:application:listApplications",
    ("cae", "list_components"): "cae:component:listComponents",
    ("cae", "list_component_configurations"): "cae:component:listConfigurations",
    ("modelarts", "list_training_jobs"): "modelarts:trainJob:list",
    ("modelarts", "show_training_job_details"): "modelarts:trainJob:get",
    ("modelarts", "list_infer_services"): "modelarts:service:list",
    ("servicestage", "show_environments"): "servicestage:environment:list",
    ("servicestage", "show_applications"): "servicestage:app:listApplication",
    ("servicestage", "show_application_configuration"): "servicestage:app:getConfiguration",
    ("servicestage", "show_components_in_application"): "servicestage:app:listComponent",
    ("servicestage", "show_component_info"): "servicestage:app:getComponent",
    ("dataartsstudio", "list_workspaces"): "DataArts Studio workspace list permission",
    ("dataartsstudio", "show_factory_env"): "DataArts Studio environment read permission",
    ("dataartsstudio", "list_dataconnections"): "DataArts Studio connection list permission",
    ("dataartsstudio", "show_dataconnection"): "DataArts Studio connection read permission",
}


def _permission_diagnostics(profile, scope):
    """Translate sanitized Huawei 403 operation errors to IAM v5 actions."""
    diagnostics = []
    context = ", ".join(f"{key}={scope[key]}" for key in ("region", "project_id") if scope.get(key))
    for error in scope.get("errors", []):
        match = re.search(r"([a-z_]+)\.([a-z_]+) failed \(HTTP (\d+)\)", error, re.I)
        if not match or match.group(3) != "403":
            continue
        service, operation = match.group(1).lower(), match.group(2).lower()
        action = _PERMISSION_ACTIONS.get((service, operation))
        if service == "codeartspipeline" and not action:
            action = f"CodeArts Pipeline project permission for {operation}"
        elif not action:
            continue
        label = {"functiongraph": "FunctionGraph", "ecs": "ECS", "cae": "CAE",
                 "codeartspipeline": "CodeArts Pipeline"}.get(service, service)
        guidance = ("Check CodeArts project access." if service == "codeartspipeline" else
                    "Check the agency's IAM v5 policy and resource/enterprise-project scope.")
        diagnostics.append(
            f"Profile {profile!r}: {label} denied {operation} ({action})"
            + (f" in {context}" if context else "")
            + f". {guidance}"
        )
    return diagnostics


def _scan_identity(identity, profile, regions, project_id, options, timeout, enterprise_project_id):
    selected_regions = regions
    if selected_regions is None:
        region = profile.get("region") or os.getenv("HUAWEICLOUD_SDK_REGION")
        selected_regions = [region] if region else None
    selected_project = project_id or (profile.get("project_id") if regions != "all" else None)
    if selected_regions is None and not selected_project:
        raise HuaweiAuthError("Set a Huawei region/project in the profile or select --huawei-region all")
    discovery = IamDiscovery(identity["credentials"], timeout)
    scopes, skipped = discovery.scopes(regions=selected_regions, project_id=selected_project,
                                       account_id=identity["account_id"])
    jobs = [(scope, {**options, "scan_obs": None}) for scope in scopes
            if options["include"] is None or options["include"] or options["scan_lts"] or options["scan_csms"]]
    if options["scan_obs"]:
        if len({scope["region"] for scope in scopes}) != 1:
            raise HuaweiAuthError("OBS targets require one explicit bucket region")
        jobs.append(({**scopes[0], "scope": "obs"}, {**options, "include": [], "scan_lts": None,
                     "scan_csms": None, "start_time": None, "end_time": None}))
    outcomes = []
    for scope, kwargs in jobs:
        registry = None
        try:
            def credentials():
                return identity["credentials"]().with_project_id(scope["project_id"])
            registry = HuaweiServiceRegistry(HuaweiAuthConfig(
                region_name=scope["region"], project_id=scope["project_id"], credential_provider=credentials,
                timeout=timeout, enterprise_project_id=enterprise_project_id))
            outcome = HuaweiIRHunt(registry).hunt_exposed_secrets(**kwargs)
        except Exception as exc:
            outcome = OperationResult("hunt_exposed_secrets", scope["project_id"], False,
                                      {"complete": False}, [_safe_error(exc)])
        finally:
            if registry is not None:
                try:
                    registry.close()
                except Exception:
                    outcome.add_error("Unable to close Huawei service client")
                    outcome.details["complete"] = False
        attribution = {**scope, "agency_urn": identity["agency_urn"]}
        if scope.get("scope") == "obs":
            attribution["project_id"] = None  # OBS is not a regional IAM-project scan.
        outcomes.append((attribution, outcome))
    return outcomes, skipped


def _probe_identity(identity, profile, regions, project_id, scanners, timeout, enterprise_project_id):
    """Check list-endpoint access only; never fetch resource configurations or values."""
    selected_regions = regions
    if selected_regions is None:
        region = profile.get("region") or os.getenv("HUAWEICLOUD_SDK_REGION")
        selected_regions = [region] if region else None
    selected_project = project_id or (profile.get("project_id") if regions != "all" else None)
    if selected_regions is None and not selected_project:
        raise HuaweiAuthError("Set a Huawei region/project in the profile or select --huawei-region all")
    discovery = IamDiscovery(identity["credentials"], timeout)
    scopes, skipped = discovery.scopes(regions=selected_regions, project_id=selected_project,
                                       account_id=identity["account_id"])
    probes = {
        "functiongraph": ("functiongraph", "list_functions", {"marker": "0", "maxitems": "1"}),
        "ecs_user_data": ("ecs", "list_servers_details", {"limit": 1}),
        "cae": ("cae", "list_environments", {"x_enterprise_project_id": enterprise_project_id}),
        "codearts": ("codeartspipeline", "list_variable_groups",
                     {"project_id": "", "body": {"offset": 0, "limit": 1, "name": ""}}),
        "modelarts": [
            ("modelarts", "list_training_jobs", {"body": {"offset": 0, "limit": 1}}),
            ("modelarts", "list_infer_services", {"limit": 1, "offset": 0}),
        ],
        "servicestage": ("servicestage", "show_environments", {"limit": 1, "offset": 0}),
        "dataartsstudio": ("dataartsstudio", "list_workspaces", {"x_project_id": "", "limit": 1, "offset": 0}),
    }
    results = []
    for scope in scopes:
        registry = None
        probe_results = []
        try:
            def credentials():
                return identity["credentials"]().with_project_id(scope["project_id"])
            registry = HuaweiServiceRegistry(HuaweiAuthConfig(
                region_name=scope["region"], project_id=scope["project_id"], credential_provider=credentials,
                timeout=timeout, enterprise_project_id=enterprise_project_id))
            for scanner in scanners:
                selected_probes = probes[scanner]
                if selected_probes and isinstance(selected_probes[0], str):
                    selected_probes = [selected_probes]
                for service, operation, params in selected_probes:
                    if scanner == "codearts":
                        params = {**params, "project_id": scope["project_id"]}
                    elif scanner == "dataartsstudio":
                        params = {**params, "x_project_id": scope["project_id"]}
                    try:
                        registry.call(service, operation, **params)
                        probe_results.append({"scanner": scanner, "service": service, "operation": operation,
                                              "accessible": True})
                    except Exception as exc:
                        probe_results.append({"scanner": scanner, "service": service, "operation": operation,
                                              "accessible": False, "error": str(exc) if isinstance(exc, Exception) else "Huawei operation failed"})
        finally:
            if registry is not None:
                try:
                    registry.close()
                except Exception:
                    # Closing a failed probe client must not hide its scan result.
                    pass  # nosec B110
        results.append(({**scope, "agency_urn": identity["agency_urn"]}, probe_results))
    return results, skipped


def check_exposed_secrets_permissions_multi_profile(
    *, profiles="all", regions=None, project_id=None, profile_source="sdk", max_workers=4,
    sso_login=False, timeout=20, enterprise_project_id="0", cache_dir=None, notify=None,
    include=None,
):
    """Read-only access preflight for default Huawei secret-scan list APIs."""
    scanners = list(CONFIG_SCANNERS) if include is None else list(include)
    if any(scanner not in set(CONFIG_SCANNERS) for scanner in scanners):
        raise ValueError("Permission-only checks support the default Huawei configuration scanners")
    profiles, regions = _selection(profiles, "profiles"), _selection(regions, "regions")
    if not isinstance(max_workers, int) or isinstance(max_workers, bool) or not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be between 1 and 32")
    if profiles is None:
        if profile_source != "sdk":
            raise ValueError("KooCLI import requires a named --huawei-profile or all")
        selected, catalog = ["default-chain"], {"default-chain": {"kind": "chain"}}
    else:
        catalog = load_profiles(profile_source)
        selected = sorted(catalog) if profiles == "all" else profiles
        if not selected or any(name not in catalog for name in selected):
            raise ValueError("No matching Huawei profiles; configure SDK/SSO profiles or select the KooCLI source")
    result = OperationResult("check_exposed_secrets_permissions", "configured Huawei profiles", True,
                             {"permission_checks": [], "complete": True})
    sessions, jobs = {}, []
    for label in selected:
        try:
            profile_errors = []
            identities = list(_identities(label, catalog[label], sessions, sso_login, timeout, cache_dir,
                                          notify, profile_errors))
            for error in profile_errors:
                result.add_error(f"Profile {label!r}: {error}")
                result.details["complete"] = False
            if not identities and not profile_errors:
                result.add_error(f"Profile {label!r}: no account/agencies were available to check")
                result.details["complete"] = False
            jobs.extend((label, identity) for identity in identities)
        except Exception as exc:
            result.add_error(f"Profile {label!r}: {_safe_error(exc)}")
            result.details["complete"] = False
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_identity, identity, catalog[label], regions, project_id,
                                   scanners, timeout, enterprise_project_id): (label, identity)
                   for label, identity in jobs}
        for future in as_completed(futures):
            label, identity = futures[future]
            try:
                outcomes, skipped = future.result()
                for scope, probes in outcomes:
                    for probe in probes:
                        item = {"profile": label, **scope, **probe}
                        result.details["permission_checks"].append(item)
                        if not probe["accessible"]:
                            result.details["complete"] = False
                            error = probe.get("error", "")
                            diagnostic = _permission_diagnostics(label, {**scope, "errors": [error]})
                            result.add_error(diagnostic[0] if diagnostic else
                                             f"Profile {label!r}: {probe['service']} {probe['operation']} failed; see permission_checks")
                if skipped:
                    result.details["complete"] = False
                    for item in skipped:
                        result.add_error(f"Profile {label!r}: project discovery skipped a scope; see permission_checks")
            except Exception as exc:
                result.details["complete"] = False
                result.add_error(f"Profile {label!r}: {_safe_error(exc)}")
    result.details["permission_checks"].sort(key=lambda p: tuple(str(p.get(k) or "") for k in
        ("profile", "account_id", "agency_urn", "region", "project_id", "scanner")))
    return result


def hunt_exposed_secrets_multi_profile(
    *, profiles="all", regions=None, project_id=None, profile_source="sdk", max_workers=4,
    sso_login=False, timeout=20, enterprise_project_id="0", cache_dir=None, notify=None, **scan_options,
):
    """Scan configured Huawei profiles using cached or opt-in device SSO.

    ``profiles='all'`` selects all SDK basic/SSO profiles (KooCLI source selects
    SSO profiles only). Native SSO account/permission-set selectors may explicitly
    be ``all``. ``regions='all'`` discovers accessible regional IAM projects;
    no static region fallback. Project IDs come from IAM, never another account's
    environment. Auth prompts are serial, before bounded account/agency workers.
    Content budgets apply per profile/account/agency/region/project, OBS once per
    account/agency in one explicit region. CCE requires a separate cluster scan.
    """
    bound = inspect.signature(HuaweiIRHunt.hunt_exposed_secrets).bind(None, **scan_options)
    bound.apply_defaults()
    options = dict(bound.arguments)
    options.pop("self")
    selected_scanners, obs, _, _ = validate_scan_options(**options)
    if "cce" in selected_scanners:
        raise ValueError("CCE requires a separate single-cluster invocation, without Huawei profile/project sweeps")
    for name, value in (("max_workers", max_workers), ("timeout", timeout)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_workers > 32:
        raise ValueError("max_workers must be at most 32")
    profiles, regions = _selection(profiles, "profiles"), _selection(regions, "regions")
    if isinstance(regions, list) and any(not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", r) for r in regions):
        raise ValueError("Invalid Huawei region")
    if project_id is not None and (not isinstance(project_id, str) or not project_id.strip()):
        raise ValueError("project_id must be a project ID or all")
    if obs and (not isinstance(regions, list) or len(regions) != 1):
        raise ValueError("OBS sweeps require one explicit --huawei-region for the target bucket")
    if profiles is None:
        if profile_source != "sdk":
            raise ValueError("KooCLI import requires a named --huawei-profile or all")
        selected = ["default-chain"]
        catalog = {"default-chain": {"kind": "chain"}}
    else:
        catalog = load_profiles(profile_source)
        selected = sorted(catalog) if profiles == "all" else profiles
        if not selected or any(name not in catalog for name in selected):
            raise ValueError("No matching Huawei profiles; configure SDK/SSO profiles or select the KooCLI source")
    result = OperationResult("hunt_exposed_secrets_multi_profile", "configured Huawei profiles", True,
        {"profiles": {}, "findings": [], "inventory": [], "uninspected": [], "complete": True,
         "content_budgets_scope": "per profile/account/agency/region/project; OBS once per account/agency"})
    sessions, jobs, findings, raw = {}, [], {}, {}
    # Complete interactive authorization before workers start. Workers can only
    # refresh tokens; they never unexpectedly prompt halfway through a scan.
    for label in selected:
        record = {"authenticated": False, "errors": [], "scopes": []}
        result.details["profiles"][label] = record
        try:
            for identity in _identities(label, catalog[label], sessions, sso_login, timeout, cache_dir, notify, record["errors"]):
                if catalog[label]["kind"] == "sso":
                    record["authenticated"] = True
                jobs.append((label, identity))
        except Exception as exc:
            record["errors"].append(_safe_error(exc))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending = {executor.submit(_scan_identity, identity, catalog[label], regions, project_id, options,
                                   timeout, enterprise_project_id): (label, identity) for label, identity in jobs}
        for future in as_completed(pending):
            label, identity = pending[future]
            record = result.details["profiles"][label]
            try:
                outcomes, skipped = future.result()
                record["authenticated"] = True
            except Exception as exc:
                record["errors"].append(_safe_error(exc))
                record["scopes"].append({"account_id": identity["account_id"], "agency_urn": identity["agency_urn"],
                                         "success": False, "complete": False, "errors": [_safe_error(exc)]})
                continue
            result.details["uninspected"].extend({**item, "profile": label, "account_id": identity["account_id"],
                                                  "agency_urn": identity["agency_urn"]} for item in skipped)
            for scope, outcome in outcomes:
                context = {**scope, "profile": label}
                details = outcome.details
                record["scopes"].append({**scope, "success": outcome.success, "errors": outcome.errors,
                    "complete": details.get("complete", False), "scanners": details.get("scanners", {})})
                for key in ("inventory", "uninspected"):
                    result.details[key].extend({**item, **context} for item in details.get(key, []))
                for finding in details.get("findings", []):
                    incoming = copy.deepcopy(finding)
                    incoming["sources"] = [{**source, **context} for source in incoming.get("sources", [])]
                    existing = findings.get(incoming["hash"])
                    if existing is None:
                        findings[incoming["hash"]] = incoming
                    else:
                        existing["sources"].extend(incoming["sources"])
                        if _SEVERITY_ORDER.get(incoming["severity"], 9) < _SEVERITY_ORDER.get(existing["severity"], 9):
                            for key in ("severity", "category", "detection_method"):
                                if key in incoming:
                                    existing[key] = incoming[key]
                if options["keep_raw"]:
                    raw.update(details.get("raw_values", {}))
    permission_errors = set()
    for label, record in result.details["profiles"].items():
        record["scopes"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in ("account_id", "agency_urn", "region", "project_id", "scope")))
        if record["errors"] or any(not s["success"] for s in record["scopes"]):
            profile_diagnostics = set()
            for scope in record["scopes"]:
                profile_diagnostics.update(_permission_diagnostics(label, scope))
            permission_errors.update(profile_diagnostics)
            if record["errors"] or (any(not s["success"] for s in record["scopes"]) and not profile_diagnostics):
                result.add_error(f"Profile {label!r} was incomplete; see details.profiles")
        if not record["scopes"] or any(not s["complete"] for s in record["scopes"]):
            result.details["complete"] = False
    for message in sorted(permission_errors):
        result.add_error(message)
    result.details["complete"] = result.details["complete"] and result.success and not result.details["uninspected"]
    result.details["findings"] = sorted(findings.values(), key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["hash"]))
    for finding in result.details["findings"]:
        finding["sources"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in
            ("profile", "account_id", "agency_urn", "region", "project_id", "resource_id")))
    for key in ("inventory", "uninspected"):
        result.details[key].sort(key=lambda item: tuple(str(item.get(k) or "") for k in
            ("profile", "account_id", "agency_urn", "region", "project_id", "resource_id")))
    result.details["statistics"] = {"profiles": len(selected), "authenticated_profiles": sum(
        record["authenticated"] for record in result.details["profiles"].values()),
        "scope_scans": sum(len(r["scopes"]) for r in result.details["profiles"].values()), "findings": len(findings)}
    if options["keep_raw"]:
        result.details["raw_values"] = raw
    return result
