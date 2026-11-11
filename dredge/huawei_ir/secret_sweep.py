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
from .hunt import HuaweiIRHunt, validate_scan_options
from .models import OperationResult
from .profiles import IamDiscovery, load_profiles
from .services import HuaweiServiceRegistry
from .profile_sweep import _identities, _safe_error, _selection


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
    for label, record in result.details["profiles"].items():
        record["scopes"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in ("account_id", "agency_urn", "region", "project_id", "scope")))
        if record["errors"] or any(not s["success"] for s in record["scopes"]):
            result.add_error(f"Profile {label!r} was incomplete; see details.profiles")
        if not record["scopes"] or any(not s["complete"] for s in record["scopes"]):
            result.details["complete"] = False
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
