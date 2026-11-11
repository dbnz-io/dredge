"""Huawei review orchestration using the same SSO identities as secret scans."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os

from .auth import HuaweiCredentialFactory
from .config import HuaweiAuthConfig
from .models import OperationResult
from .profile_sweep import _identities, _safe_error, _selection
from .profiles import IamDiscovery, load_profiles
from .review import CHECKS, HuaweiIRReview, finalize, validate_review_options
from .services import HuaweiServiceRegistry


def _selected_scopes(options):
    return {scope for cid, service, tier, scope, _, _ in CHECKS if service in options["services"]
            and tier in options["tiers"] and scope in options["scopes"]
            and cid in options["include"] and cid not in options["exclude"]}


def _review_identity(identity, profile, regions, project_id, timeout, enterprise_project_id, options, needed):
    outcomes, errors, skipped = [], [], []
    bootstrap = (regions[0] if isinstance(regions, list) else None) or profile.get("region") or profile.get("sso_region") or os.getenv("HUAWEICLOUD_SDK_REGION") or "cn-north-4"

    def run(scope):
        config = HuaweiAuthConfig(region_name=scope["region"] or bootstrap,
            credential_provider=identity["credentials"], timeout=timeout, enterprise_project_id=enterprise_project_id)
        # A project default from the environment must not cross account boundaries.
        config.project_id = scope["project_id"]
        registry = HuaweiServiceRegistry(config)
        try:
            outcome = HuaweiIRReview(registry, account_id=identity["account_id"]).review(
                **{**options, "scopes": [scope["scope"]]})
            identity["account_id"] = identity["account_id"] or outcome.details["meta"].get("account_id")
            outcomes.append((scope, outcome))
        except Exception as exc:
            errors.append(_safe_error(exc))
        finally:
            try:
                registry.close()
            except Exception:
                errors.append("Unable to close Huawei review client")

    if "global" in needed:
        run({"scope": "global", "region": None, "project_id": None})
    if "regional" in needed:
        selected_regions = regions or ([profile["region"]] if profile.get("region") else None)
        if selected_regions is None and os.getenv("HUAWEICLOUD_SDK_REGION"):
            selected_regions = [os.environ["HUAWEICLOUD_SDK_REGION"]]
        selected_project = project_id or (profile.get("project_id") if regions != "all" else None)
        if not selected_project and regions != "all" and profile["kind"] == "chain":
            selected_project = os.getenv("HUAWEICLOUD_SDK_PROJECT_ID")
        try:
            if selected_regions is None and not selected_project:
                raise ValueError("A region/project or all-region selection is required")
            scopes, skipped = IamDiscovery(identity["credentials"], timeout).scopes(
                regions=selected_regions, project_id=selected_project, account_id=identity["account_id"])
            for scope in scopes:
                identity["account_id"] = identity["account_id"] or scope["account_id"]
                run({**scope, "scope": "regional"})
        except Exception as exc:
            errors.append("Regional project discovery failed: " + _safe_error(exc))
    return outcomes, errors, skipped


def review_multi_profile(*, auth=None, profiles="all", regions=None, project_id=None, profile_source="sdk",
                         sso_login=False, max_workers=4, timeout=20, enterprise_project_id="0",
                         cache_dir=None, notify=None, **review_options):
    """Run global checks once per identity, regional checks per accessible project.

    Login prompts are serialized before workers start. auth is an optional
    HuaweiAuthConfig for library callers with explicit/callback credentials;
    it cannot be combined with an explicit profiles selection.
    """
    validated = validate_review_options(**review_options)
    needed = _selected_scopes(validated)
    if not needed:
        raise ValueError("No Huawei checks match the selection")
    if type(max_workers) is not int or not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be between 1 and 32")
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("timeout must be a positive integer")
    regions, profiles = _selection(regions, "regions"), _selection(profiles, "profiles")
    if regions not in (None, "all"):
        for region in regions:
            HuaweiAuthConfig(region_name=region)
    if project_id is not None and (not isinstance(project_id, str) or not project_id.strip()):
        raise ValueError("project_id must be a project ID or all")
    if auth is not None and profiles is not None:
        raise ValueError("Use auth with profiles=None, or select configured profiles")
    if profiles is None:
        if profile_source != "sdk":
            raise ValueError("KooCLI import requires a profile name or all")
        selected = [auth.profile_name or "default-chain"] if auth else ["default-chain"]
        catalog = {selected[0]: {"kind": "chain", "region": auth.region_name if auth else None,
                                "project_id": auth.project_id if auth else None}}
    else:
        catalog = load_profiles(profile_source)
        selected = sorted(catalog) if profiles == "all" else profiles
        if not selected or any(name not in catalog for name in selected):
            raise ValueError("No matching Huawei profiles")
    result = OperationResult("review_multi_profile", "configured Huawei profiles", True, {
        "findings": [], "checks": {}, "profiles": {}, "uninspected": [], "complete": True,
        "meta": {"provider": "huawei", "services": validated["services"], "tiers": sorted(validated["tiers"]),
                 "regions": regions, "profiles": selected, "generated_at": datetime.now(timezone.utc).isoformat(),
                 "limits": {key: validated[key] for key in ("max_resources", "max_api_calls", "max_seconds")},
                 "thresholds": {key: validated[key] for key in ("key_age_days", "min_password_length", "min_backup_days", "min_log_retention_days")},
                 "incident_start": validated["incident_start"].isoformat() if validated["incident_start"] else None}})
    sessions, jobs = {}, []
    for label in selected:
        record = dict(authenticated=False, errors=[], scopes=[])
        result.details["profiles"][label] = record
        try:
            if auth is not None:
                factory = HuaweiCredentialFactory(auth)
                def credentials(factory=factory):
                    return factory.get_credentials(require_project=False)
                credentials()
                identities = [dict(account_id=None, agency_urn=None, credentials=credentials)]
            else:
                identities = _identities(label, catalog[label], sessions, sso_login, timeout, cache_dir, notify, record["errors"])
            for identity in identities:
                if catalog[label]["kind"] == "sso":
                    record["authenticated"] = True
                jobs.append((label, identity))
        except Exception as exc:
            record["errors"].append(_safe_error(exc))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        pending = {pool.submit(_review_identity, identity, catalog[label], regions, project_id, timeout,
                              enterprise_project_id, review_options, needed): (label, identity) for label, identity in jobs}
        for future in as_completed(pending):
            label, identity = pending[future]
            record = result.details["profiles"][label]
            context = {"profile": label, "agency_urn": identity["agency_urn"]}
            try:
                outcomes, errors, skipped = future.result()
            except Exception as exc:
                record["errors"].append(_safe_error(exc))
                continue
            context["account_id"] = identity["account_id"]
            record["errors"].extend(errors)
            if skipped:
                result.details["complete"] = False
                result.details["uninspected"].extend({**item, **context} for item in skipped)
            for scope, outcome in outcomes:
                details = outcome.details
                if any(c["status"] == "ran" and c.get("api_calls", 0) > 0 for c in details["checks"].values()):
                    record["authenticated"] = True
                record["scopes"].append({**scope, **context, "success": outcome.success,
                    "complete": details["complete"], "errors": outcome.errors, "checks": details["checks"]})
                if not outcome.success:
                    record["errors"].extend(outcome.errors)
                result.details["complete"] = result.details["complete"] and details["complete"]
                result.details["findings"].extend({**finding, **context} for finding in details["findings"])
                result.details["uninspected"].extend({**item, **context} for item in details["uninspected"])
                for cid, check in details["checks"].items():
                    aggregate = result.details["checks"].setdefault(cid, {"by_scope": [], "count": 0})
                    aggregate["by_scope"].append({**scope, **context, **check})
                    aggregate["count"] += check["count"]
    for label, record in result.details["profiles"].items():
        if record["errors"] or not record["scopes"]:
            result.add_error(f"Profile {label!r} was incomplete; see details.profiles")
            result.details["complete"] = False
        record["scopes"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in ("account_id", "agency_urn", "region", "project_id")))
    for check in result.details["checks"].values():
        check["by_scope"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in ("profile", "account_id", "agency_urn", "region", "project_id")))
        states = {s["status"] for s in check["by_scope"]}
        check["status"] = next(iter(states)) if len(states) == 1 else "partial"
    result.details["uninspected"].sort(key=lambda s: tuple(str(s.get(k) or "") for k in ("profile", "region", "project_id", "check_id", "resource_id")))
    return finalize(result)
