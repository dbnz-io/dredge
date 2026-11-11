"""Secret hunting across configured AWS profiles and account-enabled regions."""
from __future__ import annotations

import copy
import inspect
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import DredgeConfig
from ..secret_scanning import _SEVERITY_ORDER
from .hunt import AwsIRHunt
from .models import OperationResult
from .profile_sweep import (
    _CLIENT_CONFIG, _authenticated_profiles, _prepare_profiles, _resolve_regions, _safe_error,
)
from .secret_sources import validate_content_options
from .services import AwsServiceRegistry


def _validate_options(options):
    # Validate once before any auth/login/API calls, using the single-region API
    # defaults as the source of truth. No dummy scan or duplicate defaults.
    bound = inspect.signature(AwsIRHunt.hunt_exposed_secrets).bind(None, **options)
    bound.apply_defaults()
    values = dict(bound.arguments)
    values.pop("self")
    include = values["include"]
    if include is not None and (isinstance(include, str) or set(include) - set(AwsIRHunt._SECRET_SCANNERS)):
        raise ValueError("include must contain valid AWS secret scanners")
    if not isinstance(values["max_ec2_instances"], int) or isinstance(values["max_ec2_instances"], bool) or values["max_ec2_instances"] <= 0:
        raise ValueError("max_ec2_instances must be positive")
    s3, logs = values["scan_s3"] or [], values["scan_cloudwatch"] or []
    if isinstance(s3, str) or isinstance(logs, str):
        raise ValueError("scan_s3 and scan_cloudwatch must be lists of targets")
    validate_content_options(s3, logs, values["start_time"], values["end_time"], **{
        name: values[name] for name in ("s3_max_objects", "s3_max_object_bytes", "cloudwatch_max_events",
                                      "content_max_bytes", "content_max_api_calls", "content_max_seconds")
    })
    if values["cloudwatch_stream_prefix"] is not None and (not logs or not values["cloudwatch_stream_prefix"]):
        raise ValueError("cloudwatch_stream_prefix requires CloudWatch targets and a nonempty prefix")
    return values


def _scan_profile(factory, bootstrap, regions, options, profile, progress):
    """One worker owns this profile's session; regions run sequentially.

    Boto3 Sessions are not shared between workers, and auth/MFA/SSO prompts
    happen before the session is handed to a worker.
    """
    outcomes, errors = {}, []
    regional_work = options["include"] is None or bool(options["include"]) or bool(options["scan_cloudwatch"])
    selected = []
    if regional_work:
        try:
            selected = _resolve_regions(factory, bootstrap, regions)
        except Exception as exc:
            errors.append("region discovery failed: " + _safe_error(exc))
    jobs = []
    for region in selected:
        jobs.append((region, region, {**options, "scan_s3": None}))
    if options["scan_s3"]:
        # S3 bucket names are global: never reread each prefix in every region.
        jobs.append(("global", bootstrap, {**options, "include": [], "scan_cloudwatch": None,
                                           "start_time": None, "end_time": None, "cloudwatch_stream_prefix": None}))
    for label, region, kwargs in jobs:
        if progress:
            progress(profile, label)
        try:
            registry = AwsServiceRegistry(factory.get_session(), region=region, client_config=_CLIENT_CONFIG)
            outcomes[label] = AwsIRHunt(registry, DredgeConfig(region_name=region)).hunt_exposed_secrets(**kwargs)
        except Exception as exc:
            outcome = OperationResult("hunt_exposed_secrets", label, False)
            outcome.add_error(_safe_error(exc))
            outcomes[label] = outcome
    return outcomes, errors


def hunt_exposed_secrets_multi_profile(
    *, auth=None, profiles="all", regions=None, max_workers=4, sso_login=False,
    progress=None, **scan_options,
):
    """Scan configured profiles, preserving profile/account/region attribution.

    ``profiles='all'`` enumerates local profiles, not every account/role the user
    might be entitled to. ``profiles=None`` uses auth.profile_name/default chain.
    ``regions='all'`` requires EC2 DescribeRegions; there is no static fallback.
    Regions are serial within each profile; at most max_workers profiles run at
    once. Content budgets apply per profile/region; S3 runs once per profile.
    ``sso_login=True`` may invoke AWS CLI/browser login once per shared session
    after a failed auth attempt. MFA approval cannot be bypassed.
    """
    options = _validate_options(scan_options)
    auth, catalog, selected, regions = _prepare_profiles(auth, profiles, regions, max_workers)
    result = OperationResult("hunt_exposed_secrets_multi_profile", "configured AWS profiles", True,
                             {"credentials": [], "profiles": {}, "statistics": {}})
    findings, raw_values = {}, {}
    pending = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for label, record, factory, bootstrap in _authenticated_profiles(auth, catalog, selected, sso_login):
            result.details["profiles"][label] = record
            if factory is not None:
                pending[executor.submit(_scan_profile, factory, bootstrap, regions, options, label, progress)] = label
        for future in as_completed(pending):
            label = pending[future]
            record = result.details["profiles"][label]
            try:
                outcomes, errors = future.result()
            except Exception as exc:
                record["errors"].append("profile scan failed: " + _safe_error(exc))
                continue
            record["errors"].extend(errors)
            for region, outcome in sorted(outcomes.items()):
                details = outcome.details
                record["regions"][region] = {
                    "success": outcome.success, "errors": outcome.errors,
                    "scan_errors": details.get("scan_errors", []),
                    "statistics": details.get("statistics", {}),
                    "content_scans": details.get("content_scans", {}),
                }
                for finding in details.get("credentials", []):
                    incoming = copy.deepcopy(finding)
                    context = {"profile": label, "account_id": record["account_id"],
                               "principal_arn": record["principal_arn"], "region": region}
                    incoming["sources"] = [{**source, **context} for source in incoming.get("sources", [])]
                    existing = findings.get(incoming["hash"])
                    if existing is None:
                        findings[incoming["hash"]] = incoming
                    else:
                        existing["sources"].extend(incoming["sources"])
                        if _SEVERITY_ORDER.get(incoming["severity"], 9) < _SEVERITY_ORDER.get(existing["severity"], 9):
                            existing["severity"] = incoming["severity"]
                            existing["category"] = incoming["category"]
                            existing["detection_method"] = incoming["detection_method"]
                if options["keep_raw"]:
                    raw_values.update(details.get("raw_values", {}))
    for label, record in result.details["profiles"].items():
        if record["errors"] or any(not r["success"] for r in record["regions"].values()):
            result.add_error(f"Profile {label!r} was incomplete; see details.profiles")
    result.details["credentials"] = sorted(findings.values(), key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["hash"]))
    for finding in result.details["credentials"]:
        finding["sources"].sort(key=lambda source: (source["profile"], source["region"], str(source.get("resource_id", ""))))
    result.details["statistics"] = {
        "profiles": len(selected),
        "authenticated_profiles": sum(record["authenticated"] for record in result.details["profiles"].values()),
        "region_scans": sum(len(record["regions"]) for record in result.details["profiles"].values()),
        "findings": len(findings),
    }
    result.details["content_budgets_scope"] = "per profile/region; S3 once per profile"
    if options["keep_raw"]:
        result.details["raw_values"] = raw_values
    return result
