"""Posture reviews across configured AWS profiles and enabled regions."""
from __future__ import annotations

import inspect
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ..config import DredgeConfig
from .models import OperationResult
from .profile_sweep import (
    _CLIENT_CONFIG, _authenticated_profiles, _prepare_profiles, _resolve_regions, _safe_error,
)
from .review import AwsIRReview, SERVICES, _SEVERITY_RANK
from .services import AwsServiceRegistry


def _validate_options(options):
    bound = inspect.signature(AwsIRReview.review).bind(None, **options)
    bound.apply_defaults()
    values = dict(bound.arguments)
    for key in ("self", "regions", "max_workers"):
        values.pop(key)
    services = values["services"]
    if services is not None and services != "all" and (
        isinstance(services, str) or not services or set(services) - set(SERVICES)
    ):
        raise ValueError("services must be 'all' or a nonempty list of review services")
    if not values["tiers"] or set(values["tiers"]) - {1, 2}:
        raise ValueError("tiers must contain 1 and/or 2")
    check_ids = {check[0] for check in AwsIRReview._CHECKS}
    for key in ("include", "exclude"):
        if values[key] is not None and (isinstance(values[key], str) or set(values[key]) - check_ids):
            raise ValueError(f"{key} must contain valid review check ids")
    if values["incident_start"] is not None and not isinstance(values["incident_start"], datetime):
        raise ValueError("incident_start must be a datetime")
    if isinstance(values["ips"], str):
        raise ValueError("ips must be a list of IPs/CIDRs")
    for value in values["ips"] or []:
        ipaddress.ip_network(value, strict=False)
    return values


def _regional_checks(options):
    services = options["services"]
    return [cid for cid, service, tier, _, needs_start, scope in AwsIRReview._CHECKS
            if scope == "regional"
            and (services is None or services == "all" or service in services)
            and tier in options["tiers"]
            and (options["include"] is None or cid in options["include"])
            and cid not in (options["exclude"] or [])
            and (not needs_start or options["incident_start"] is not None)
            and (cid != "ec2-sg-references-ip" or options["ips"])]


class _ProfileReviewServices(AwsServiceRegistry):
    """Refresh explicitly assumed roles before each sequential regional review."""

    def __init__(self, factory, bootstrap, profile, progress):
        super().__init__(factory.get_session(), region=bootstrap, client_config=_CLIENT_CONFIG)
        self._factory, self._profile, self._progress = factory, profile, progress

    def regional(self, region):
        if self._progress:
            self._progress(self._profile, region)
        return AwsServiceRegistry(self._factory.get_session(), region=region, client_config=_CLIENT_CONFIG)


def _review_profile(factory, bootstrap, regions, options, profile, progress):
    regional_checks = _regional_checks(options)
    selected, discovery_error = [], None
    if regional_checks:
        try:
            selected = _resolve_regions(factory, bootstrap, regions)
        except Exception as exc:
            discovery_error = "region discovery failed: " + _safe_error(exc)
    if progress:
        progress(profile, "global")
    registry = _ProfileReviewServices(factory, bootstrap, profile, progress)
    outcome = AwsIRReview(registry, DredgeConfig(region_name=bootstrap)).review(
        **options, regions=selected, max_workers=1,
    )
    if discovery_error:
        outcome.add_error(discovery_error)
        for cid in regional_checks:
            outcome.details["checks"][cid] = {
                "status": "skipped", "count": 0, "reason": discovery_error, "by_region": {},
            }
    return outcome


def review_multi_profile(
    *, auth=None, profiles="all", regions=None, max_workers=12, sso_login=False,
    progress=None, **review_options,
):
    """Review each configured profile, preserving account/principal attribution.

    Selectors and optional SSO login match ``hunt_exposed_secrets_multi_profile``.
    At most ``max_workers`` profiles run concurrently (1–32); regions run
    sequentially within each profile. Global checks run once per profile.
    Discovery/auth/check failures remain visible, including in HTML reports.
    """
    options = _validate_options(review_options)
    auth, catalog, selected, regions = _prepare_profiles(auth, profiles, regions, max_workers)
    result = OperationResult("review_multi_profile", "configured AWS profiles", True, {
        "findings": [], "summary": {}, "checks": {}, "profiles": {}, "permission_checks": [],
    })
    pending = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for label, record, factory, bootstrap in _authenticated_profiles(auth, catalog, selected, sso_login):
            result.details["profiles"][label] = record
            record["success"] = False
            if factory is not None:
                pending[executor.submit(_review_profile, factory, bootstrap, regions, options, label, progress)] = label
        for future in as_completed(pending):
            label = pending[future]
            record = result.details["profiles"][label]
            try:
                outcome = future.result()
            except Exception as exc:
                record["errors"].append("profile review failed: " + _safe_error(exc))
                continue
            record.update(success=outcome.success, checks=outcome.details.get("checks", {}),
                  summary=outcome.details.get("summary", {}), meta=outcome.details.get("meta", {}),
                  permission_checks=outcome.details.get("permission_checks", []))
            result.details.setdefault("permission_checks", []).extend(
                {"profile": label, "account_id": record.get("account_id"), **check}
                for check in outcome.details.get("permission_checks", []))
            record["errors"].extend(outcome.errors)
            context = {key: record[key] for key in ("account_id", "principal_arn")}
            for finding in outcome.details.get("findings", []):
                result.details["findings"].append({**finding, **context, "profile": label})
            for cid, check in record["checks"].items():
                aggregate = result.details["checks"].setdefault(cid, {"by_profile": {}, "count": 0})
                aggregate["by_profile"][label] = check
                aggregate["count"] += check.get("count", 0)
                for region, status in check.get("by_region", {}).items():
                    regional = record["regions"].setdefault(region, {"success": True, "checks": {}})
                    regional["checks"][cid] = status
                    if status.get("error"):
                        regional["success"] = False
    for label, record in result.details["profiles"].items():
        if not record["success"]:
            specific = list(record.get("errors", []))
            for check_id, check in record.get("checks", {}).items():
                if check.get("error"):
                    specific.append(f"{check_id}: {check['error']}")
                for region, status in check.get("by_region", {}).items():
                    if status.get("error"):
                        specific.append(f"{check_id} ({region}): {status['error']}")
            if specific:
                result.add_error(f"Profile {label!r} was incomplete: " + "; ".join(dict.fromkeys(specific)))
            else:
                result.add_error(f"Profile {label!r} was incomplete; see details.profiles")
    result.details["profiles"] = dict(sorted(result.details["profiles"].items()))
    for check in result.details["checks"].values():
        states = [value["status"] for value in check["by_profile"].values()]
        check["status"] = states[0] if len(set(states)) == 1 else "partial"
        if len(states) < len(selected):
            check["status"] = "partial"
        check["by_profile"] = dict(sorted(check["by_profile"].items()))
    findings = result.details["findings"]
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f["severity"], 9), f["profile"], f["service"],
                                 f["check_id"], f.get("region") or "", f["resource_id"]))
    for finding in findings:
        severity = finding["severity"]
        result.details["summary"][severity] = result.details["summary"].get(severity, 0) + 1
    result.details["total_findings"] = len(findings)
    result.details["meta"] = {
        "profiles": list(result.details["profiles"]),
        "account_ids": sorted({r["account_id"] for r in result.details["profiles"].values() if r["authenticated"]}),
        "regions": regions,
        "services": sorted(SERVICES if options["services"] in (None, "all") else options["services"]),
        "tiers": sorted(options["tiers"]),
        "incident_start": options["incident_start"].isoformat() if options["incident_start"] else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return result
