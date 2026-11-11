"""Bounded, read-only Huawei posture review with explicit coverage reporting."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import time

from .auth import HuaweiAuthError
from .models import OperationResult
from .review_checks import HuaweiReviewChecks
from .services import HuaweiServiceError

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# id, service, tier, scope, implementation, optional input
CHECKS = (
    ("iam-login-protection", "iam", 1, "global", "iam_login", None),
    ("iam-admin-groups", "iam", 1, "global", "iam_admin", None),
    ("iam-old-access-keys", "iam", 2, "global", "iam_keys", None),
    ("iam-external-agencies", "iam", 2, "global", "iam_agencies", None),
    ("iam-password-policy", "iam", 2, "global", "iam_password", None),
    ("obs-public-buckets", "obs", 1, "global", "obs_public", None),
    ("obs-public-access-block", "obs", 2, "global", "obs_block", None),
    ("obs-default-encryption", "obs", 2, "global", "obs_encryption", None),
    ("obs-access-logging", "obs", 2, "global", "obs_logging", None),
    ("vpc-open-critical-ports", "vpc", 1, "regional", "vpc_ports", None),
    ("vpc-sg-references-ip", "vpc", 2, "regional", "vpc_ips", "ips"),
    ("vpc-flow-logs", "vpc", 1, "regional", "vpc_flow", None),
    ("ecs-public-addresses", "ecs", 1, "regional", "ecs_public", None),
    ("evs-unencrypted-volumes", "evs", 2, "regional", "evs_encryption", None),
    ("rds-public-instances", "rds", 1, "regional", "rds_public", None),
    ("rds-storage-encryption", "rds", 2, "regional", "rds_encryption", None),
    ("rds-ssl-disabled", "rds", 2, "regional", "rds_ssl", None),
    ("rds-backup-retention", "rds", 2, "regional", "rds_backups", None),
    ("cce-public-api", "cce", 1, "regional", "cce_public", None),
    ("cce-legacy-auth", "cce", 2, "regional", "cce_auth", None),
    ("cce-master-encryption", "cce", 2, "regional", "cce_encryption", None),
    ("functiongraph-unauthenticated-triggers", "functiongraph", 1, "regional", "function_triggers", None),
    ("cts-system-tracker", "cts", 1, "regional", "cts_enabled", None),
    ("cts-log-archive", "cts", 1, "regional", "cts_archive", None),
    ("cts-integrity-validation", "cts", 2, "regional", "cts_integrity", None),
    ("lts-log-retention", "lts", 2, "regional", "lts_retention", None),
    ("hss-host-protection", "hss", 1, "regional", "hss_protection", None),
    ("secmaster-workspaces", "secmaster", 2, "regional", "secmaster_workspaces", None),
    ("recent-iam-resources", "recent", 1, "global", "recent_iam", "incident_start"),
    ("recent-regional-resources", "recent", 1, "regional", "recent_regional", "incident_start"),
)
SERVICES = sorted({check[1] for check in CHECKS})


def validate_review_options(*, services=None, tiers=(1, 2), include=None, exclude=None,
                            incident_start=None, ips=None, scopes=("global", "regional"),
                            max_resources=1000, max_api_calls=2000, max_seconds=120,
                            key_age_days=90, min_password_length=12, min_backup_days=7,
                            min_log_retention_days=30):
    def names(value, allowed, name, default):
        if value is None:
            return list(default)
        if isinstance(value, str) or not isinstance(value, (list, tuple, set)) or set(value) - set(allowed):
            raise ValueError(f"Invalid Huawei review {name}")
        return list(dict.fromkeys(value))
    selected = names(None if services == "all" else services, SERVICES, "services", SERVICES)
    tiers = names(tiers, (1, 2), "tiers", (1, 2))
    if any(type(tier) is not int for tier in tiers):
        raise ValueError("Invalid Huawei review tiers")
    scopes = names(scopes, ("global", "regional"), "scopes", ("global", "regional"))
    ids = [c[0] for c in CHECKS]
    include = names(include, ids, "include check IDs", ids)
    exclude = names(exclude, ids, "exclude check IDs", [])
    if not selected or not tiers or not scopes:
        raise ValueError("Select at least one Huawei service, tier, and scope")
    if incident_start is not None and (not isinstance(incident_start, datetime) or incident_start.utcoffset() is None):
        raise ValueError("incident_start must be a timezone-aware datetime")
    if isinstance(ips, str) or (ips is not None and not isinstance(ips, (list, tuple))):
        raise ValueError("ips must be a list of IP addresses/CIDRs")
    try:
        networks = [ipaddress.ip_network(ip, strict=False) for ip in (ips or [])]
    except ValueError:
        raise ValueError("Invalid IP address/CIDR") from None
    limits = dict(max_resources=max_resources, max_api_calls=max_api_calls, max_seconds=max_seconds,
                  key_age_days=key_age_days, min_password_length=min_password_length,
                  min_backup_days=min_backup_days, min_log_retention_days=min_log_retention_days)
    if any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in limits.values()):
        raise ValueError("Huawei review limits and thresholds must be positive integers")
    return dict(services=selected, tiers=tiers, scopes=scopes, include=include, exclude=exclude,
                incident_start=incident_start, ips=networks, **limits)


def finalize(result):
    findings = result.details["findings"]
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), *(str(f.get(k) or "") for k in
        ("profile", "account_id", "agency_urn", "service", "check_id", "region", "project_id", "resource_id"))))
    result.details["summary"] = {severity: sum(f["severity"] == severity for f in findings) for severity in SEVERITIES}
    result.details["total_findings"] = len(findings)
    return result


class _BudgetStop(Exception):
    pass


class HuaweiIRReview(HuaweiReviewChecks):
    """Same finding/check/tier contract as AWS, with Huawei project attribution."""
    _CHECKS = CHECKS

    def __init__(self, services, *, account_id=None):
        self.services, self.account_id = services, account_id
        self.project_id = services.config.project_id

    def review(self, *, services=None, tiers=(1, 2), include=None, exclude=None,
               incident_start=None, ips=None, scopes=("global", "regional"),
               max_resources=1000, max_api_calls=2000, max_seconds=120,
               key_age_days=90, min_password_length=12, min_backup_days=7,
               min_log_retention_days=30, regions=None, max_workers=4):
        """Review metadata only. Limits apply per check per account/project.

        Failed reads never imply a missing control. Unknown fields and caps make
        complete=False; API errors additionally set success=False. Findings are
        assessment signals, not proof of compromise or internet reachability.
        """
        options = dict(services=services, tiers=tiers, include=include, exclude=exclude, incident_start=incident_start,
            ips=ips, scopes=scopes, max_resources=max_resources, max_api_calls=max_api_calls, max_seconds=max_seconds,
            key_age_days=key_age_days, min_password_length=min_password_length, min_backup_days=min_backup_days,
            min_log_retention_days=min_log_retention_days)
        self.options = validate_review_options(**options)
        if regions is not None:
            from .review_sweep import review_multi_profile
            return review_multi_profile(auth=self.services.config, profiles=None, regions=regions,
                max_workers=max_workers, timeout=self.services.config.timeout,
                enterprise_project_id=self.services.config.enterprise_project_id, **options)
        self.result = OperationResult("review", "huawei-account", True, {
            "findings": [], "checks": {}, "uninspected": [], "complete": True,
            "meta": {"provider": "huawei", "region": self.services.config.region_name,
                     "project_id": self.project_id, "account_id": self.account_id,
                     "services": self.options["services"], "tiers": sorted(self.options["tiers"]),
                     "generated_at": datetime.now(timezone.utc).isoformat(),
                     "incident_start": incident_start.isoformat() if incident_start else None,
                     "thresholds": {k: self.options[k] for k in ("key_age_days", "min_password_length", "min_backup_days", "min_log_retention_days")},
                     "limits": {k: self.options[k] for k in ("max_resources", "max_api_calls", "max_seconds")}}})
        self._cache = {}
        if not any(c[1] in self.options["services"] and c[2] in self.options["tiers"] and
                   c[3] in self.options["scopes"] and c[0] in self.options["include"] and
                   c[0] not in self.options["exclude"] for c in CHECKS):
            raise ValueError("No Huawei checks match the selection")
        for cid, service, tier, scope, method, required in CHECKS:
            if (service not in self.options["services"] or tier not in self.options["tiers"] or scope not in self.options["scopes"]
                    or cid not in self.options["include"] or cid in self.options["exclude"]):
                continue
            self._check = dict(service=service, tier=tier, scope=scope, status="ran", count=0,
                               api_calls=0, resources=0, errors=[], stop_reasons=[], uninspected=0)
            self._cid, self._started = cid, time.monotonic()
            self.result.details["checks"][cid] = self._check
            if required and not self.options[required]:
                self._check.update(status="skipped", reason=f"No {required} supplied")
                continue
            before = len(self.result.details["uninspected"])
            try:
                if scope == "regional" and not self.project_id:
                    self.project_id = self.services.auth.get_credentials().project_id
                if (scope == "regional" or service == "obs") and not self.account_id:
                    self._account()
                getattr(self, method)()
            except _BudgetStop:
                pass
            except Exception:
                self._check["errors"].append("Check could not finish; response/credential data omitted")
            if self._check["errors"]:
                self.result.add_error(f"{cid}: one or more metadata reads failed; see details.checks")
            if self._check["errors"] or self._check["stop_reasons"] or len(self.result.details["uninspected"]) > before:
                self._check["status"] = "partial" if self._check["resources"] or not self._check["errors"] else "failed"
                self.result.details["complete"] = False
        self.result.details["meta"].update(account_id=self.account_id, project_id=self.project_id)
        return finalize(self.result)

    def _stop(self, reason):
        if reason not in self._check["stop_reasons"]:
            self._check["stop_reasons"].append(reason)
        raise _BudgetStop()

    def _time(self):
        if time.monotonic() - self._started >= self.options["max_seconds"]:
            self._stop("max_seconds")

    def _unknown(self, resource, reason):
        self._check["uninspected"] += 1
        self.result.details["uninspected"].append(dict(check_id=self._cid, resource_id=resource,
            reason=reason, region=self.services.config.region_name if self._check["scope"] == "regional" else None,
            project_id=self.project_id if self._check["scope"] == "regional" else None, account_id=self.account_id))

    def _call(self, service, operation, *, absent=(), obs_region=None, **kwargs):
        self._time()
        key = (service, operation, obs_region, json.dumps(kwargs, sort_keys=True))
        if key not in self._cache:
            if self._check["api_calls"] >= self.options["max_api_calls"]:
                self._stop("max_api_calls")
            self._check["api_calls"] += 1
            try:
                if service == "iam":
                    value = self.services.iam_call(operation, **kwargs)
                elif service == "obs":
                    registry = self.services.obs_for_region(obs_region) if obs_region else self.services
                    value = registry.obs_call(operation, **kwargs).body
                else:
                    value = self.services.call(service, operation, **kwargs)
                self._cache[key] = (value, None)
            except Exception as exc:
                # Only preserve structured status/code and our sanitized errors.
                status, code = getattr(exc, "status", None), getattr(exc, "code", None)
                safe = str(exc) if isinstance(exc, (HuaweiServiceError, HuaweiAuthError)) else "Metadata request failed"
                self._cache[key] = (None, (status, code, safe))
        value, error = self._cache[key]
        if error:
            if error[0] == 404 and (error[1] or "").lower() in {c.lower() for c in absent}:
                return {"_absent": True}  # Only API-specific, documented absence codes.
            self._check["errors"].append(f"{service}.{operation}: {error[2]}")
            return None
        if value is None:
            self._unknown(operation, "empty_response")
        return value

    def _items(self, service, operation, key, *, mode=None, total=None, id_key="id", **params):
        position, seen, count = ("0" if mode == "functiongraph" else None), set(), 0
        while True:
            paging = {}
            if mode in ("marker", "page_info"):
                paging = {"limit": 100, **({"marker": position} if position else {})}
            elif mode == "offset":
                paging = {"limit": 100, "offset": count}
            elif mode == "page":
                paging = {"per_page": 100, "page": count // 100 + 1}
            elif mode == "functiongraph":
                paging = {"maxitems": "100", "marker": position}
            elif mode == "obs":
                paging = {"maxKeys": 100, "isQueryLocation": True, **({"marker": position} if position else {})}
            response = self._call(service, operation, **params, **paging)
            if response is None:
                return
            items = response.get(key)
            if not isinstance(items, list):
                self._unknown(operation, "resource_list_not_returned")
                return
            for item in items:
                self._time()
                if self._check["resources"] >= self.options["max_resources"]:
                    self._stop("max_resources")
                if not isinstance(item, dict):
                    self._unknown(operation, "malformed_resource")
                    continue
                identity = item
                for part in id_key.split("."):
                    identity = identity.get(part) if isinstance(identity, dict) else None
                if identity and identity in seen:
                    self._stop("pagination_stalled")
                if identity:
                    seen.add(identity)
                self._check["resources"] += 1
                yield item
            count += len(items)
            if mode == "page_info":
                if not isinstance(response.get("page_info"), dict):
                    self._unknown(operation, "pagination_metadata_not_returned")
                    return
                nxt = (response.get("page_info") or {}).get("next_marker")
            elif mode == "functiongraph":
                nxt = response.get("next_marker")
                if nxt in (None, 0, "0", -1, "-1", ""):
                    return
            elif mode == "obs":
                if response.get("isTruncated") is not True:
                    return
                nxt = response.get("nextMarker")
                if not nxt:
                    self._stop("pagination_stalled")
            elif mode in ("offset", "marker", "page"):
                if total and isinstance(response.get(total), (int, float)):
                    if count >= response[total]:
                        return
                    if not items:
                        self._stop("pagination_stalled")
                elif len(items) < 100:
                    return
                nxt = count if mode in ("offset", "page") else items[-1].get(id_key)
            else:
                if (response.get("links") or {}).get("next"):
                    self._stop("unsupported_pagination")
                return
            if not nxt:
                return
            if not items or nxt == position:
                self._stop("pagination_stalled")
            position = nxt

    def _account(self):
        if not self.account_id:
            pid = self.project_id or self.services.auth.get_credentials(require_project=False).project_id
            if pid:
                response = self._call("iam", "keystone_show_project", project_id=pid)
                self.account_id = ((response or {}).get("project") or {}).get("domain_id")
            else:
                domains = list(self._items("iam", "keystone_list_auth_domains", "domains"))
                if len(domains) == 1:
                    self.account_id = domains[0].get("id")
            if not self.account_id:
                self._unknown("account", "account_id_unresolved")
        return self.account_id

    def _emit(self, severity, rtype, rid, title, recommendation, *, detail=None, created_time=None, region=None):
        regional = self._check["scope"] == "regional"
        self.result.details["findings"].append(dict(check_id=self._cid, title=title, severity=severity,
            resource_type=f"Huawei::{rtype}", resource_id=rid or "unknown", recommendation=recommendation,
            service=self._check["service"], tier=self._check["tier"],
            region=region or (self.services.config.region_name if regional else None),
            project_id=self.project_id if regional else None, account_id=self.account_id,
            created_time=created_time, detail=detail or {}))
        self._check["count"] += 1

    @staticmethod
    def to_csv(result, path):
        from .review_reports import to_csv
        to_csv(result, path)

    @staticmethod
    def to_html(result, path):
        from .review_reports import to_html
        to_html(result, path)
