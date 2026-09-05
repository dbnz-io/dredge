from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import boto3
import botocore.exceptions
from botocore.config import Config as BotoConfig

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)

_THROTTLE_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
}


# =====================
# Exposed-secret detection engine
#
# Two layers:
#   1. Pattern detectors — regexes for well-known credential shapes
#      (AWS key pairs, GitHub/Slack/Stripe tokens, JWTs, PEM blocks).
#   2. Key-name heuristic — a variable named like a secret whose value is
#      also credential-shaped gets flagged as a generic secret.
#
# Raw values are never returned by default: each finding stores a
# SHA-256 hash (first 16 hex chars, used for dedup) plus a redacted
# preview. Pass keep_raw=True to hunt_exposed_secrets() to also get the
# plaintext back (e.g. for a rotation worklist) — handle with care.
# =====================


@dataclass
class _SecretDetector:
    name: str
    category: str
    severity: str
    pattern: "re.Pattern"


# Notably absent: a bare `AKIA...` detector. An access key ID alone isn't
# secret (you need the 40-char secret key to use it) and leaks routinely
# in CloudTrail/IAM output. The paired check in _detect_aws_pair_in_bag
# below catches the dangerous case: an AKIA AND its SAK in the same bag.
_SECRET_DETECTORS: List[_SecretDetector] = [
    _SecretDetector("github_token", "GitHub Token", "CRITICAL",
                     re.compile(r"\bgh[psour]_[A-Za-z0-9_]{30,255}\b")),
    _SecretDetector("stripe_key", "Stripe Key", "CRITICAL",
                     re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    _SecretDetector("private_key_block", "Private Key Block", "CRITICAL",
                     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    _SecretDetector("google_api_key", "Google API Key", "HIGH",
                     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _SecretDetector("slack_token", "Slack Token", "HIGH",
                     re.compile(r"\bxox[bpoars]-[A-Za-z0-9-]{15,}\b")),
    _SecretDetector("jwt_token", "JWT Token", "HIGH",
                     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    _SecretDetector("aws_secret_with_context", "AWS Secret Access Key", "CRITICAL",
                     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
]

_AKIA_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|ANPA|ANVA|AROA|AIDA)[0-9A-Z]{16}\b")
_SAK_SHAPE_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")

_SECRET_KEY_NAME_RE = re.compile(
    r"(?i)(secret|password|passwd|pwd|api[_-]?key|access[_-]?key|"
    r"token|credential|private[_-]?key|auth)"
)
_GENERIC_SECRET_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-./+=:]{12,}$")
_SECRET_PLACEHOLDERS = {
    "changeme", "change-me", "password", "passw0rd", "secret", "test",
    "true", "false", "none", "null", "todo", "fixme", "your-token-here",
    "your-secret-here", "<password>", "<secret>",
}

_SECRET_URL_RE = re.compile(r"^(https?://[^/?#]+)(.*)$", re.IGNORECASE)
_SECRET_ARN_RE = re.compile(
    r"^(arn:[a-z\-]+:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]*:[^/]+)(.*)$", re.IGNORECASE,
)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _redact_secret(value: str) -> str:
    """Shape-aware redaction: keeps the non-sensitive prefix of URLs/ARNs,
    otherwise first4 + asterisks + last4."""
    n = len(value)
    if n <= 8:
        return f"{'*' * n} ({n} chars)"

    m = _SECRET_URL_RE.match(value)
    if m:
        prefix, tail = m.group(1), m.group(2)
        if not tail or tail in ("/", "?"):
            return f"{prefix} ({n} chars)"
        return f"{prefix}/[…{len(tail)} chars] ({n} chars)"

    m = _SECRET_ARN_RE.match(value)
    if m:
        prefix, tail = m.group(1), m.group(2)
        if not tail:
            return f"{prefix} ({n} chars)"
        return f"{prefix}/[…{len(tail)} chars] ({n} chars)"

    return f"{value[:4]}{'*' * max(4, n - 8)}{value[-4:]} ({n} chars)"


def _detect_secret(value: str, key_name: str = "") -> Optional[Tuple[str, str, str]]:
    """Return (category, severity, detection_method) or None. AWS access
    key IDs are intentionally NOT detected here — see
    _detect_aws_pair_in_bag for the context-aware paired check."""
    if not value or not isinstance(value, str):
        return None

    for d in _SECRET_DETECTORS:
        if d.pattern.search(value):
            return d.category, d.severity, f"regex:{d.name}"

    if key_name and _SECRET_KEY_NAME_RE.search(key_name):
        v_norm = value.strip()
        if v_norm.lower() in _SECRET_PLACEHOLDERS:
            return None
        if _SECRET_ARN_RE.match(v_norm):
            return None
        if _GENERIC_SECRET_VALUE_RE.match(v_norm) and len(v_norm) >= 16:
            return "Generic Secret", "MEDIUM", "key_name_heuristic"

    return None


def _detect_aws_pair_in_bag(bag: Dict[str, str]) -> List[Tuple[str, str, str, str, str]]:
    """An AKIA on its own isn't a secret; an AKIA AND a matching 40-char SAK
    shape in the same bag (env vars, task-def env, etc.) is a leaked
    credential pair. Returns (key_name, value, category, severity, method)
    tuples, empty if no pair is present."""
    out: List[Tuple[str, str, str, str, str]] = []
    if not bag:
        return out
    akias = [(k, v) for k, v in bag.items() if isinstance(v, str) and _AKIA_RE.search(v)]
    saks = [
        (k, v) for k, v in bag.items()
        if isinstance(v, str) and _SAK_SHAPE_RE.match(v or "") and not _AKIA_RE.search(v)
    ]
    if not akias or not saks:
        return out
    for k, v in akias:
        out.append((k, v, "AWS Access Key", "CRITICAL", "regex:aws_pair_access_key"))
    for k, v in saks:
        out.append((k, v, "AWS Secret Access Key", "CRITICAL", "regex:aws_pair_secret_access_key"))
    return out


class _SecretBucket:
    """Aggregates detected secrets by hash. With keep_raw=True the raw
    plaintext is also held in memory (keyed by hash) so the caller can
    return it; findings themselves never carry the raw value."""

    def __init__(self, keep_raw: bool = False) -> None:
        self.findings: Dict[str, Dict[str, Any]] = {}
        self.keep_raw = keep_raw
        self.raw_by_hash: Dict[str, str] = {}

    def _upsert(self, value: str, source: Dict[str, Any], category: str, severity: str, method: str) -> None:
        h = _hash_secret(value)
        if self.keep_raw:
            self.raw_by_hash[h] = value
        existing = self.findings.get(h)
        if existing:
            if _SEVERITY_ORDER.get(severity, 9) < _SEVERITY_ORDER.get(existing["severity"], 9):
                existing["severity"] = severity
            existing["sources"].append(source)
        else:
            self.findings[h] = {
                "hash": h,
                "category": category,
                "redacted_value": _redact_secret(value),
                "detection_method": method,
                "severity": severity,
                "sources": [source],
                "live_test_result": None,
            }

    def add(self, value: str, source: Dict[str, Any], key_name: str = "") -> None:
        det = _detect_secret(value, key_name)
        if det is None:
            return
        category, severity, method = det
        self._upsert(value, source, category, severity, method)

    def add_explicit(self, value: str, source: Dict[str, Any], category: str, severity: str, method: str) -> None:
        if not value:
            return
        self._upsert(value, source, category, severity, method)

    def values(self) -> List[Dict[str, Any]]:
        return list(self.findings.values())


def _emit_aws_pair(bag: Dict[str, str], make_source, bucket: "_SecretBucket") -> None:
    for key_name, value, category, severity, method in _detect_aws_pair_in_bag(bag):
        bucket.add_explicit(str(value), make_source(key_name), category, severity, method)


def verify_aws_key_pair(
    access_key_id: str,
    secret_access_key: str,
    *,
    region: str = "us-east-1",
    timeout: int = 10,
) -> Dict[str, Any]:
    """Call sts:GetCallerIdentity with the supplied pair. Never raises —
    returns a dict with status "live" | "denied" | "expired" | "error".

    Only sts:GetCallerIdentity is ever called; the response's principal
    ARN identifies exactly which user/role the leaked pair belongs to.
    The secret value itself is used only to build a throwaway boto3
    client for this one call and is never logged.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cfg = BotoConfig(connect_timeout=timeout, read_timeout=timeout, retries={"max_attempts": 1})
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region,
            config=cfg,
        )
        ident = sts.get_caller_identity()
        return {
            "status": "live",
            "tested_at": now,
            "caller_arn": ident.get("Arn", ""),
            "caller_account": ident.get("Account", ""),
            "caller_user_id": ident.get("UserId", ""),
        }
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"InvalidClientTokenId", "SignatureDoesNotMatch", "InvalidAccessKeyId"}:
            return {"status": "denied", "tested_at": now, "error": code}
        if code in {"ExpiredToken", "TokenRefreshRequired"}:
            return {"status": "expired", "tested_at": now, "error": code}
        msg = e.response.get("Error", {}).get("Message", "")
        return {"status": "error", "tested_at": now, "error": f"{code}: {msg}".strip(": ")}
    except botocore.exceptions.BotoCoreError as e:
        return {"status": "error", "tested_at": now, "error": str(e)}


def _dig(record: Dict[str, Any], dotted_path: str) -> Any:
    """Extract a value from a nested dict via a dot-separated path, e.g.
    "userIdentity.accountId". Returns None on any missing/non-dict step."""
    cur: Any = record
    for part in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


class AwsIRHunt:
    """
    Hunt / search utilities over CloudTrail LookupEvents.

    Example:
        dredge.aws_ir.hunt.lookup_events(
            user_name="alice",
            event_name="ConsoleLogin",
            max_events=100,
        )
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def lookup_events(
        self,
        *,
        user_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        event_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: Optional[int] = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
        allow_full_scan: bool = False,
    ) -> OperationResult:
        """
        Search CloudTrail LookupEvents by simple filters.

        CloudTrail LookupEvents only supports ONE LookupAttribute per call.
        We choose the most specific one (access_key_id > user_name > event_name)
        and then apply additional filters (e.g., source_ip) client-side.

        NOTE: source_ip is always applied client-side — CloudTrail does not
        support it as a server-side LookupAttribute. Using it alone means every
        event in the time range has to be paged through and inspected, which is
        expensive and may miss matches beyond max_events if the range is wide.
        By default this requires combining source_ip with at least one of
        user_name, access_key_id, or event_name to narrow the server-side scan;
        pass allow_full_scan=True to explicitly opt into scanning by IP alone.

        Args:
            user_name: Filter by CloudTrail Username.
            access_key_id: Filter by AccessKeyId.
            event_name: Filter by EventName (e.g., "ConsoleLogin").
            source_ip: Filter by sourceIPAddress (client-side only).
            start_time: Earliest event time (UTC). Defaults to now - 24h.
            end_time: Latest event time (UTC). Defaults to now.
            max_events: Maximum number of events to return. None or a
                value <= 0 means unlimited — keep paginating until
                CloudTrail has no more matching events for the time range.
            page_size: CloudTrail MaxResults per request (<= 50).
            throttle_max_retries: Max retries on throttling.
            throttle_base_delay: Base seconds for exponential backoff.
            allow_full_scan: If True, permits source_ip as the sole filter,
                scanning every event in the time range client-side. Results
                may still be truncated at max_events — check
                details["statistics"]["truncated"].

        Raises:
            ValueError: If source_ip is the only filter provided and
                allow_full_scan is False.

        Returns:
            OperationResult with:
              - details["events"]: list of normalized event dicts
              - details["statistics"]: counts and filter info
        """
        if source_ip and not any([user_name, access_key_id, event_name]) and not allow_full_scan:
            raise ValueError(
                "source_ip cannot be the sole filter for CloudTrail lookup_events. "
                "CloudTrail does not support IP-based server-side filtering; using "
                "source_ip alone would scan all events in the time range and may "
                "truncate results at max_events. Either provide at least one of: "
                "user_name, access_key_id, event_name — or pass allow_full_scan=True "
                "to explicitly opt into a full client-side scan."
            )

        # None or <=0 means unlimited: normalize once so every bound check
        # below is a simple "is there a cap, and have we hit it".
        if max_events is not None and max_events <= 0:
            max_events = None

        now = datetime.now(timezone.utc)

        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="lookup_events",
            target=self._build_target_string(
                user_name=user_name,
                access_key_id=access_key_id,
                event_name=event_name,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        _log.debug(event("aws_ir_hunt", "lookup_events.start", target=result.target, max_events=max_events))

        events, total_api_calls, next_token, lookup_attributes, error = self._paginate_lookup_events(
            self._services.cloudtrail,
            user_name=user_name,
            access_key_id=access_key_id,
            event_name=event_name,
            source_ip=source_ip,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            page_size=page_size,
            throttle_max_retries=throttle_max_retries,
            throttle_base_delay=throttle_base_delay,
        )
        if error:
            result.add_error(f"Failed to lookup CloudTrail events: {error}")
            _log.error(event("aws_ir_hunt", "lookup_events.api_error", target=result.target, error=error))

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "api_calls": total_api_calls,
            "lookup_attributes": lookup_attributes,
            "truncated": max_events is not None and bool(next_token) and len(events) >= max_events,
            "time_range": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
        }

        _log.info(event("aws_ir_hunt", "lookup_events.complete", target=result.target, total_events=len(events), api_calls=total_api_calls))

        return result

    def _paginate_lookup_events(
        self,
        cloudtrail,
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
        source_ip: Optional[str],
        start_time: datetime,
        end_time: datetime,
        max_events: Optional[int],
        page_size: int,
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> Tuple[List[Dict[str, Any]], int, Optional[str], List[Dict[str, str]], Optional[str]]:
        """Paginate LookupEvents on one CloudTrail client (one region).

        Shared by lookup_events (single region) and lookup_events_multi_region.
        Returns (events, api_calls, next_token, lookup_attributes, error) —
        `error` is a message string if an API call failed (any events gathered
        before the failure are still returned), else None.
        """
        lookup_attributes = self._build_lookup_attributes(
            user_name=user_name,
            access_key_id=access_key_id,
            event_name=event_name,
        )

        # Pre-compute whether we need a client-side event_name filter.
        # This is needed when a different attribute (access_key_id or user_name) was
        # chosen as the primary LookupAttribute, so event_name wasn't filtered server-side.
        apply_event_name_filter: bool = (
            event_name is not None
            and bool(lookup_attributes)
            and lookup_attributes[0]["AttributeKey"] != "EventName"
        )

        events: List[Dict[str, Any]] = []
        total_api_calls = 0
        next_token: Optional[str] = None

        while True:
            if max_events is not None and len(events) >= max_events:
                break

            params: Dict[str, Any] = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": min(page_size, 50),
            }
            if lookup_attributes:
                params["LookupAttributes"] = lookup_attributes
            if next_token:
                params["NextToken"] = next_token

            try:
                resp = self._call_with_backoff(
                    cloudtrail.lookup_events,
                    params=params,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
                total_api_calls += 1
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
                return events, total_api_calls, next_token, lookup_attributes, str(exc)

            raw_events = resp.get("Events", [])
            for raw_event in raw_events:
                if max_events is not None and len(events) >= max_events:
                    break

                # Fast path: EventName is a top-level field — filter before any JSON work.
                if apply_event_name_filter and raw_event.get("EventName") != event_name:
                    continue

                # source_ip is only available inside the CloudTrailEvent JSON blob.
                # Parse it once here; pass the result to _normalize_event to avoid re-parsing.
                ct_dict: Optional[Dict[str, Any]] = None
                if source_ip:
                    raw_ct = raw_event.get("CloudTrailEvent")
                    if raw_ct:
                        try:
                            ct_dict = json.loads(raw_ct)
                        except ValueError:
                            ct_dict = {}
                    event_ip = raw_event.get("SourceIPAddress", (ct_dict or {}).get("sourceIPAddress"))
                    if event_ip != source_ip:
                        continue

                events.append(self._normalize_event(raw_event, ct=ct_dict))

            next_token = resp.get("NextToken")
            if not next_token:
                break

        return events, total_api_calls, next_token, lookup_attributes, None

    def lookup_events_multi_region(
        self,
        *,
        regions=None,
        user_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        event_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events_per_region: Optional[int] = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
        allow_full_scan: bool = False,
        max_workers: int = 12,
    ) -> OperationResult:
        """
        Run LookupEvents concurrently across multiple regions.

        CloudTrail LookupEvents is a regional API — each region's endpoint only
        returns events recorded in that region. This fans out one paginated
        lookup per region across a thread pool (so every regional endpoint is
        queried at the same time) and merges the results into one time-sorted
        list. Every normalized event already carries its `aws_region`, and the
        per-region breakdown (counts, errors) is in details["by_region"].

        Args:
            regions: list of region names, or the string "all" (default) to
                query every region enabled for the account (resolved via EC2
                DescribeRegions, falling back to botocore's static list).
            user_name/access_key_id/event_name/source_ip/start_time/end_time/
                page_size/throttle_*/allow_full_scan: same as lookup_events,
                applied identically in every region.
            max_events_per_region: cap applied per region (not overall).
            max_workers: max regions queried concurrently.

        Returns:
            OperationResult with:
              - details["events"]: merged, time-sorted events across regions
              - details["by_region"]: {region: {count, api_calls, truncated,
                error?}}
              - details["statistics"]: regions_queried/succeeded/failed, totals
        """
        if source_ip and not any([user_name, access_key_id, event_name]) and not allow_full_scan:
            raise ValueError(
                "source_ip cannot be the sole filter for CloudTrail lookup_events. "
                "Provide at least one of user_name/access_key_id/event_name, or pass "
                "allow_full_scan=True to opt into a full client-side scan per region."
            )

        if regions is None or regions == "all":
            regions = self._services.resolve_enabled_regions()
        regions = list(dict.fromkeys(regions))  # dedupe, preserve order
        if not regions:
            raise ValueError("no regions to query")

        if max_events_per_region is not None and max_events_per_region <= 0:
            max_events_per_region = None

        now = datetime.now(timezone.utc)
        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="lookup_events_multi_region",
            target=self._build_target_string(
                user_name=user_name,
                access_key_id=access_key_id,
                event_name=event_name,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ) + f",regions={len(regions)}",
            success=True,
        )

        def _hunt_region(region: str):
            events, api_calls, next_token, _attrs, error = self._paginate_lookup_events(
                self._services.cloudtrail_for_region(region),
                user_name=user_name,
                access_key_id=access_key_id,
                event_name=event_name,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
                max_events=max_events_per_region,
                page_size=page_size,
                throttle_max_retries=throttle_max_retries,
                throttle_base_delay=throttle_base_delay,
            )
            truncated = max_events_per_region is not None and bool(next_token) and len(events) >= max_events_per_region
            return region, events, api_calls, truncated, error

        all_events: List[Dict[str, Any]] = []
        by_region: Dict[str, Dict[str, Any]] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for region, events, api_calls, truncated, error in pool.map(_hunt_region, regions):
                by_region[region] = {
                    "count": len(events),
                    "api_calls": api_calls,
                    "truncated": truncated,
                }
                if error:
                    by_region[region]["error"] = error
                    result.add_error(f"{region}: {error}")
                all_events.extend(events)

        all_events.sort(key=lambda e: e.get("event_time") or "")

        result.details["events"] = all_events
        result.details["by_region"] = by_region
        result.details["statistics"] = {
            "regions_queried": len(regions),
            "regions_succeeded": sum(1 for r in by_region.values() if "error" not in r),
            "regions_failed": sum(1 for r in by_region.values() if "error" in r),
            "total_events": len(all_events),
            "time_range": {"start_time": start_time.isoformat(), "end_time": end_time.isoformat()},
        }

        _log.info(event(
            "aws_ir_hunt", "lookup_events_multi_region.complete", target=result.target,
            regions=len(regions), total_events=len(all_events),
        ))

        return result

    # ----------------- internal helpers -----------------

    @staticmethod
    def _build_target_string(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
        source_ip: Optional[str],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        bits = []
        if user_name:
            bits.append(f"user={user_name}")
        if access_key_id:
            bits.append(f"access_key_id={access_key_id}")
        if event_name:
            bits.append(f"event_name={event_name}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        bits.append(f"time={start_time.isoformat()}..{end_time.isoformat()}")
        return ",".join(bits)

    @staticmethod
    def _build_lookup_attributes(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
    ) -> List[Dict[str, str]]:
        """
        Choose the primary CloudTrail LookupAttribute.

        Priority:
            1) AccessKeyId
            2) Username
            3) EventName
        """
        if access_key_id:
            return [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}]
        if user_name:
            return [{"AttributeKey": "Username", "AttributeValue": user_name}]
        if event_name:
            return [{"AttributeKey": "EventName", "AttributeValue": event_name}]
        return []

    @staticmethod
    def _normalize_event(
        raw: Dict[str, Any],
        *,
        ct: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize a CloudTrail event from LookupEvents into a simple dict.

        ct: pre-parsed CloudTrailEvent JSON dict, if already parsed by the
            caller (e.g. during source_ip filtering) to avoid double-parsing.
        """
        if ct is None:
            raw_ct = raw.get("CloudTrailEvent")
            if raw_ct:
                try:
                    ct = json.loads(raw_ct)
                except ValueError:
                    ct = {}
        ct = ct or {}

        # SourceIPAddress at top-level takes precedence over the embedded JSON value.
        source_ip = raw.get("SourceIPAddress", ct.get("sourceIPAddress"))

        return {
            "event_id": raw.get("EventId"),
            "event_name": raw.get("EventName"),
            "event_time": (
                raw["EventTime"].isoformat() if raw.get("EventTime") else None
            ),
            "username": raw.get("Username"),
            "event_source": raw.get("EventSource"),
            "aws_region": raw.get("AwsRegion"),
            "read_only": raw.get("ReadOnly"),
            "access_key_id": raw.get("AccessKeyId"),
            "source_ip_address": source_ip,
            "resources": raw.get("Resources", []),
            "raw_cloudtrail_event": raw.get("CloudTrailEvent"),
        }

    @staticmethod
    def _call_with_backoff(
        func,
        *,
        params: Dict[str, Any],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> Dict[str, Any]:
        """
        Call an AWS API with basic exponential backoff on throttling.
        """
        attempt = 0
        while True:
            try:
                return func(**params)
            except botocore.exceptions.ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_ERROR_CODES or attempt >= throttle_max_retries:
                    raise

                delay = throttle_base_delay * (2**attempt)
                _log.warning(event("aws_ir_hunt", "cloudtrail_throttle", code=code, attempt=attempt, delay=delay))
                time.sleep(delay)
                attempt += 1

    # =====================
    # CloudTrail — list-driven hunts
    # =====================

    def hunt_cloudtrail_multi_user(
        self,
        users: List[str],
        *,
        mode: str = "per_user",
        event_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events_per_user: Optional[int] = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
        allow_full_scan: bool = False,
        stop_on_error: bool = False,
        output_path: Optional[str] = None,
    ) -> OperationResult:
        """
        Run lookup_events once per username in `users` (CloudTrail LookupEvents
        has no server-side "IN a list" filter, so each identity gets its own
        call) and combine the results.

        If `output_path` is given, each user's record is appended as one line
        of JSON (JSON Lines) to that file as soon as it completes, flushed and
        fsynced immediately. That way a failure partway through a long list
        (throttling, a bad username, a network blip) doesn't lose the results
        already gathered for earlier users — the file on disk always reflects
        progress up to the last completed user.

        Args:
            users: Usernames to hunt, one lookup_events call each.
            mode: "per_user" (default) keeps results keyed by user only.
                "batch" additionally merges every user's events into one
                time-sorted list at details["events"].
            event_name, source_ip, start_time, end_time, page_size,
                throttle_max_retries, throttle_base_delay, allow_full_scan:
                passed straight through to each lookup_events call.
            max_events_per_user: max_events cap applied per user (not overall).
            stop_on_error: If True, stop after the first user whose lookup
                fails instead of continuing with the rest of the list.
            output_path: Optional path to stream per-user JSON Lines records
                to as they complete (see above). Parent directories are
                created if missing.

        Returns:
            OperationResult with:
              - details["per_user"]: {username: {events, statistics, errors?}}
              - details["events"]: merged, time-sorted events (mode="batch" only)
              - details["statistics"]: users_requested/succeeded/failed, totals
        """
        if mode not in ("per_user", "batch"):
            raise ValueError('mode must be "per_user" or "batch"')
        if not users:
            raise ValueError("users must be a non-empty list")

        result = OperationResult(
            operation="hunt_cloudtrail_multi_user",
            target=f"users={len(users)},mode={mode}",
            success=True,
        )

        fh = None
        if output_path:
            dirname = os.path.dirname(output_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            fh = open(output_path, "w")

        per_user: Dict[str, Dict[str, Any]] = {}
        all_events: List[Dict[str, Any]] = []

        try:
            for user in users:
                user_result = self.lookup_events(
                    user_name=user,
                    event_name=event_name,
                    source_ip=source_ip,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events_per_user,
                    page_size=page_size,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                    allow_full_scan=allow_full_scan,
                )
                record: Dict[str, Any] = {
                    "user": user,
                    "success": user_result.success,
                    "events": user_result.details.get("events", []),
                    "statistics": user_result.details.get("statistics", {}),
                }
                if user_result.errors:
                    record["errors"] = user_result.errors

                if not record["success"]:
                    result.add_error(f"{user}: " + "; ".join(record.get("errors", ["unknown error"])))
                    _log.warning(event("aws_ir_hunt", "hunt_cloudtrail_multi_user.user_error", user=user, errors=record.get("errors")))

                per_user[user] = record
                all_events.extend(record["events"])

                if fh:
                    fh.write(json.dumps(record, default=str) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())

                if not record["success"] and stop_on_error:
                    break
        finally:
            if fh:
                fh.close()

        result.details["per_user"] = per_user
        if mode == "batch":
            all_events.sort(key=lambda e: e.get("event_time") or "")
            result.details["events"] = all_events
        result.details["statistics"] = {
            "users_requested": len(users),
            "users_completed": len(per_user),
            "users_succeeded": sum(1 for r in per_user.values() if r.get("success")),
            "users_failed": sum(1 for r in per_user.values() if not r.get("success")),
            "total_events": sum(len(r.get("events", [])) for r in per_user.values()),
        }
        if output_path:
            result.details["output_path"] = output_path

        _log.info(event("aws_ir_hunt", "hunt_cloudtrail_multi_user.complete", target=result.target, **result.details["statistics"]))

        return result

    @staticmethod
    def _parse_ip_allowlist(allowed_ips: List[str]) -> List["ipaddress._BaseNetwork"]:
        networks = []
        for entry in allowed_ips:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR in allowlist: {entry!r}")
        return networks

    @staticmethod
    def _classify_ip_against_allowlist(
        source_ip: Optional[str], networks: List["ipaddress._BaseNetwork"]
    ) -> str:
        """Returns "expected", "unexpected", or "unparseable_source_ip" (the
        source IP field wasn't a real IP at all — e.g. an AWS service
        principal like "cloudtrail.amazonaws.com" on a service-linked call)."""
        if not source_ip:
            return "unparseable_source_ip"
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return "unparseable_source_ip"
        return "expected" if any(addr in net for net in networks) else "unexpected"

    def hunt_user_activity_by_ip(
        self,
        user_name: str,
        allowed_ips: List[str],
        *,
        event_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: Optional[int] = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
    ) -> OperationResult:
        """
        Hunt one identity's CloudTrail activity and classify every event by
        whether its source IP falls inside `allowed_ips` (IPs and/or CIDRs).

        Unlike lookup_events(source_ip=...), which filters down to exactly one
        IP, this evaluates every event the user generated against the whole
        allowlist and keeps all three buckets — so a baseline ("expected")
        picture and any deviations ("unexpected") are both visible in one
        call, instead of having to guess which single IP to filter by.

        Args:
            user_name: CloudTrail Username to hunt.
            allowed_ips: IPs and/or CIDRs the identity is expected to operate
                from (e.g. office/VPN egress ranges, known instance IPs).
            event_name, start_time, end_time, max_events, page_size,
                throttle_max_retries, throttle_base_delay: passed straight
                through to the underlying lookup_events call.

        Raises:
            ValueError: allowed_ips is empty, or contains something that
                isn't a valid IP or CIDR.

        Returns:
            OperationResult with:
              - details["expected_events"]: source IP is in allowed_ips
              - details["unexpected_events"]: source IP is NOT in allowed_ips
              - details["unparseable_source_ip_events"]: no usable IP (e.g.
                an AWS service principal on a service-linked call)
              - details["statistics"]: counts per bucket plus the underlying
                lookup_events statistics
        """
        if not allowed_ips:
            raise ValueError("allowed_ips must be a non-empty list")
        networks = self._parse_ip_allowlist(allowed_ips)

        result = OperationResult(
            operation="hunt_user_activity_by_ip",
            target=f"user={user_name},allowed_ips={len(allowed_ips)}",
            success=True,
        )

        lookup_result = self.lookup_events(
            user_name=user_name,
            event_name=event_name,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            page_size=page_size,
            throttle_max_retries=throttle_max_retries,
            throttle_base_delay=throttle_base_delay,
        )
        for err in lookup_result.errors:
            result.add_error(err)

        expected: List[Dict[str, Any]] = []
        unexpected: List[Dict[str, Any]] = []
        unparseable: List[Dict[str, Any]] = []
        buckets = {
            "expected": expected,
            "unexpected": unexpected,
            "unparseable_source_ip": unparseable,
        }

        for ev in lookup_result.details.get("events", []):
            status = self._classify_ip_against_allowlist(ev.get("source_ip_address"), networks)
            tagged = dict(ev)
            tagged["ip_allowlist_status"] = status
            buckets[status].append(tagged)

        result.details["expected_events"] = expected
        result.details["unexpected_events"] = unexpected
        result.details["unparseable_source_ip_events"] = unparseable
        result.details["statistics"] = {
            "total_events": len(expected) + len(unexpected) + len(unparseable),
            "expected_count": len(expected),
            "unexpected_count": len(unexpected),
            "unparseable_count": len(unparseable),
            "allowed_ips": allowed_ips,
            "lookup": lookup_result.details.get("statistics", {}),
        }

        _log.info(event(
            "aws_ir_hunt", "hunt_user_activity_by_ip.complete", target=result.target,
            expected=len(expected), unexpected=len(unexpected), unparseable=len(unparseable),
        ))

        return result

    # =====================
    # GuardDuty
    # =====================

    def list_guardduty_findings(
        self,
        detector_id: str,
        *,
        severity_min: float = 0.0,
        max_findings: int = 100,
        finding_types: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> OperationResult:
        """
        List and retrieve GuardDuty findings for a detector.

        Args:
            detector_id:   GuardDuty detector ID.
            severity_min:  Minimum severity (0.0–8.9). 4.0 = Medium, 7.0 = High.
            max_findings:  Maximum number of findings to return.
            finding_types: Optional list of finding type strings to filter by.
            start_time:    Only include findings updated at or after this time.
            end_time:      Only include findings updated before or at this time.

        Returns:
            OperationResult with details["findings"] = list of normalized finding dicts.
        """
        result = OperationResult(
            operation="list_guardduty_findings",
            target=f"detector={detector_id}",
            success=True,
        )

        gd = self._services.guardduty

        # Build FindingCriteria
        criterion: Dict[str, Any] = {}
        if severity_min > 0.0:
            criterion["severity"] = {"Gte": severity_min}
        if finding_types:
            criterion["type"] = {"Eq": finding_types}
        if start_time:
            criterion["updatedAt"] = {"Gte": start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}
        if end_time:
            criterion.setdefault("updatedAt", {})["Lte"] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Phase 1: collect finding IDs (paginated, max 50 per call)
        finding_ids: List[str] = []
        next_token: Optional[str] = None

        try:
            while len(finding_ids) < max_findings:
                params: Dict[str, Any] = {
                    "DetectorId": detector_id,
                    "MaxResults": min(50, max_findings - len(finding_ids)),
                }
                if criterion:
                    params["FindingCriteria"] = {"Criterion": criterion}
                if next_token:
                    params["NextToken"] = next_token

                resp = gd.list_findings(**params)
                batch = resp.get("FindingIds", [])
                remaining = max_findings - len(finding_ids)
                finding_ids.extend(batch[:remaining])

                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list GuardDuty findings: {exc}")
            _log.error(event("aws_ir_hunt", "list_guardduty_findings.list_error", target=result.target, error=str(exc)))
            return result

        # Phase 2: fetch full finding details in batches of 50
        findings: List[Dict[str, Any]] = []
        for i in range(0, len(finding_ids), 50):
            batch_ids = finding_ids[i:i + 50]
            try:
                resp = gd.get_findings(DetectorId=detector_id, FindingIds=batch_ids)
                findings.extend(resp.get("Findings", []))
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to get findings batch {i}–{i+50}: {exc}")
                _log.warning(event("aws_ir_hunt", "list_guardduty_findings.get_error", batch=i, error=str(exc)))

        result.details["findings"] = [self._normalize_guardduty_finding(f) for f in findings]
        result.details["statistics"] = {
            "total_findings": len(findings),
            "detector_id": detector_id,
            "severity_min": severity_min,
        }
        _log.info(event("aws_ir_hunt", "list_guardduty_findings.complete", target=result.target, total=len(findings)))
        return result

    @staticmethod
    def _normalize_guardduty_finding(f: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "finding_id": f.get("Id"),
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "description": f.get("Description"),
            "region": f.get("Region"),
            "account_id": f.get("AccountId"),
            "created_at": f.get("CreatedAt"),
            "updated_at": f.get("UpdatedAt"),
            "resource_type": f.get("Resource", {}).get("ResourceType"),
            "service_name": f.get("Service", {}).get("ServiceName"),
            "raw": f,
        }

    # =====================
    # CloudWatch Logs Insights
    # =====================

    def hunt_cloudwatch_logs(
        self,
        log_group: str,
        query: str,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_results: int = 1000,
        poll_interval: float = 1.0,
        max_wait_seconds: float = 60.0,
    ) -> OperationResult:
        """
        Run a CloudWatch Logs Insights query and return the results.

        Args:
            log_group:        Log group name (e.g. /aws/lambda/my-function).
            query:            Logs Insights query string.
            start_time:       Query window start (UTC). Defaults to now - 24h.
            end_time:         Query window end (UTC). Defaults to now.
            max_results:      Maximum rows to return (API-level cap).
            poll_interval:    Seconds between status polls.
            max_wait_seconds: Maximum total seconds to wait for query completion.

        Returns:
            OperationResult with details["results"] = list of flat row dicts.
        """
        now = datetime.now(timezone.utc)
        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="hunt_cloudwatch_logs",
            target=f"log_group={log_group}",
            success=True,
        )

        logs = self._services.logs

        # Start query
        try:
            resp = logs.start_query(
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query,
                limit=max_results,
            )
            query_id = resp["queryId"]
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to start CloudWatch Logs Insights query: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_cloudwatch_logs.start_error", target=result.target, error=str(exc)))
            return result

        # Poll for completion
        elapsed = 0.0
        status = "Running"
        raw_results: List[Any] = []

        _TERMINAL_STATUSES = {"Complete", "Failed", "Cancelled", "Timeout"}

        while elapsed < max_wait_seconds:
            time.sleep(poll_interval)
            elapsed += poll_interval

            try:
                resp = logs.get_query_results(queryId=query_id)
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to get query results: {exc}")
                _log.error(event("aws_ir_hunt", "hunt_cloudwatch_logs.poll_error", query_id=query_id, error=str(exc)))
                return result

            status = resp.get("status", "Unknown")

            if status == "Complete":
                raw_results = resp.get("results", [])
                break

            if status in _TERMINAL_STATUSES:
                result.add_error(f"CloudWatch Logs Insights query ended with status: {status}")
                _log.warning(event("aws_ir_hunt", "hunt_cloudwatch_logs.terminal_status", query_id=query_id, status=status))
                return result

        if status not in _TERMINAL_STATUSES and status != "Complete":
            result.add_error(f"Query timed out after {max_wait_seconds}s (status: {status})")
            _log.warning(event("aws_ir_hunt", "hunt_cloudwatch_logs.timeout", query_id=query_id, elapsed=elapsed))
            try:
                logs.stop_query(queryId=query_id)
            except botocore.exceptions.ClientError:
                pass
            return result

        # Normalize: each row is List[{"field": str, "value": str}]
        normalized = [
            {item["field"]: item["value"] for item in row}
            for row in raw_results
        ]

        result.details["results"] = normalized
        result.details["statistics"] = {
            "query_id": query_id,
            "status": status,
            "total_results": len(normalized),
            "log_group": log_group,
        }
        _log.info(event("aws_ir_hunt", "hunt_cloudwatch_logs.complete", target=result.target, total=len(normalized)))
        return result

    # =====================
    # Security Hub
    # =====================

    def hunt_security_hub_findings(
        self,
        *,
        severity_labels: Optional[List[str]] = None,
        workflow_status: Optional[List[str]] = None,
        product_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_findings: int = 100,
    ) -> OperationResult:
        """
        Query Security Hub findings with optional filters.

        Args:
            severity_labels: e.g. ["HIGH", "CRITICAL"]
            workflow_status: e.g. ["NEW", "NOTIFIED"]
            product_name:    e.g. "GuardDuty"
            start_time:      Filter by UpdatedAt >= start_time.
            end_time:        Filter by UpdatedAt <= end_time.
            max_findings:    Maximum findings to return.

        Returns:
            OperationResult with details["findings"] = list of finding dicts.
        """
        result = OperationResult(
            operation="hunt_security_hub_findings",
            target="security_hub",
            success=True,
        )

        filters: Dict[str, Any] = {}
        if severity_labels:
            filters["SeverityLabel"] = [{"Value": lbl, "Comparison": "EQUALS"} for lbl in severity_labels]
        if workflow_status:
            filters["WorkflowStatus"] = [{"Value": s, "Comparison": "EQUALS"} for s in workflow_status]
        if product_name:
            filters["ProductName"] = [{"Value": product_name, "Comparison": "EQUALS"}]
        updated_at: Dict[str, str] = {}
        if start_time:
            updated_at["Start"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        if end_time:
            updated_at["End"] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        if updated_at:
            filters["UpdatedAt"] = [updated_at]

        hub = self._services.securityhub
        findings: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(findings) < max_findings:
                params: Dict[str, Any] = {
                    "Filters": filters,
                    "MaxResults": min(100, max_findings - len(findings)),
                }
                if next_token:
                    params["NextToken"] = next_token

                resp = hub.get_findings(**params)
                batch = resp.get("Findings", [])
                findings.extend(batch)
                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to query Security Hub: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_security_hub_findings.error", error=str(exc)))

        result.details["findings"] = findings
        result.details["statistics"] = {"total_findings": len(findings)}
        _log.info(event("aws_ir_hunt", "hunt_security_hub_findings.complete", total=len(findings)))
        return result

    # =====================
    # IAM Access Analyzer
    # =====================

    def hunt_access_analyzer_findings(
        self,
        analyzer_arn: str,
        *,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
        max_findings: int = 100,
    ) -> OperationResult:
        """
        List IAM Access Analyzer findings for a given analyzer.

        Args:
            analyzer_arn:  ARN of the Access Analyzer.
            status:        Filter by finding status: "ACTIVE", "ARCHIVED", "RESOLVED".
            resource_type: Filter by resource type (e.g. "AWS::S3::Bucket").
            max_findings:  Maximum findings to return.

        Returns:
            OperationResult with details["findings"] = list of finding dicts.
        """
        result = OperationResult(
            operation="hunt_access_analyzer_findings",
            target=f"analyzer={analyzer_arn}",
            success=True,
        )

        filter_criteria: Dict[str, Any] = {}
        if status:
            filter_criteria["status"] = {"eq": [status]}
        if resource_type:
            filter_criteria["resourceType"] = {"eq": [resource_type]}

        aa = self._services.accessanalyzer
        findings: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(findings) < max_findings:
                params: Dict[str, Any] = {
                    "analyzerArn": analyzer_arn,
                    "maxResults": min(100, max_findings - len(findings)),
                }
                if filter_criteria:
                    params["filter"] = filter_criteria
                if next_token:
                    params["nextToken"] = next_token

                resp = aa.list_findings(**params)
                batch = resp.get("findings", [])
                findings.extend(batch)
                next_token = resp.get("nextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list Access Analyzer findings: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_access_analyzer_findings.error", error=str(exc)))

        result.details["findings"] = findings
        result.details["statistics"] = {"total_findings": len(findings)}
        _log.info(event("aws_ir_hunt", "hunt_access_analyzer_findings.complete", total=len(findings)))
        return result

    # =====================
    # AWS Config
    # =====================

    def hunt_config_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_items: int = 100,
    ) -> OperationResult:
        """
        Retrieve configuration history for a specific AWS resource via AWS Config.

        Args:
            resource_type: e.g. "AWS::EC2::Instance", "AWS::IAM::User"
            resource_id:   The resource ID (not ARN).
            start_time:    Only return configurations recorded after this time.
            end_time:      Only return configurations recorded before this time.
            max_items:     Maximum configuration items to return.

        Returns:
            OperationResult with details["configuration_items"] = list of config snapshots.
        """
        result = OperationResult(
            operation="hunt_config_resource_history",
            target=f"resource_type={resource_type},resource_id={resource_id}",
            success=True,
        )

        config = self._services.awsconfig
        items: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(items) < max_items:
                params: Dict[str, Any] = {
                    "resourceType": resource_type,
                    "resourceId": resource_id,
                    "limit": min(100, max_items - len(items)),
                }
                if start_time:
                    params["earlierTime"] = start_time
                if end_time:
                    params["laterTime"] = end_time
                if next_token:
                    params["nextToken"] = next_token

                resp = config.get_resource_config_history(**params)
                batch = resp.get("configurationItems", [])
                items.extend(batch)
                next_token = resp.get("nextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to get resource config history: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_config_resource_history.error", error=str(exc)))

        result.details["configuration_items"] = items
        result.details["statistics"] = {
            "total_items": len(items),
            "resource_type": resource_type,
            "resource_id": resource_id,
        }
        _log.info(event("aws_ir_hunt", "hunt_config_resource_history.complete", total=len(items)))
        return result

    # =====================
    # IAM Credential Report
    # =====================

    def get_iam_credential_report(
        self,
        *,
        max_wait_seconds: float = 30.0,
        poll_interval: float = 1.0,
    ) -> OperationResult:
        """
        Generate and retrieve the IAM credential report.

        The report contains one row per IAM user with columns for access key
        status, password last used, MFA active, etc.

        Args:
            max_wait_seconds: Maximum time to wait for report generation.
            poll_interval:    Seconds between status polls.

        Returns:
            OperationResult with details["users"] = list of per-user dicts
            parsed from the CSV report.
        """
        import csv
        import io

        result = OperationResult(
            operation="get_iam_credential_report",
            target="iam",
            success=True,
        )

        iam = self._services.iam
        elapsed = 0.0
        state = "STARTED"

        try:
            while elapsed <= max_wait_seconds:
                resp = iam.generate_credential_report()
                state = resp.get("State", "STARTED")
                if state == "COMPLETE":
                    break
                if elapsed < max_wait_seconds:
                    time.sleep(poll_interval)
                    elapsed += poll_interval
                else:
                    break

            if state != "COMPLETE":
                result.add_error(f"IAM credential report did not complete within {max_wait_seconds}s (state: {state})")
                return result

            report_resp = iam.get_credential_report()
            content = report_resp.get("Content", b"")
            if isinstance(content, (bytes, bytearray)):
                content = content.decode("utf-8")

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to generate IAM credential report: {exc}")
            _log.error(event("aws_ir_hunt", "get_iam_credential_report.error", error=str(exc)))
            return result

        users = list(csv.DictReader(io.StringIO(content)))
        result.details["users"] = users
        result.details["statistics"] = {"total_users": len(users)}
        _log.info(event("aws_ir_hunt", "get_iam_credential_report.complete", total=len(users)))
        return result

    # =====================
    # S3: Exposed buckets
    # =====================

    def hunt_exposed_s3_buckets(self) -> OperationResult:
        """
        List S3 buckets that may be publicly accessible.

        Checks each bucket's public access block configuration and flags any
        bucket where block public access is not fully enabled. Buckets with
        NoSuchPublicAccessBlockConfiguration are also flagged as potentially exposed.

        Returns:
            OperationResult with details["exposed_buckets"] = list of bucket names,
            details["buckets"] = per-bucket findings.
        """
        result = OperationResult(
            operation="hunt_exposed_s3_buckets",
            target="s3",
            success=True,
        )

        s3 = self._services.s3
        findings: List[Dict[str, Any]] = []
        exposed: List[str] = []

        try:
            resp = s3.list_buckets()
            buckets = resp.get("Buckets", [])

            for bucket in buckets:
                name = bucket["Name"]
                entry: Dict[str, Any] = {"bucket": name, "exposed": False, "reason": None}

                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    fully_blocked = all([
                        cfg.get("BlockPublicAcls"),
                        cfg.get("IgnorePublicAcls"),
                        cfg.get("BlockPublicPolicy"),
                        cfg.get("RestrictPublicBuckets"),
                    ])
                    if not fully_blocked:
                        entry["exposed"] = True
                        entry["reason"] = "public_access_block_incomplete"
                        entry["public_access_block"] = cfg
                        exposed.append(name)
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code == "NoSuchPublicAccessBlockConfiguration":
                        entry["exposed"] = True
                        entry["reason"] = "no_public_access_block"
                        exposed.append(name)
                    else:
                        entry["check_error"] = str(exc)

                findings.append(entry)

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list S3 buckets: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_exposed_s3_buckets.error", error=str(exc)))

        result.details["buckets"] = findings
        result.details["exposed_buckets"] = exposed
        result.details["statistics"] = {
            "total_buckets": len(findings),
            "exposed_count": len(exposed),
        }
        _log.info(event("aws_ir_hunt", "hunt_exposed_s3_buckets.complete", total=len(findings), exposed=len(exposed)))
        return result

    # =====================
    # IAM: Admin principals
    # =====================

    def list_iam_admin_principals(self) -> OperationResult:
        """
        Find IAM users and roles with administrator-level access.

        Checks for principals with AdministratorAccess managed policy attached
        or any inline policy containing Action: * with Effect: Allow.

        Returns:
            OperationResult with details["admin_users"] and details["admin_roles"].
        """
        result = OperationResult(
            operation="list_iam_admin_principals",
            target="iam",
            success=True,
        )

        iam = self._services.iam
        admin_users: List[str] = []
        admin_roles: List[str] = []
        _ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

        try:
            # Users with AdministratorAccess or wildcard inline policy
            for page in iam.get_paginator("list_users").paginate():
                for user in page.get("Users", []):
                    name = user["UserName"]
                    is_admin = False

                    # Attached managed policies
                    for ap in iam.get_paginator("list_attached_user_policies").paginate(UserName=name):
                        for p in ap.get("AttachedPolicies", []):
                            if p["PolicyArn"] == _ADMIN_ARN:
                                is_admin = True

                    # Inline policies
                    if not is_admin:
                        for ip in iam.get_paginator("list_user_policies").paginate(UserName=name):
                            for pname in ip.get("PolicyNames", []):
                                doc = iam.get_user_policy(UserName=name, PolicyName=pname)
                                pd = doc.get("PolicyDocument", {})
                                for stmt in pd.get("Statement", []):
                                    if stmt.get("Effect") == "Allow" and stmt.get("Action") in ("*", ["*"]):
                                        is_admin = True

                    if is_admin:
                        admin_users.append(name)

            # Roles with AdministratorAccess or wildcard inline policy
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    name = role["RoleName"]
                    is_admin = False

                    for ap in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                        for p in ap.get("AttachedPolicies", []):
                            if p["PolicyArn"] == _ADMIN_ARN:
                                is_admin = True

                    if not is_admin:
                        for ip in iam.get_paginator("list_role_policies").paginate(RoleName=name):
                            for pname in ip.get("PolicyNames", []):
                                doc = iam.get_role_policy(RoleName=name, PolicyName=pname)
                                pd = doc.get("PolicyDocument", {})
                                for stmt in pd.get("Statement", []):
                                    if stmt.get("Effect") == "Allow" and stmt.get("Action") in ("*", ["*"]):
                                        is_admin = True

                    if is_admin:
                        admin_roles.append(name)

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to enumerate IAM principals: {exc}")
            _log.error(event("aws_ir_hunt", "list_iam_admin_principals.error", error=str(exc)))

        result.details["admin_users"] = admin_users
        result.details["admin_roles"] = admin_roles
        result.details["statistics"] = {
            "admin_users": len(admin_users),
            "admin_roles": len(admin_roles),
        }
        _log.info(event("aws_ir_hunt", "list_iam_admin_principals.complete",
                        users=len(admin_users), roles=len(admin_roles)))
        return result

    # =====================
    # CloudTrail: Login hunt
    # =====================

    def hunt_unusual_login_locations(
        self,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 200,
    ) -> OperationResult:
        """
        Hunt for console login events in CloudTrail.

        Returns all ConsoleLogin events in the time window. Callers can inspect
        source IPs, user agents, and MFA usage to identify anomalous logins.

        Args:
            start_time:  Earliest event time (UTC).
            end_time:    Latest event time (UTC).
            max_events:  Maximum events to return.

        Returns:
            OperationResult with details["events"] = list of login event dicts.
        """
        result = OperationResult(
            operation="hunt_unusual_login_locations",
            target="cloudtrail",
            success=True,
        )

        ct = self._services.cloudtrail
        events: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        lookup_attrs = [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}]

        try:
            while len(events) < max_events:
                params: Dict[str, Any] = {
                    "LookupAttributes": lookup_attrs,
                    "MaxResults": min(50, max_events - len(events)),
                }
                if start_time:
                    params["StartTime"] = start_time
                if end_time:
                    params["EndTime"] = end_time
                if next_token:
                    params["NextToken"] = next_token

                resp = ct.lookup_events(**params)
                batch = resp.get("Events", [])
                events.extend(batch)
                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"CloudTrail lookup failed: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_unusual_login_locations.error", error=str(exc)))

        result.details["events"] = events
        result.details["statistics"] = {"total_events": len(events)}
        _log.info(event("aws_ir_hunt", "hunt_unusual_login_locations.complete", total=len(events)))
        return result

    # =====================
    # EC2: Public snapshots
    # =====================

    def list_public_snapshots(
        self,
        *,
        owner_id: Optional[str] = None,
    ) -> OperationResult:
        """
        List EBS snapshots that are shared publicly.

        Public snapshots are a significant data-leakage vector. This method
        lists all snapshots restorable by any AWS account (RestorableByUserIds=all).

        Args:
            owner_id: AWS account ID to restrict results to. If omitted, returns
                      any publicly-visible snapshot.

        Returns:
            OperationResult with details["snapshots"] = list of snapshot dicts.
        """
        result = OperationResult(
            operation="list_public_snapshots",
            target=f"account={owner_id or 'all'}",
            success=True,
        )

        ec2 = self._services.ec2
        snapshots: List[Dict[str, Any]] = []

        describe_kwargs: Dict[str, Any] = {
            "RestorableByUserIds": ["all"],
        }
        if owner_id:
            describe_kwargs["OwnerIds"] = [owner_id]

        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(**describe_kwargs):
                for snap in page.get("Snapshots", []):
                    snapshots.append({
                        "snapshot_id": snap.get("SnapshotId"),
                        "volume_id": snap.get("VolumeId"),
                        "owner_id": snap.get("OwnerId"),
                        "start_time": snap.get("StartTime").isoformat() if snap.get("StartTime") else None,
                        "volume_size": snap.get("VolumeSize"),
                        "description": snap.get("Description"),
                        "encrypted": snap.get("Encrypted"),
                        "tags": snap.get("Tags", []),
                    })

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list public snapshots: {exc}")
            _log.error(event("aws_ir_hunt", "list_public_snapshots.error", error=str(exc)))

        result.details["snapshots"] = snapshots
        result.details["statistics"] = {"total_public_snapshots": len(snapshots)}
        _log.info(event("aws_ir_hunt", "list_public_snapshots.complete", total=len(snapshots)))
        return result

    # =====================
    # Lambda: Env secret hunt
    # =====================

    def hunt_lambda_env_secrets(
        self,
        *,
        patterns: Optional[List[str]] = None,
        max_functions: int = 200,
    ) -> OperationResult:
        """
        List Lambda functions whose environment variables may contain secrets.

        Checks env var names against known secret-like patterns (KEY, SECRET,
        TOKEN, PASSWORD, CREDENTIAL, etc.). Returns function names + flagged
        var names (never values).

        Args:
            patterns:      Additional env var name substrings to flag.
            max_functions: Maximum functions to scan.

        Returns:
            OperationResult with details["flagged"] = list of {function, flagged_vars}.
        """
        _DEFAULT_PATTERNS = {
            "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL",
            "PRIVATE", "API_KEY", "AUTH", "ACCESS_KEY", "CLIENT_SECRET",
        }
        check_patterns = _DEFAULT_PATTERNS | {p.upper() for p in (patterns or [])}

        result = OperationResult(
            operation="hunt_lambda_env_secrets",
            target="lambda",
            success=True,
        )

        lambda_ = self._services.lambda_
        flagged: List[Dict[str, Any]] = []
        total_scanned = 0

        try:
            paginator = lambda_.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    if total_scanned >= max_functions:
                        break

                    total_scanned += 1
                    fn_name = fn.get("FunctionName", "")
                    env_vars = fn.get("Environment", {}).get("Variables", {})

                    suspect_keys = [
                        k for k in env_vars
                        if any(pat in k.upper() for pat in check_patterns)
                    ]

                    if suspect_keys:
                        flagged.append({
                            "function": fn_name,
                            "runtime": fn.get("Runtime"),
                            "flagged_vars": suspect_keys,
                        })

                if total_scanned >= max_functions:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list Lambda functions: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_lambda_env_secrets.error", error=str(exc)))

        result.details["flagged"] = flagged
        result.details["statistics"] = {
            "functions_scanned": total_scanned,
            "functions_flagged": len(flagged),
        }
        _log.info(event("aws_ir_hunt", "hunt_lambda_env_secrets.complete",
                        scanned=total_scanned, flagged=len(flagged)))
        return result

    # =====================
    # EC2: Open security groups
    # =====================

    def list_open_security_groups(
        self,
        *,
        ports: Optional[List[int]] = None,
        max_groups: int = 500,
    ) -> OperationResult:
        """
        Find EC2 security groups with ingress rules open to 0.0.0.0/0 or ::/0.

        Optionally restrict to specific destination ports.

        Args:
            ports:      If provided, only flag rules matching these ports.
            max_groups: Maximum security groups to return.

        Returns:
            OperationResult with details["open_groups"] = list of group findings.
        """
        result = OperationResult(
            operation="list_open_security_groups",
            target="ec2",
            success=True,
        )

        ec2 = self._services.ec2
        open_groups: List[Dict[str, Any]] = []
        total = 0

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    if total >= max_groups:
                        break

                    total += 1
                    open_rules: List[Dict[str, Any]] = []

                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        # Check if this port range overlaps requested ports
                        if ports:
                            port_match = any(
                                (from_port is None or from_port <= p) and
                                (to_port is None or to_port >= p)
                                for p in ports
                            )
                            if not port_match:
                                continue

                        open_cidrs = [
                            r["CidrIp"] for r in perm.get("IpRanges", [])
                            if r.get("CidrIp") in ("0.0.0.0/0",)
                        ]
                        open_ipv6 = [
                            r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                            if r.get("CidrIpv6") in ("::/0",)
                        ]

                        if open_cidrs or open_ipv6:
                            open_rules.append({
                                "protocol": perm.get("IpProtocol"),
                                "from_port": from_port,
                                "to_port": to_port,
                                "open_cidrs": open_cidrs + open_ipv6,
                            })

                    if open_rules:
                        open_groups.append({
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "open_rules": open_rules,
                        })

                if total >= max_groups:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to describe security groups: {exc}")
            _log.error(event("aws_ir_hunt", "list_open_security_groups.error", error=str(exc)))

        result.details["open_groups"] = open_groups
        result.details["statistics"] = {
            "groups_scanned": total,
            "open_groups_count": len(open_groups),
        }
        _log.info(event("aws_ir_hunt", "list_open_security_groups.complete",
                        scanned=total, open=len(open_groups)))
        return result

    # =====================
    # EC2: Security groups referencing specific IP(s)
    # =====================

    def hunt_security_groups_by_ip(
        self,
        ips: List[str],
        *,
        direction: str = "both",
        max_groups: int = 500,
    ) -> OperationResult:
        """
        Find EC2 security groups with ingress or egress rules whose CIDR
        ranges cover one or more of the given IP addresses (or CIDRs).

        Each entry in `ips` may be a bare address ("1.2.3.4") or a CIDR
        block ("1.2.3.0/24"), IPv4 or IPv6. A rule matches when its CIDR
        range overlaps a target — this catches both an exact /32 match and
        a broader rule that happens to cover the target IP.

        Args:
            ips: IP addresses or CIDR blocks to search for.
            direction: "ingress", "egress", or "both" (default). Restricts
                which side of the security group is scanned.
            max_groups: Maximum security groups to scan.

        Returns:
            OperationResult with details["matches"] = list of group findings.
            Each matched rule includes match_type: "explicit" if the rule's
            CIDR was written to cover this IP/range specifically, or
            "wildcard" if it's 0.0.0.0/0 or ::/0 (open to everyone — the
            target IP just happens to be included).

        Raises:
            ValueError: If `ips` is empty, any entry doesn't parse as an IP
                address or CIDR network, or `direction` isn't one of
                "ingress", "egress", "both".
        """
        if not ips:
            raise ValueError("At least one IP or CIDR is required")
        if direction not in ("ingress", "egress", "both"):
            raise ValueError(f"direction must be 'ingress', 'egress', or 'both' — got {direction!r}")

        targets = []
        for raw in ips:
            try:
                targets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid IP or CIDR: {raw!r} ({exc})") from exc

        result = OperationResult(
            operation="hunt_security_groups_by_ip",
            target=f"ips={','.join(ips)},direction={direction}",
            success=True,
        )

        ec2 = self._services.ec2
        matches: List[Dict[str, Any]] = []
        total = 0

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    if total >= max_groups:
                        break
                    total += 1

                    matched_rules: List[Dict[str, Any]] = []
                    if direction in ("ingress", "both"):
                        matched_rules += self._match_sg_rules_by_ip(
                            sg.get("IpPermissions", []), "ingress", targets,
                        )
                    if direction in ("egress", "both"):
                        matched_rules += self._match_sg_rules_by_ip(
                            sg.get("IpPermissionsEgress", []), "egress", targets,
                        )

                    if matched_rules:
                        matches.append({
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "matched_rules": matched_rules,
                        })

                if total >= max_groups:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to describe security groups: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_security_groups_by_ip.error", error=str(exc)))

        result.details["matches"] = matches
        result.details["statistics"] = {
            "groups_scanned": total,
            "groups_matched": len(matches),
            "targets": [str(t) for t in targets],
        }
        _log.info(event("aws_ir_hunt", "hunt_security_groups_by_ip.complete",
                        scanned=total, matched=len(matches)))
        return result

    @staticmethod
    def _match_sg_rules_by_ip(
        perms: List[Dict[str, Any]],
        direction: str,
        targets: List[ipaddress._BaseNetwork],
    ) -> List[Dict[str, Any]]:
        matched: List[Dict[str, Any]] = []
        for perm in perms:
            cidrs = [
                (r.get("CidrIp"), r.get("Description"))
                for r in perm.get("IpRanges", []) if r.get("CidrIp")
            ] + [
                (r.get("CidrIpv6"), r.get("Description"))
                for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")
            ]
            for cidr_str, description in cidrs:
                try:
                    cidr_net = ipaddress.ip_network(cidr_str, strict=False)
                except ValueError:
                    continue
                hit_targets = [
                    str(t) for t in targets
                    if t.version == cidr_net.version and t.overlaps(cidr_net)
                ]
                if hit_targets:
                    matched.append({
                        "direction": direction,
                        "protocol": perm.get("IpProtocol"),
                        "from_port": perm.get("FromPort"),
                        "to_port": perm.get("ToPort"),
                        "cidr": cidr_str,
                        "description": description,
                        # "wildcard": the rule is 0.0.0.0/0 or ::/0 — it allows
                        # everyone, the target IP just happens to be covered.
                        # "explicit": the rule's CIDR is narrower than that,
                        # i.e. it was written to allow this IP/range specifically.
                        "match_type": "wildcard" if cidr_net.prefixlen == 0 else "explicit",
                        "matched_targets": hit_targets,
                    })
        return matched

    # =====================
    # Exposed secrets: Lambda / ECS / SSM / EC2 user-data / CodeBuild
    # =====================

    _SECRET_SCANNERS = ("lambda", "ecs", "ssm", "ec2_user_data", "codebuild")

    def _scan_lambda_secrets(self, bucket: "_SecretBucket", errors: List[str]) -> int:
        lambda_ = self._services.lambda_
        scanned = 0
        try:
            paginator = lambda_.get_paginator("list_functions")
            for page in paginator.paginate():
                for f in page.get("Functions", []):
                    scanned += 1
                    env = (f.get("Environment") or {}).get("Variables") or {}
                    env = {k: str(v) for k, v in env.items()}

                    def make_src(key, _f=f):
                        return {
                            "location_type": "lambda_env",
                            "resource_id": _f.get("FunctionName", ""),
                            "resource_arn": _f.get("FunctionArn", ""),
                            "key_name": key,
                        }

                    _emit_aws_pair(env, make_src, bucket)
                    for k, v in env.items():
                        bucket.add(v, make_src(k), key_name=k)
        except botocore.exceptions.ClientError as exc:
            errors.append(f"lambda: {exc}")
        return scanned

    def _scan_ecs_secrets(self, bucket: "_SecretBucket", errors: List[str]) -> int:
        ecs = self._services.ecs
        arns: List[str] = []
        try:
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                arns.extend(page.get("taskDefinitionArns", []))
        except botocore.exceptions.ClientError as exc:
            errors.append(f"ecs: {exc}")
            return 0

        # Collapse to one revision per family — newest wins.
        by_family: Dict[str, str] = {}
        for arn in arns:
            family = arn.rsplit("/", 1)[-1].rsplit(":", 1)[0]
            by_family[family] = arn

        scanned = 0
        for arn in by_family.values():
            scanned += 1
            try:
                resp = ecs.describe_task_definition(taskDefinition=arn)
                td = resp.get("taskDefinition", {})
                for c in td.get("containerDefinitions", []):
                    cname = c.get("name", "")
                    bag = {
                        env.get("name", ""): str(env.get("value", ""))
                        for env in (c.get("environment", []) or [])
                    }

                    def make_src(key, _arn=arn, _cname=cname):
                        return {
                            "location_type": "ecs_task_env",
                            "resource_id": f"{_arn}::{_cname}",
                            "resource_arn": _arn,
                            "key_name": key,
                        }

                    _emit_aws_pair(bag, make_src, bucket)
                    for k, v in bag.items():
                        bucket.add(v, make_src(k), key_name=k)
            except botocore.exceptions.ClientError as exc:
                errors.append(f"ecs: {exc}")
        return scanned

    def _scan_ssm_secrets(self, bucket: "_SecretBucket", errors: List[str]) -> int:
        ssm = self._services.ssm

        # Only String parameters — SecureString is encrypted at rest with KMS.
        names: List[str] = []
        try:
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate(
                ParameterFilters=[{"Key": "Type", "Option": "Equals", "Values": ["String"]}],
            ):
                for p in page.get("Parameters", []):
                    names.append(p.get("Name", ""))
        except botocore.exceptions.ClientError as exc:
            errors.append(f"ssm: {exc}")
            return 0

        for i in range(0, len(names), 10):  # GetParameters caps at 10 names/call
            chunk = names[i:i + 10]
            try:
                resp = ssm.get_parameters(Names=chunk)
                for p in resp.get("Parameters", []):
                    name = p.get("Name", "")
                    bucket.add(str(p.get("Value", "")), {
                        "location_type": "ssm_parameter",
                        "resource_id": name,
                        "resource_arn": p.get("ARN", ""),
                        "key_name": name,
                    }, key_name=name)
            except botocore.exceptions.ClientError as exc:
                errors.append(f"ssm: {exc}")
        return len(names)

    def _scan_ec2_user_data_secrets(
        self, bucket: "_SecretBucket", errors: List[str], max_instances: int,
    ) -> int:
        ec2 = self._services.ec2

        instance_ids: List[str] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for r in page.get("Reservations", []):
                    for inst in r.get("Instances", []):
                        instance_ids.append(inst["InstanceId"])
        except botocore.exceptions.ClientError as exc:
            errors.append(f"ec2: {exc}")
            return 0

        scanned = 0
        for inst_id in instance_ids[:max_instances]:
            scanned += 1
            try:
                resp = ec2.describe_instance_attribute(InstanceId=inst_id, Attribute="userData")
                ud_b64 = (resp.get("UserData", {}) or {}).get("Value", "")
                if not ud_b64:
                    continue
                # Unparseable user-data is skipped by design.
                try:
                    user_data = base64.b64decode(ud_b64).decode("utf-8", errors="replace")
                except Exception:  # nosec B112
                    continue

                # Walk line-by-line so the line itself works as a synthetic key_name.
                for lineno, line in enumerate(user_data.splitlines(), start=1):
                    bucket.add(line.strip(), {
                        "location_type": "ec2_user_data",
                        "resource_id": inst_id,
                        "key_name": "user-data",
                        "extra": f"line {lineno}",
                    }, key_name=line[:120])
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code != "InvalidInstanceID.NotFound":
                    errors.append(f"ec2: {exc}")
        return scanned

    def _scan_codebuild_secrets(self, bucket: "_SecretBucket", errors: List[str]) -> int:
        cb = self._services.codebuild

        names: List[str] = []
        try:
            paginator = cb.get_paginator("list_projects")
            for page in paginator.paginate():
                names.extend(page.get("projects", []))
        except botocore.exceptions.ClientError as exc:
            errors.append(f"codebuild: {exc}")
            return 0

        scanned = 0
        for i in range(0, len(names), 100):  # BatchGetProjects caps at 100 names/call
            chunk = names[i:i + 100]
            try:
                resp = cb.batch_get_projects(names=chunk)
                for p in resp.get("projects", []):
                    scanned += 1
                    proj_name = p.get("name", "")
                    proj_arn = p.get("arn", "")
                    env_vars = (p.get("environment") or {}).get("environmentVariables", []) or []
                    bag = {
                        ev.get("name", ""): str(ev.get("value", ""))
                        for ev in env_vars if ev.get("type") in (None, "PLAINTEXT")
                    }

                    def make_src(key, _n=proj_name, _a=proj_arn):
                        return {
                            "location_type": "codebuild_env",
                            "resource_id": _n,
                            "resource_arn": _a,
                            "key_name": key,
                        }

                    _emit_aws_pair(bag, make_src, bucket)
                    for k, v in bag.items():
                        bucket.add(v, make_src(k), key_name=k)
            except botocore.exceptions.ClientError as exc:
                errors.append(f"codebuild: {exc}")
        return scanned

    def _verify_secret_pairs(self, bucket: "_SecretBucket") -> None:
        """Group AKIA + SAK occurrences by source-resource bag, test each
        unique (AKIA, SAK) pair once via sts:GetCallerIdentity, and attach
        the outcome to every finding built from that pair."""

        def _source_key(s: Dict[str, Any]) -> Tuple[str, str]:
            return (s.get("location_type", ""), s.get("resource_arn") or s.get("resource_id", ""))

        grouped: Dict[Tuple[str, str], Dict[str, list]] = {}
        for finding in bucket.values():
            if finding["category"] not in ("AWS Access Key", "AWS Secret Access Key"):
                continue
            raw = bucket.raw_by_hash.get(finding["hash"])
            if not raw:
                continue
            side = "akia" if finding["category"] == "AWS Access Key" else "sak"
            for s in finding["sources"]:
                key = _source_key(s)
                grouped.setdefault(key, {"akia": [], "sak": []})
                grouped[key][side].append((finding, raw))

        seen_pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for sides in grouped.values():
            if not sides["akia"] or not sides["sak"]:
                continue
            for akia_finding, akia_raw in sides["akia"]:
                for sak_finding, sak_raw in sides["sak"]:
                    pair_key = (akia_finding["hash"], sak_finding["hash"])
                    entry = seen_pairs.setdefault(pair_key, {
                        "akia_raw": akia_raw, "sak_raw": sak_raw, "findings": [],
                    })
                    entry["findings"].append((akia_finding, sak_finding))

        if not seen_pairs:
            return

        with ThreadPoolExecutor(max_workers=4) as ex:
            future_to_key = {
                ex.submit(verify_aws_key_pair, info["akia_raw"], info["sak_raw"]): pair_key
                for pair_key, info in seen_pairs.items()
            }
            for fut in as_completed(future_to_key):
                pair_key = future_to_key[fut]
                outcome = fut.result()
                for akia_finding, sak_finding in seen_pairs[pair_key]["findings"]:
                    akia_finding["live_test_result"] = outcome
                    sak_finding["live_test_result"] = outcome

    def hunt_exposed_secrets(
        self,
        *,
        include: Optional[List[str]] = None,
        keep_raw: bool = False,
        test_pairs: bool = False,
        max_ec2_instances: int = 500,
    ) -> OperationResult:
        """
        Scan common plaintext-secret hiding spots across the account/region:
        Lambda env vars, ECS task-definition env vars, SSM String
        parameters, EC2 instance user-data, and CodeBuild project env vars.

        Detection runs two layers: regex matchers for well-known credential
        shapes (AWS access-key pairs, GitHub/Slack/Stripe tokens, JWTs, PEM
        private-key blocks) plus a key-name heuristic (a variable named
        like a secret whose value is also credential-shaped). Findings are
        deduplicated by a SHA-256 hash of the raw value — the raw value
        itself is never returned unless keep_raw=True.

        A bare AWS access key ID (AKIA...) is never flagged on its own —
        it's not usable without its secret key and leaks routinely in
        CloudTrail/IAM output. It's only flagged when a same-shaped 40-char
        secret key is found in the same env-var/parameter bag.

        Args:
            include: Subset of {"lambda", "ecs", "ssm", "ec2_user_data",
                "codebuild"} to scan. Defaults to all five.
            keep_raw: If True, details["raw_values"] maps hash -> the
                plaintext value (e.g. to build a rotation worklist).
                Treat the result as sensitive when set.
            test_pairs: If True, every detected AWS access-key + secret-key
                pair found together is verified live via
                sts:GetCallerIdentity — read-only, no other API is ever
                called, and the raw values are held only in memory for the
                duration of the check. The outcome (live/denied/expired/
                error + calling principal ARN) is attached to the finding
                as live_test_result. Off by default since this makes
                authenticated calls using the discovered credentials.
            max_ec2_instances: Cap on EC2 instances scanned for user-data
                (one DescribeInstanceAttribute call per instance).

        Returns:
            OperationResult with:
              - details["credentials"]: deduplicated findings (category,
                severity, redacted preview, detection method, source
                locations, and live_test_result if test_pairs=True).
              - details["raw_values"]: hash -> plaintext, only if keep_raw.
              - details["statistics"]: per-source scan counts and total
                findings.
        """
        scanners = include if include is not None else list(self._SECRET_SCANNERS)
        unknown = sorted(set(scanners) - set(self._SECRET_SCANNERS))
        if unknown:
            raise ValueError(
                f"Unknown scanner(s): {unknown}. Valid: {list(self._SECRET_SCANNERS)}"
            )

        result = OperationResult(
            operation="hunt_exposed_secrets",
            target=f"sources={','.join(scanners)}",
            success=True,
        )

        bucket = _SecretBucket(keep_raw=keep_raw or test_pairs)
        errors: List[str] = []
        scan_counts: Dict[str, int] = {}

        if "lambda" in scanners:
            scan_counts["lambda"] = self._scan_lambda_secrets(bucket, errors)
        if "ecs" in scanners:
            scan_counts["ecs"] = self._scan_ecs_secrets(bucket, errors)
        if "ssm" in scanners:
            scan_counts["ssm"] = self._scan_ssm_secrets(bucket, errors)
        if "ec2_user_data" in scanners:
            scan_counts["ec2_user_data"] = self._scan_ec2_user_data_secrets(
                bucket, errors, max_ec2_instances,
            )
        if "codebuild" in scanners:
            scan_counts["codebuild"] = self._scan_codebuild_secrets(bucket, errors)

        if test_pairs:
            self._verify_secret_pairs(bucket)

        result.details["credentials"] = bucket.values()
        if keep_raw:
            result.details["raw_values"] = dict(bucket.raw_by_hash)
        result.details["statistics"] = {
            "scanned": scan_counts,
            "findings": len(bucket.findings),
        }
        if errors:
            result.details["scan_errors"] = errors
            result.add_error(f"{len(errors)} source scan(s) failed — see details.scan_errors")
            for e in errors:
                _log.warning(event("aws_ir_hunt", "hunt_exposed_secrets.scan_error", error=e))

        _log.info(event("aws_ir_hunt", "hunt_exposed_secrets.complete", findings=len(bucket.findings)))
        return result

    # =====================
    # Local CloudTrail log query (files already on disk, e.g. from
    # aws_ir.forensics.download_s3_logs())
    # =====================

    _DEFAULT_QUERY_FIELDS = (
        "eventTime", "userIdentity.accountId", "userIdentity.arn",
        "userIdentity.accessKeyId", "eventSource", "eventName",
        "awsRegion", "userAgent",
    )

    # Curated set of high-signal CloudTrail eventNames worth surfacing first in
    # an incident, grouped by the attacker objective they usually serve. These
    # are the calls an IR analyst wants to see plotted on a timeline before
    # anything else: turning off logging, harvesting credentials, planting
    # persistence/privesc, and hijacking or exfiltrating resources. Passing
    # ir=True to query_local_cloudtrail_logs() filters to just these eventNames
    # so you don't have to hand-type each --event-name. Grouped (rather than a
    # flat list) so the categories can drive a visualization/legend; the actual
    # matcher uses the flattened _IR_DANGEROUS_EVENT_NAMES set below.
    _IR_DANGEROUS_EVENTS = {
        # Anti-forensics: disabling or tampering with logging, monitoring, and
        # the guardrails that would otherwise record the rest of the attack.
        "anti-forensics": (
            "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
            "DeleteFlowLogs", "StopConfigurationRecorder",
            "DeleteConfigurationRecorder", "DeleteDetector", "UpdateDetector",
            "DisableSecurityHub", "DeleteLogGroup", "DeleteAlarms",
            "LeaveOrganization",
        ),
        # Credential access: reading secrets/params, decrypting data, and
        # minting or resetting credentials to move laterally.
        "credential-access": (
            "GetSecretValue", "GetParameter", "GetParameters",
            "GetParametersByPath", "Decrypt", "GetPasswordData",
            "CreateLoginProfile", "UpdateLoginProfile", "GetFederationToken",
            "GetSessionToken",
        ),
        # Persistence & privilege escalation: creating identities, keys, and
        # policy bindings that outlive the initial access.
        "persistence-privesc": (
            "CreateUser", "CreateAccessKey", "CreateRole", "AttachUserPolicy",
            "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy",
            "PutRolePolicy", "PutGroupPolicy", "AddUserToGroup",
            "UpdateAssumeRolePolicy", "CreatePolicyVersion",
            "SetDefaultPolicyVersion", "DeactivateMFADevice",
        ),
        # Resource hijacking & exfiltration: spinning up compute, and sharing
        # snapshots/AMIs/buckets or opening the network to move data out.
        "hijacking-exfil": (
            "RunInstances", "CreateKeyPair", "ImportKeyPair",
            "ModifySnapshotAttribute", "ModifyImageAttribute",
            "ModifyDBSnapshotAttribute", "PutBucketPolicy", "PutBucketAcl",
            "DeleteBucketPolicy", "AuthorizeSecurityGroupIngress",
        ),
        # Discovery: the "who am I / what can I reach" recon that usually
        # bookends the noisy actions above.
        "discovery": (
            "GetCallerIdentity",
        ),
    }

    # Flattened membership set used by the ir=True filter.
    _IR_DANGEROUS_EVENT_NAMES = frozenset(
        name for names in _IR_DANGEROUS_EVENTS.values() for name in names
    )

    # Reverse index: eventName -> attacker-objective category, so an incident
    # finding can be labelled and scored by what the call is usually used for.
    _IR_EVENT_CATEGORY = {
        name: category
        for category, names in _IR_DANGEROUS_EVENTS.items()
        for name in names
    }

    # Base severity (0-100) per category, ranking how urgently a responder
    # should look at a dangerous event *on its own merits* (before any IOC
    # correlation). Turning off logging and planting persistence outrank pure
    # recon. These drive the ranking in incident_local_cloudtrail_logs().
    _IR_CATEGORY_SEVERITY = {
        "anti-forensics": 90,
        "persistence-privesc": 80,
        "hijacking-exfil": 75,
        "credential-access": 70,
        "discovery": 30,
    }

    # Score added when a finding also matches a supplied IOC (known-bad IP or
    # principal). A dangerous action performed by a flagged actor is the top
    # priority — e.g. CreateAccessKey from a flagged IP outranks a GetSecretValue
    # by an unremarkable role, even though both are worth reporting.
    _IR_IOC_OVERLAP_BOOST = 100
    # Base score for an event attributable to an IOC that is NOT itself in the
    # dangerous set — surfaced as "related IOC activity", low priority context.
    _IR_IOC_ONLY_SEVERITY = 40

    @staticmethod
    def _severity_label(score: int) -> str:
        if score >= 150:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    def query_local_cloudtrail_logs(
        self,
        path: str,
        *,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        event_name: Optional[str] = None,
        event_source: Optional[str] = None,
        aws_region: Optional[str] = None,
        account_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        fields: Optional[List[str]] = None,
        max_events: Optional[int] = None,
        ir: bool = False,
    ) -> OperationResult:
        """
        Filter and project fields from CloudTrail log files already on
        disk — e.g. the flat folder produced by
        aws_ir.forensics.download_s3_logs().

        This is an offline query: no AWS API calls, no 90-day CloudTrail
        history limit (works on however far back you downloaded), and
        every field in the raw record is available for projection — not
        just what LookupEvents exposes. Use hunt.lookup_events() instead
        for live/recent data straight from the CloudTrail API.

        Reads every "*.json" and "*.json.gz" file directly under `path`
        (non-recursive; pass a single file path to query just that file).
        Each file is expected to be a standard CloudTrail log file (a
        top-level {"Records": [...]}), though a bare list of records or a
        single record object is also accepted.

        Args:
            path: Directory of CloudTrail log files, or a single file.
            source_ip: Exact match on sourceIPAddress.
            user_name: Matches userIdentity.userName exactly, or as a
                substring of userIdentity.arn (covers assumed-role
                sessions, which have no userName field).
            access_key_id: Exact match on userIdentity.accessKeyId.
            event_name: Exact match on eventName.
            event_source: Exact match on eventSource (e.g. "s3.amazonaws.com").
            aws_region: Exact match on awsRegion.
            account_id: Matches userIdentity.accountId or recipientAccountId.
            start_time / end_time: Filter by eventTime (UTC).
            fields: Dot-path fields to project per matching record, e.g.
                "userIdentity.accountId". Defaults to the fields IR triage
                usually wants first: eventTime, userIdentity.accountId,
                userIdentity.arn, userIdentity.accessKeyId, eventSource,
                eventName, awsRegion, userAgent.
            max_events: Cap on matched records returned. None = unlimited.
            ir: Incident-response triage filter. When True, only records whose
                eventName is in the curated high-signal set
                (AwsIRHunt._IR_DANGEROUS_EVENTS -- disabling logging, credential
                access, persistence/privesc, resource hijacking/exfil) are
                matched, so a single command surfaces the "dangerous" activity
                to plot on an incident timeline. Combines (AND) with the other
                filters; e.g. add start_time/end_time to bound the window, or
                user_name/access_key_id to focus on one principal. If
                event_name is also given, it must additionally match.

        Returns:
            OperationResult with:
              - details["events"]: matching records projected to `fields`,
                sorted by eventTime ascending.
              - details["statistics"]: files scanned/failed, records
                scanned, records matched.
              - details["failed_files"]: present only if some files
                couldn't be parsed — the run still returns what it could.
        """
        fields = list(fields) if fields else list(self._DEFAULT_QUERY_FIELDS)
        event_names = self._IR_DANGEROUS_EVENT_NAMES if ir else None

        target = f"path={path}" + (",ir=true" if ir else "")
        result = OperationResult(
            operation="query_local_cloudtrail_logs",
            target=target,
            success=True,
        )

        files = self._collect_cloudtrail_log_files(path)
        if not files:
            result.add_error(f"No .json/.json.gz files found under {path!r}")
            result.details["events"] = []
            result.details["statistics"] = {
                "files_scanned": 0, "files_failed": 0,
                "records_scanned": 0, "records_matched": 0,
            }
            return result

        matched: List[Tuple[str, Dict[str, Any]]] = []
        records_scanned = 0
        failed_files: List[str] = []

        for file_path in files:
            if max_events is not None and len(matched) >= max_events:
                break

            try:
                records = self._read_cloudtrail_records(file_path)
            except (OSError, ValueError) as exc:
                failed_files.append(f"{file_path}: {exc}")
                continue

            for record in records:
                records_scanned += 1
                if max_events is not None and len(matched) >= max_events:
                    break
                if not self._cloudtrail_record_matches(
                    record,
                    source_ip=source_ip, user_name=user_name,
                    access_key_id=access_key_id, event_name=event_name,
                    event_source=event_source, aws_region=aws_region,
                    account_id=account_id, start_time=start_time, end_time=end_time,
                    event_names=event_names,
                ):
                    continue
                matched.append((
                    record.get("eventTime") or "",
                    {f: _dig(record, f) for f in fields},
                ))

        matched.sort(key=lambda pair: pair[0])
        events = [projected for _, projected in matched]

        result.details["events"] = events
        result.details["statistics"] = {
            "files_scanned": len(files),
            "files_failed": len(failed_files),
            "records_scanned": records_scanned,
            "records_matched": len(events),
        }
        if failed_files:
            result.details["failed_files"] = failed_files
            result.add_error(f"{len(failed_files)} file(s) failed to parse — see details.failed_files")

        _log.info(event("aws_ir_hunt", "query_local_cloudtrail_logs.complete",
                        files=len(files), scanned=records_scanned, matched=len(events)))
        return result

    def incident_local_cloudtrail_logs(
        self,
        path: str,
        *,
        ioc_ips: Optional[List[str]] = None,
        ioc_users: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_findings: Optional[int] = None,
    ) -> OperationResult:
        """
        Offline incident-triage sweep over CloudTrail log files on disk,
        producing findings ranked by severity — the "what do I look at
        first" report for a responder holding a folder of logs.

        Two things are surfaced, and their overlap is the whole point:

          1. Dangerous activity: every record whose eventName is in the
             curated high-signal set (AwsIRHunt._IR_DANGEROUS_EVENTS —
             disabling logging, credential access, persistence/privesc,
             resource hijacking/exfil, recon). This runs whether or not
             IOCs are supplied.
          2. IOC-attributable activity (only when ioc_ips/ioc_users are
             given): any record whose sourceIPAddress matches an IOC IP
             (exact or CIDR) or whose principal matches an IOC user token
             (userName, accessKeyId, principalId, or substring of the ARN)
             — even non-dangerous calls, kept as related context.

        A record that is BOTH dangerous AND attributable to an IOC is the
        highest-priority finding (category base severity + IOC overlap
        boost). This is what makes "CreateAccessKey from a flagged IP"
        outrank "GetSecretValue by an unremarkable role": both are
        reported, but the overlap floats to the top.

        Scoring:
            score = (category base severity if dangerous else 0)
                    + (IOC overlap boost if dangerous & IOC-matched
                       else IOC-only base if IOC-matched
                       else 0)
        mapped to CRITICAL / HIGH / MEDIUM / LOW labels.

        Args:
            path: Directory of CloudTrail log files, or a single file.
            ioc_ips: Known-bad IPs/CIDRs to correlate on sourceIPAddress.
            ioc_users: Known-bad principals — matched against
                userIdentity.userName / accessKeyId / principalId
                (exact) or as a substring of userIdentity.arn (covers
                assumed-role sessions and role ARNs).
            start_time / end_time: Bound the window by eventTime (UTC).
            max_findings: Cap on findings returned (highest severity
                kept). None = unlimited.

        Returns:
            OperationResult with:
              - details["findings"]: ranked list (severity desc, then
                eventTime asc), each a flat dict ready for CSV.
              - details["severity_counts"]: {label: count}.
              - details["iocs"]: the IOCs that were applied.
              - details["statistics"]: files/records scanned & matched.
              - details["failed_files"]: only if some files failed to parse.
        """
        ioc_ips = [ip.strip() for ip in (ioc_ips or []) if ip and ip.strip()]
        ioc_users = [u.strip() for u in (ioc_users or []) if u and u.strip()]

        # Pre-parse IOC IPs into (exact-string set, networks) so we match
        # both plain IPs and CIDRs without re-parsing per record.
        ioc_ip_exact = set()
        ioc_networks = []
        for raw in ioc_ips:
            try:
                ioc_networks.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                ioc_ip_exact.add(raw)

        target = f"path={path}"
        if ioc_ips or ioc_users:
            target += f",iocs={len(ioc_ips)}ip/{len(ioc_users)}user"
        result = OperationResult(
            operation="incident_local_cloudtrail_logs",
            target=target,
            success=True,
        )

        files = self._collect_cloudtrail_log_files(path)
        if not files:
            result.add_error(f"No .json/.json.gz files found under {path!r}")
            result.details["findings"] = []
            result.details["severity_counts"] = {}
            result.details["iocs"] = {"ips": ioc_ips, "users": ioc_users}
            result.details["statistics"] = {
                "files_scanned": 0, "files_failed": 0,
                "records_scanned": 0, "records_matched": 0,
            }
            return result

        findings: List[Dict[str, Any]] = []
        records_scanned = 0
        failed_files: List[str] = []

        for file_path in files:
            try:
                records = self._read_cloudtrail_records(file_path)
            except (OSError, ValueError) as exc:
                failed_files.append(f"{file_path}: {exc}")
                continue

            for record in records:
                records_scanned += 1

                if start_time or end_time:
                    et = self._parse_cloudtrail_time(record.get("eventTime"))
                    if et is None:
                        continue
                    if start_time and et < start_time:
                        continue
                    if end_time and et > end_time:
                        continue

                finding = self._score_incident_record(
                    record,
                    ioc_ip_exact=ioc_ip_exact,
                    ioc_networks=ioc_networks,
                    ioc_users=ioc_users,
                )
                if finding is not None:
                    findings.append(finding)

        # Rank: highest severity first, then chronological within a score.
        findings.sort(key=lambda f: (-f["severity_score"], f["eventTime"] or ""))
        if max_findings is not None:
            findings = findings[:max_findings]

        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        result.details["findings"] = findings
        result.details["severity_counts"] = severity_counts
        result.details["iocs"] = {"ips": ioc_ips, "users": ioc_users}
        result.details["statistics"] = {
            "files_scanned": len(files),
            "files_failed": len(failed_files),
            "records_scanned": records_scanned,
            "records_matched": len(findings),
        }
        if failed_files:
            result.details["failed_files"] = failed_files
            result.add_error(f"{len(failed_files)} file(s) failed to parse — see details.failed_files")

        _log.info(event("aws_ir_hunt", "incident_local_cloudtrail_logs.complete",
                        files=len(files), scanned=records_scanned,
                        findings=len(findings), **severity_counts))
        return result

    @classmethod
    def _score_incident_record(
        cls,
        record: Dict[str, Any],
        *,
        ioc_ip_exact: set,
        ioc_networks: list,
        ioc_users: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Turn one CloudTrail record into a ranked finding, or None if it is
        neither dangerous nor attributable to an IOC."""
        event_name = record.get("eventName") or ""
        category = cls._IR_EVENT_CATEGORY.get(event_name)
        is_dangerous = category is not None

        user_identity = record.get("userIdentity") or {}
        arn = user_identity.get("arn") or ""
        user_name = user_identity.get("userName") or ""
        access_key_id = user_identity.get("accessKeyId") or ""
        principal_id = user_identity.get("principalId") or ""
        source_ip = record.get("sourceIPAddress") or ""

        reasons: List[str] = []
        if is_dangerous:
            reasons.append(f"dangerous:{category}")

        # IOC IP correlation (exact or CIDR).
        ip_hit = False
        if source_ip in ioc_ip_exact:
            ip_hit = True
        elif ioc_networks:
            try:
                addr = ipaddress.ip_address(source_ip)
                ip_hit = any(addr in net for net in ioc_networks)
            except ValueError:
                ip_hit = False
        if ip_hit:
            reasons.append(f"ioc-ip:{source_ip}")

        # IOC principal correlation.
        user_hit = False
        for token in ioc_users:
            if token in (user_name, access_key_id, principal_id) or (arn and token in arn):
                user_hit = True
                reasons.append(f"ioc-user:{token}")
        ioc_match = ip_hit or user_hit

        if not is_dangerous and not ioc_match:
            return None

        base = cls._IR_CATEGORY_SEVERITY.get(category, 0) if is_dangerous else 0
        if ioc_match:
            base += cls._IR_IOC_OVERLAP_BOOST if is_dangerous else cls._IR_IOC_ONLY_SEVERITY
        score = base

        return {
            "severity": cls._severity_label(score),
            "severity_score": score,
            "ioc_match": ioc_match,
            "category": category or ("ioc-related" if ioc_match else ""),
            "reasons": "; ".join(reasons),
            "eventTime": record.get("eventTime") or "",
            "eventName": event_name,
            "eventSource": record.get("eventSource") or "",
            "awsRegion": record.get("awsRegion") or "",
            "arn": arn,
            "userName": user_name,
            "accessKeyId": access_key_id,
            "sourceIPAddress": source_ip,
            "userAgent": record.get("userAgent") or "",
            "errorCode": record.get("errorCode") or "",
        }

    @staticmethod
    def _collect_cloudtrail_log_files(path: str) -> List[str]:
        if os.path.isfile(path):
            return [path]
        if not os.path.isdir(path):
            return []
        return [
            os.path.join(path, name)
            for name in sorted(os.listdir(path))
            if name.endswith(".json") or name.endswith(".json.gz")
        ]

    @staticmethod
    def _read_cloudtrail_records(file_path: str) -> List[Dict[str, Any]]:
        opener = gzip.open if file_path.endswith(".gz") else open
        with opener(file_path, "rt", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            return data["Records"]
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        raise ValueError(f"unrecognized CloudTrail log shape in {file_path}")

    @staticmethod
    def _parse_cloudtrail_time(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        v = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    @staticmethod
    def _cloudtrail_record_matches(
        record: Dict[str, Any],
        *,
        source_ip: Optional[str],
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
        event_source: Optional[str],
        aws_region: Optional[str],
        account_id: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        event_names: Optional[FrozenSet[str]] = None,
    ) -> bool:
        if source_ip and record.get("sourceIPAddress") != source_ip:
            return False
        if event_names is not None and record.get("eventName") not in event_names:
            return False
        if event_name and record.get("eventName") != event_name:
            return False
        if event_source and record.get("eventSource") != event_source:
            return False
        if aws_region and record.get("awsRegion") != aws_region:
            return False

        user_identity = record.get("userIdentity") or {}
        if access_key_id and user_identity.get("accessKeyId") != access_key_id:
            return False
        if user_name:
            arn = user_identity.get("arn") or ""
            if user_identity.get("userName") != user_name and user_name not in arn:
                return False
        if account_id:
            record_account = user_identity.get("accountId") or record.get("recipientAccountId")
            if record_account != account_id:
                return False

        if start_time or end_time:
            event_time = AwsIRHunt._parse_cloudtrail_time(record.get("eventTime"))
            if event_time is None:
                return False
            if start_time and event_time < start_time:
                return False
            if end_time and event_time > end_time:
                return False

        return True
