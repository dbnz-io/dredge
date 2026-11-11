"""Provider-neutral credential detection, redaction and bounded scan accounting."""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
        # Content scans can find tokens in URL userinfo or hostnames. Only
        # preserve a prefix when it carries no credentials or token pattern.
        if "@" not in prefix and not any(d.pattern.search(prefix) for d in _SECRET_DETECTORS):
            if not tail or tail in ("/", "?"):
                return f"{prefix} ({n} chars)"
            return f"{prefix}/[…{len(tail)} chars] ({n} chars)"

    m = _SECRET_ARN_RE.match(value)
    if m:
        prefix, tail = m.group(1), m.group(2)
        if not any(d.pattern.search(prefix) for d in _SECRET_DETECTORS):
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


def _emit_huawei_pair(bag, make_source, bucket):
    """Require named AK/SK fields together; random identifiers are not secrets."""
    names = {str(k).lower().replace("-", "_"): (k, v) for k, v in bag.items()}
    for ak_name, sk_name in (("huaweicloud_sdk_ak", "huaweicloud_sdk_sk"),
                             ("huawei_access_key_id", "huawei_secret_access_key"),
                             ("hw_ak", "hw_sk"), ("ak", "sk")):
        ak, sk = names.get(ak_name), names.get(sk_name)
        if not ak or not sk or not isinstance(ak[1], str) or not isinstance(sk[1], str):
            continue
        if not re.fullmatch(r"[A-Z0-9]{20}", ak[1]) or not _SAK_SHAPE_RE.fullmatch(sk[1]):
            continue
        for (key, value), label in ((ak, "Access Key"), (sk, "Secret Access Key")):
            bucket.add_explicit(value, make_source(key), f"Huawei {label}", "CRITICAL",
                                "context:huawei_key_pair")


def _emit_secret_bag(bag, source, bucket):
    def make_source(key):
        return {**source, "key_name": key}

    _emit_aws_pair(bag, make_source, bucket)
    _emit_huawei_pair(bag, make_source, bucket)
    for key, value in bag.items():
        bucket.add(value, make_source(key), key_name=key)


_SECRET_ASSIGNMENT_RE = re.compile(
    r'''(?<![\w./-])["']?([\w./-]{1,256})["']?\s*[:=]\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s,;}]+))'''
)
_SECRET_PEM_RE = re.compile(
    r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END \1-----", re.S,
)


def _emit_secret_text(text, source, bucket):
    """Inspect JSON / assignments and extract tokens without returning log lines."""
    def walk(value, path=""):
        pending = [(value, path)]
        while pending:
            value, path = pending.pop()
            if isinstance(value, dict):
                bag = {k: v for k, v in value.items() if isinstance(v, str)}
                _emit_secret_bag(bag, {**source, "scope": path}, bucket)
                pending.extend((child, f"{path}.{key}".lstrip("."))
                               for key, child in value.items() if isinstance(child, (dict, list)))
            elif isinstance(value, list):
                pending.extend((child, f"{path}[{i}]") for i, child in enumerate(value))

    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        walk(parsed)
    else:
        bag = {}
        for match in _SECRET_ASSIGNMENT_RE.finditer(text):
            key = match.group(1)
            value = next(v for v in match.groups()[1:] if v is not None)
            # Inspect every occurrence, even repeated names in a text log.
            bucket.add(value, {**source, "key_name": key}, key_name=key)
            bag[key] = value
        _emit_aws_pair(bag, lambda k: {**source, "key_name": k}, bucket)
        _emit_huawei_pair(bag, lambda k: {**source, "key_name": k}, bucket)

    for detector in _SECRET_DETECTORS:
        if detector.name == "private_key_block":
            continue
        for match in detector.pattern.finditer(text):
            value = match.group(1) if detector.name == "aws_secret_with_context" else match.group(0)
            bucket.add_explicit(value, {**source, "key_name": "content"}, detector.category,
                                detector.severity, f"regex:{detector.name}")
    for match in _SECRET_PEM_RE.finditer(text):
        bucket.add_explicit(match.group(0), {**source, "key_name": "content"},
                            "Private Key Block", "CRITICAL", "regex:private_key_block")


@dataclass
class ContentBudget:
    max_calls: int
    max_bytes: int
    max_seconds: int
    started: float = field(default_factory=time.monotonic)
    calls: int = 0
    bytes_read: int = 0
    bytes_reserved: int = 0
    scanned: int = 0
    examined: int = 0
    skipped: int = 0
    reasons: list = field(default_factory=list)

    def stop(self, reason):
        if reason not in self.reasons:
            self.reasons.append(reason)

    def request(self):
        if self.calls >= self.max_calls:
            self.stop("max_api_calls")
        if time.monotonic() - self.started >= self.max_seconds:
            self.stop("max_seconds")
        if self.bytes_reserved >= self.max_bytes:
            self.stop("max_bytes")
        if self.reasons:
            return False
        self.calls += 1
        return True

    def summary(self):
        return {
            "scanned": self.scanned, "examined": self.examined, "skipped": self.skipped,
            "api_calls": self.calls, "bytes_read": self.bytes_read,
            "bytes_budgeted": self.bytes_reserved, "truncated": bool(self.reasons),
            "stop_reasons": self.reasons,
            "limits": {"max_api_calls": self.max_calls, "max_bytes": self.max_bytes,
                       "max_seconds": self.max_seconds},
        }


