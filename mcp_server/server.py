"""
Dredge MCP server -- a READ-ONLY investigation plane for the Dredge cloud-IR
library. It lets an MCP client (e.g. Claude) *chat about how to use Dredge* and
drive its non-destructive surface: log download, hunting, forensic evidence
capture, and cross-source investigation/correlation across AWS, Kubernetes,
GitHub and GCP.

Run: python mcp_server/server.py   (stdio transport)
Register with Claude Code:
  claude mcp add dredge \
    --env AWS_PROFILE=ir --env AWS_REGION=us-east-1 \
    -- python /path/to/mcp_server/server.py

Design goals (mirrors the OpenCDR MCP server's safety model):
  * NO destructive actions are wired. Not one tool reaches Dredge's
    `.response` containment surface (disable/delete IAM, isolate EC2, delete
    pods, drain nodes, quarantine, ...). Those wrappers simply do not exist in
    this process, so an MCP client cannot discover or call them.
  * Capability profiles reduce the tool set further (see below).
  * Defense in depth: the profile is a client-side capability *reduction*, not
    the security boundary. The real boundary is the cloud credentials this
    server runs under -- run it with READ-ONLY credentials (AWS
    SecurityAudit/ReadOnlyAccess, read-only Kubernetes RBAC, a read-scoped
    GitHub token, GCP Logs Viewer). A read-only key with the `forensic` profile
    still cannot snapshot; the `analyst` profile with an admin key still cannot
    mutate, because the mutating tools are never registered.

Capability profiles (DREDGE_MCP_PROFILE)
----------------------------------------
  analyst  (default) -- 100% read-only: how-to/guide, log download (to the
                        local workdir only), all hunts, the posture review, and
                        all read/capture forensics. Never touches cloud state.
  forensic           -- analyst + additive EBS volume snapshotting
                        (create_snapshot). Non-destructive but it does write to
                        the cloud and costs money, so it is opt-in. VPC flow-log
                        enablement and pod `exec` are deliberately NOT wired
                        under any profile.

Under `analyst`, the underlying Dredge instance is built with dry_run=True as a
belt-and-suspenders neutralizer: even if a mutating path were reachable it would
no-op. `forensic` runs with dry_run=False so snapshots actually execute.

Provider gating
---------------
AWS is always available (default credential chain). Kubernetes, GitHub and GCP
tools are only registered when their provider is configured via env (see
`_enabled_providers`), so an AWS-only deployment shows a clean AWS-only tool set.

Local filesystem safety
-----------------------
Every tool that reads or writes local files (log download, review export,
offline CloudTrail analysis) is confined to a single working directory,
DREDGE_MCP_WORKDIR (default ./dredge-mcp-workdir). Paths that escape it are
rejected, so the LLM cannot read or overwrite arbitrary files.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import ipaddress
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

import dredge  # noqa: E402
from dredge import Dredge  # noqa: E402
from dredge.auth import AwsAuthConfig  # noqa: E402
from dredge.config import DredgeConfig  # noqa: E402

mcp = FastMCP("dredge")


class DredgeMCPConfigError(Exception):
    """Raised for server/tool configuration problems -- surfaced as a tool
    error rather than killing the stdio server process."""


# ---------------------------------------------------------------------------
# Typed domain values -- an MCP client sees the valid inputs from the tool
# schema instead of a bare `str`, and out-of-domain values are rejected before
# they reach a cloud SDK.
# ---------------------------------------------------------------------------

Provider = Literal["aws", "k8s", "github", "gcp", "meta"]
SGDirection = Literal["ingress", "egress", "both"]
MultiUserMode = Literal["per_user", "batch"]
ReviewService = Literal["iam", "ec2", "s3", "rds", "lambda", "ecs", "org", "recent"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")

# ---------------------------------------------------------------------------
# Capability profiles + provider gating.
#
# Each tool declares (capability, provider). A tool is only *registered*
# (discoverable/callable) when the active profile grants the capability AND the
# provider is configured. `allowed_tools()` is a pure policy function so the
# mapping can be asserted in tests without re-importing per profile.
# ---------------------------------------------------------------------------

CAP_READ = "read"
CAP_FORENSIC_CAPTURE = "forensic_capture"  # additive, non-destructive cloud write

_ANALYST_CAPS = frozenset({CAP_READ})
_FORENSIC_CAPS = _ANALYST_CAPS | {CAP_FORENSIC_CAPTURE}

_PROFILE_CAPS: dict[str, frozenset[str]] = {
    "analyst": _ANALYST_CAPS,
    "forensic": _FORENSIC_CAPS,
}


def _resolve_profile() -> str:
    raw = (os.getenv("DREDGE_MCP_PROFILE") or "analyst").strip().lower()
    return raw if raw in _PROFILE_CAPS else "analyst"


PROFILE = _resolve_profile()
_ACTIVE_CAPS = _PROFILE_CAPS[PROFILE]

# tool name -> capability / provider, populated by @_tool at import time.
_TOOL_CAPS: dict[str, str] = {}
_TOOL_PROVIDERS: dict[str, str] = {}


def _enabled_providers() -> set[str]:
    """Which provider tool groups are configured (and therefore registered).

    AWS + meta are always on. The optional providers turn on only when their
    required configuration is present in the environment, so an AWS-only
    deployment never shows half-configured GitHub/GCP/K8s tools.
    """
    providers = {"meta", "aws"}
    if os.getenv("DREDGE_GITHUB_ORG") or os.getenv("DREDGE_GITHUB_ENTERPRISE"):
        providers.add("github")
    if os.getenv("DREDGE_GCP_PROJECT"):
        providers.add("gcp")
    if _env_truthy("DREDGE_ENABLE_K8S"):
        providers.add("k8s")
    return providers


def _env_truthy(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


ENABLED_PROVIDERS = _enabled_providers()


def allowed_tools(profile: str, providers: set[str] | None = None) -> set[str]:
    """Names of tools a (profile, providers) combination may discover/call.

    Pure policy: tool is allowed iff its capability is in the profile's caps AND
    its provider is enabled. Defaults to every provider when `providers` is None
    so the profile axis can be tested independently of env.
    """
    caps = _PROFILE_CAPS.get(profile, _ANALYST_CAPS)
    provs = providers if providers is not None else {"meta", "aws", "k8s", "github", "gcp"}
    return {
        name
        for name, cap in _TOOL_CAPS.items()
        if cap in caps and _TOOL_PROVIDERS[name] in provs
    }


def _tool(
    cap: str, provider: str, *, annotations: ToolAnnotations
) -> Callable[[Callable], Callable]:
    """Register a FastMCP tool only if the active profile grants `cap` AND the
    tool's provider is enabled. The function is always returned unchanged (so it
    stays importable/unit-testable regardless of profile/provider)."""

    def deco(fn: Callable) -> Callable:
        _TOOL_CAPS[fn.__name__] = cap
        _TOOL_PROVIDERS[fn.__name__] = provider
        fn._mcp_capability = cap  # type: ignore[attr-defined]
        fn._mcp_provider = provider  # type: ignore[attr-defined]
        fn._mcp_annotations = annotations  # type: ignore[attr-defined]
        if cap in _ACTIVE_CAPS and provider in ENABLED_PROVIDERS:
            mcp.tool(annotations=annotations)(fn)
        return fn

    return deco


# Annotation presets. Every cloud tool reaches an external provider, so
# openWorldHint is True. There is deliberately NO destructive preset -- no
# destructive tool exists in this server.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
_LOCAL_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
# Writes files into the local workdir; does not mutate cloud state.
_LOCAL_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
# Additive cloud write (create_snapshot): non-destructive, but NOT idempotent
# (each call creates a new snapshot).
_CAPTURE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)


# ---------------------------------------------------------------------------
# Local-filesystem sandbox.
# ---------------------------------------------------------------------------

_WORKDIR = Path(os.getenv("DREDGE_MCP_WORKDIR") or (Path.cwd() / "dredge-mcp-workdir")).resolve()


def _safe_path(value: str, *, create_parent: bool = False, create_dir: bool = False) -> str:
    """Resolve `value` INSIDE the MCP workdir, rejecting escapes.

    `value` is always interpreted relative to DREDGE_MCP_WORKDIR (absolute paths
    and `..` traversal that would leave the workdir are refused). This is the
    single choke point for every local read/write tool, so the LLM cannot reach
    arbitrary files. Set DREDGE_MCP_WORKDIR to point the sandbox at real
    evidence locations.
    """
    if value is None or str(value).strip() == "":
        raise ValueError("path is required")
    candidate = (_WORKDIR / str(value)).resolve()
    if candidate != _WORKDIR and _WORKDIR not in candidate.parents:
        raise ValueError(
            f"path {value!r} escapes the MCP workdir ({_WORKDIR}); "
            "set DREDGE_MCP_WORKDIR to allow a different location"
        )
    if create_dir:
        candidate.mkdir(parents=True, exist_ok=True)
    elif create_parent:
        candidate.parent.mkdir(parents=True, exist_ok=True)
    return str(candidate)


# ---------------------------------------------------------------------------
# Input validation / coercion helpers.
# ---------------------------------------------------------------------------


def _parse_time(value: Optional[str], *, name: str) -> Optional[_dt.datetime]:
    """Parse an ISO-8601 date or datetime (UTC). Accepts 'YYYY-MM-DD' or a full
    timestamp with optional trailing 'Z'. Returns None for None/empty."""
    if value is None or str(value).strip() == "":
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        return _dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an ISO-8601 date/datetime (e.g. 2026-08-01 or "
            f"2026-08-01T12:00:00Z), got {value!r}"
        ) from exc


def _validate_ips(ips: Optional[list[str]], *, name: str) -> Optional[list[str]]:
    """Validate a list of IPv4/IPv6 addresses or CIDRs, rejecting garbage before
    it reaches a cloud SDK."""
    if not ips:
        return ips
    for ip in ips:
        try:
            if "/" in str(ip):
                ipaddress.ip_network(str(ip), strict=False)
            else:
                ipaddress.ip_address(str(ip))
        except ValueError as exc:
            raise ValueError(f"{name}: {ip!r} is not a valid IP address or CIDR") from exc
    return ips


def _require_account_id(value: str, *, name: str = "account_id") -> str:
    if not isinstance(value, str) or not _ACCOUNT_ID_RE.match(value):
        raise ValueError(f"{name} must be a 12-digit AWS account ID")
    return value


def _jsonable(obj: Any) -> Any:
    """Coerce a value into something JSON-serializable (datetimes -> ISO
    strings, sets -> lists, bytes -> base64, unknowns -> str())."""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, set):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _jsonable(dataclasses.asdict(obj))
    return str(obj)


def _result(obj: Any) -> dict:
    """Serialize a Dredge OperationResult (or any value) into a JSON-safe dict.

    OperationResult carries its own `success`/`errors`, so a failed operation is
    returned as data (the LLM can read the errors) rather than raised."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _jsonable(dataclasses.asdict(obj))
    return {"value": _jsonable(obj)}


# ---------------------------------------------------------------------------
# Dredge instance (built once, from the environment -- NEVER from tool args).
# Credentials come from the standard provider chains, exactly like the
# credentials-are-server-side rule in the OpenCDR MCP.
# ---------------------------------------------------------------------------

_DREDGE: Optional[Dredge] = None


def _build_dredge() -> Dredge:
    region = (
        os.getenv("DREDGE_AWS_REGION")
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
    )
    # analyst => dry_run True (neutralize any accidental mutation); the forensic
    # profile needs dry_run False so snapshots actually run.
    dry_run = CAP_FORENSIC_CAPTURE not in _ACTIVE_CAPS
    config = DredgeConfig(region_name=region, dry_run=dry_run)

    github_config = None
    if "github" in ENABLED_PROVIDERS:
        from dredge.github_ir.config import GitHubIRConfig

        github_config = GitHubIRConfig(
            org=os.getenv("DREDGE_GITHUB_ORG") or None,
            enterprise=os.getenv("DREDGE_GITHUB_ENTERPRISE") or None,
            base_url=os.getenv("DREDGE_GITHUB_BASE_URL") or "https://api.github.com",
        )

    gcp_config = None
    if "gcp" in ENABLED_PROVIDERS:
        from dredge.gcp_ir.config import GcpIRConfig

        gcp_config = GcpIRConfig(
            project_id=os.environ["DREDGE_GCP_PROJECT"],
            credentials_file=os.getenv("DREDGE_GCP_CREDENTIALS")
            or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"),
        )

    k8s_config = None
    if "k8s" in ENABLED_PROVIDERS:
        from dredge.k8s_ir.config import K8sAuthConfig

        k8s_config = K8sAuthConfig(
            kubeconfig_path=os.getenv("DREDGE_K8S_KUBECONFIG") or None,
            context=os.getenv("DREDGE_K8S_CONTEXT") or None,
            in_cluster=_env_truthy("DREDGE_K8S_IN_CLUSTER"),
            namespace=os.getenv("DREDGE_K8S_NAMESPACE") or None,
        )

    return Dredge(
        auth=AwsAuthConfig(region_name=region),
        config=config,
        github_config=github_config,
        gcp_config=gcp_config,
        k8s_config=k8s_config,
    )


def _d() -> Dredge:
    global _DREDGE
    if _DREDGE is None:
        _DREDGE = _build_dredge()
    return _DREDGE


def _aws():
    return _d().aws_ir


def _k8s():
    ns = _d().k8s_ir
    if ns is None:
        raise DredgeMCPConfigError(
            "Kubernetes is not configured. Set DREDGE_ENABLE_K8S=1 (and optionally "
            "DREDGE_K8S_CONTEXT / DREDGE_K8S_KUBECONFIG / DREDGE_K8S_IN_CLUSTER)."
        )
    return ns


def _github():
    ns = _d().github_ir
    if ns is None:
        raise DredgeMCPConfigError(
            "GitHub is not configured. Set DREDGE_GITHUB_ORG or DREDGE_GITHUB_ENTERPRISE "
            "and provide a token via GITHUB_TOKEN."
        )
    return ns


def _gcp():
    ns = _d().gcp_ir
    if ns is None:
        raise DredgeMCPConfigError("GCP is not configured. Set DREDGE_GCP_PROJECT.")
    return ns


# ===========================================================================
# META -- how-to / capability discovery (local, no cloud calls).
# ===========================================================================

_DOCS = Path(__file__).resolve().parent.parent / "docs"

# Fixed topic -> doc-file whitelist. The key space is closed, so no user input
# ever reaches the filesystem as a path.
_GUIDE_TOPICS: dict[str, str] = {
    "overview": "getting-started.md",
    "getting-started": "getting-started.md",
    "authentication": "authentication.md",
    "installation": "installation.md",
    "reference": "reference.md",
    "cli": "cli/README.md",
    "aws": "cli/aws.md",
    "github": "cli/github.md",
    "kubernetes": "cli/kubernetes.md",
    "library": "library/README.md",
    "roadmap": "roadmap.md",
}


@_tool(CAP_READ, "meta", annotations=_LOCAL_READ_ONLY)
def dredge_capabilities() -> dict:
    """Describe this Dredge MCP: active profile, enabled providers, the local
    workdir, the security model, and the tools currently registered. Read-only,
    no cloud calls. Start here to understand what you can do and how to enable
    more providers."""
    registered = sorted(t.name for t in mcp._tool_manager.list_tools())
    return {
        "profile": PROFILE,
        "profile_capabilities": sorted(_ACTIVE_CAPS),
        "enabled_providers": sorted(ENABLED_PROVIDERS),
        "workdir": str(_WORKDIR),
        "dry_run": CAP_FORENSIC_CAPTURE not in _ACTIVE_CAPS,
        "registered_tools": registered,
        "notes": [
            "No destructive/containment actions are wired under any profile.",
            "The security boundary is the cloud credentials this server runs "
            "under -- prefer read-only credentials.",
            "Local file tools are confined to the workdir; set DREDGE_MCP_WORKDIR "
            "to change it.",
            "Enable providers: DREDGE_GITHUB_ORG/ENTERPRISE (+GITHUB_TOKEN), "
            "DREDGE_GCP_PROJECT, DREDGE_ENABLE_K8S=1.",
            "Set DREDGE_MCP_PROFILE=forensic to add additive EBS snapshotting.",
        ],
        "guide_topics": sorted(set(_GUIDE_TOPICS)),
    }


@_tool(CAP_READ, "meta", annotations=_LOCAL_READ_ONLY)
def dredge_guide(topic: str = "overview") -> dict:
    """Return Dredge how-to documentation for a topic, to answer questions about
    using the tool. Read-only. Valid topics: overview, getting-started,
    authentication, installation, reference, cli, aws, github, kubernetes,
    library, roadmap. Unknown topics return the list of valid ones."""
    key = (topic or "overview").strip().lower()
    if key not in _GUIDE_TOPICS:
        return {"error": "unknown topic", "available_topics": sorted(set(_GUIDE_TOPICS))}
    doc = _DOCS / _GUIDE_TOPICS[key]
    try:
        return {"topic": key, "source": _GUIDE_TOPICS[key], "content": doc.read_text()}
    except OSError as exc:
        return {"topic": key, "error": f"doc unavailable: {exc}"}


# ===========================================================================
# AWS -- HUNT
# ===========================================================================


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_cloudtrail(
    user_name: Optional[str] = None,
    access_key_id: Optional[str] = None,
    event_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 500,
) -> dict:
    """Search CloudTrail (LookupEvents) in the session region by user, access
    key, event name and/or source IP over a time window. Read-only. Times are
    ISO-8601 (e.g. 2026-08-01T00:00:00Z). For every enabled region use
    aws_hunt_cloudtrail_multi_region."""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    r = _aws().hunt.lookup_events(
        user_name=user_name,
        access_key_id=access_key_id,
        event_name=event_name,
        source_ip=source_ip,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_cloudtrail_multi_region(
    regions: Optional[list[str]] = None,
    user_name: Optional[str] = None,
    access_key_id: Optional[str] = None,
    event_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events_per_region: int = 500,
    max_workers: int = 12,
) -> dict:
    """Search CloudTrail concurrently across regions. Read-only. Pass
    regions=["all"] (or omit) for every enabled region, or an explicit list.
    Results are merged, time-sorted, with a per-region breakdown."""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    regions_arg = "all" if (regions in (None, ["all"], [])) else regions
    r = _aws().hunt.lookup_events_multi_region(
        regions=regions_arg,
        user_name=user_name,
        access_key_id=access_key_id,
        event_name=event_name,
        source_ip=source_ip,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events_per_region=max_events_per_region,
        max_workers=max_workers,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_cloudtrail_multi_user(
    users: list[str],
    mode: MultiUserMode = "per_user",
    event_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events_per_user: int = 500,
) -> dict:
    """Search CloudTrail for several usernames at once (one LookupEvents call
    per user). Read-only. mode='per_user' groups results by user;
    mode='batch' merges them into one time-sorted list."""
    if not users:
        raise ValueError("users must be a non-empty list of usernames")
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    r = _aws().hunt.hunt_cloudtrail_multi_user(
        users,
        mode=mode,
        event_name=event_name,
        source_ip=source_ip,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events_per_user=max_events_per_user,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_user_activity_by_ip(
    user_name: str,
    allowed_ips: list[str],
    event_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 500,
) -> dict:
    """Correlation hunt: pull one identity's CloudTrail activity and classify
    every event by whether its source IP falls inside an allowlist
    (IPs/CIDRs). Read-only. The `unexpected_events` bucket is the
    baseline-deviation signal."""
    if not user_name:
        raise ValueError("user_name is required")
    _validate_ips(allowed_ips, name="allowed_ips")
    r = _aws().hunt.hunt_user_activity_by_ip(
        user_name,
        allowed_ips,
        event_name=event_name,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_guardduty_findings(
    detector_id: str,
    severity_min: float = 0.0,
    max_findings: int = 100,
    finding_types: Optional[list[str]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> dict:
    """List and retrieve GuardDuty findings for a detector. Read-only."""
    if not detector_id:
        raise ValueError("detector_id is required")
    r = _aws().hunt.list_guardduty_findings(
        detector_id,
        severity_min=severity_min,
        max_findings=max_findings,
        finding_types=finding_types,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_security_hub_findings(
    severity_labels: Optional[list[str]] = None,
    workflow_status: Optional[list[str]] = None,
    product_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_findings: int = 100,
) -> dict:
    """Query Security Hub findings with optional severity/workflow/product
    filters. Read-only."""
    r = _aws().hunt.hunt_security_hub_findings(
        severity_labels=severity_labels,
        workflow_status=workflow_status,
        product_name=product_name,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_findings=max_findings,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_access_analyzer_findings(
    analyzer_arn: str,
    status: Optional[str] = None,
    resource_type: Optional[str] = None,
    max_findings: int = 100,
) -> dict:
    """List IAM Access Analyzer findings (external/public access) for an
    analyzer ARN. Read-only."""
    if not analyzer_arn:
        raise ValueError("analyzer_arn is required")
    r = _aws().hunt.hunt_access_analyzer_findings(
        analyzer_arn, status=status, resource_type=resource_type, max_findings=max_findings
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_config_resource_history(
    resource_type: str,
    resource_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_items: int = 100,
) -> dict:
    """Retrieve AWS Config configuration history for a specific resource (how it
    changed over time). Read-only."""
    if not resource_type or not resource_id:
        raise ValueError("resource_type and resource_id are required")
    r = _aws().hunt.hunt_config_resource_history(
        resource_type,
        resource_id,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_items=max_items,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_cloudwatch_logs(
    log_group: str,
    query: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_results: int = 1000,
) -> dict:
    """Run a CloudWatch Logs Insights query against a log group and return the
    rows. Read-only."""
    if not log_group or not query:
        raise ValueError("log_group and query are required")
    r = _aws().hunt.hunt_cloudwatch_logs(
        log_group,
        query,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_results=max_results,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_iam_credential_report() -> dict:
    """Generate and retrieve the IAM credential report (all users: keys, MFA,
    password/last-used). Read-only."""
    return _result(_aws().hunt.get_iam_credential_report())


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_iam_admin_principals() -> dict:
    """List IAM users/roles with admin-equivalent access. Read-only."""
    return _result(_aws().hunt.list_iam_admin_principals())


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_unusual_login_locations(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 200,
) -> dict:
    """Pull console login events (ConsoleLogin) from CloudTrail for review of
    unusual source locations. Read-only."""
    r = _aws().hunt.hunt_unusual_login_locations(
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_exposed_s3_buckets() -> dict:
    """List S3 buckets that may be publicly accessible. Read-only."""
    return _result(_aws().hunt.hunt_exposed_s3_buckets())


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_public_snapshots(owner_id: Optional[str] = None) -> dict:
    """List EBS snapshots shared publicly (optionally filtered to an owner
    account id). Read-only."""
    if owner_id:
        _require_account_id(owner_id, name="owner_id")
    return _result(_aws().hunt.list_public_snapshots(owner_id=owner_id))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_open_security_groups(
    ports: Optional[list[int]] = None, max_groups: int = 500
) -> dict:
    """Find EC2 security groups with ingress open to 0.0.0.0/0 or ::/0
    (optionally only for specific ports). Read-only."""
    return _result(_aws().hunt.list_open_security_groups(ports=ports, max_groups=max_groups))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_security_groups_by_ip(
    ips: list[str], direction: SGDirection = "both", max_groups: int = 500
) -> dict:
    """Find EC2 security groups whose ingress/egress CIDR ranges cover the given
    IPs. Read-only. Useful to pivot from a suspect IP to exposed groups."""
    _validate_ips(ips, name="ips")
    if not ips:
        raise ValueError("ips must be a non-empty list")
    r = _aws().hunt.hunt_security_groups_by_ip(ips, direction=direction, max_groups=max_groups)
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_hunt_lambda_env_secrets(
    patterns: Optional[list[str]] = None, max_functions: int = 200
) -> dict:
    """List Lambda functions whose environment variables look like they contain
    secrets. Read-only."""
    return _result(
        _aws().hunt.hunt_lambda_env_secrets(patterns=patterns, max_functions=max_functions)
    )


@_tool(CAP_READ, "aws", annotations=_LOCAL_READ_ONLY)
def aws_hunt_local_cloudtrail(
    path: str,
    source_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    access_key_id: Optional[str] = None,
    event_name: Optional[str] = None,
    event_source: Optional[str] = None,
    aws_region: Optional[str] = None,
    account_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: Optional[int] = None,
) -> dict:
    """Filter/project CloudTrail log files already downloaded into the workdir
    (offline, no cloud calls). `path` is relative to DREDGE_MCP_WORKDIR."""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    if account_id:
        _require_account_id(account_id)
    r = _aws().hunt.query_local_cloudtrail_logs(
        _safe_path(path),
        source_ip=source_ip,
        user_name=user_name,
        access_key_id=access_key_id,
        event_name=event_name,
        event_source=event_source,
        aws_region=aws_region,
        account_id=account_id,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_LOCAL_READ_ONLY)
def aws_incident_local_cloudtrail(
    path: str,
    ioc_ips: Optional[list[str]] = None,
    ioc_users: Optional[list[str]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_findings: Optional[int] = None,
) -> dict:
    """Offline incident-triage sweep over downloaded CloudTrail logs, ranking
    findings by severity and correlating on IoC IPs/users. `path` is relative to
    DREDGE_MCP_WORKDIR. No cloud calls."""
    _validate_ips(ioc_ips, name="ioc_ips")
    r = _aws().hunt.incident_local_cloudtrail_logs(
        _safe_path(path),
        ioc_ips=ioc_ips,
        ioc_users=ioc_users,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_findings=max_findings,
    )
    return _result(r)


# ===========================================================================
# AWS -- REVIEW (read-only posture review)
# ===========================================================================


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_review(
    services: Optional[list[ReviewService]] = None,
    deep: bool = False,
    incident_start: Optional[str] = None,
    ips: Optional[list[str]] = None,
    regions: Optional[list[str]] = None,
    export: Optional[Literal["csv", "html"]] = None,
    output_name: Optional[str] = None,
    max_workers: int = 12,
) -> dict:
    """Run Dredge's read-only security posture review (IAM/S3/RDS/EC2/Lambda/
    ECS/org guardrails/recent). Read-only cloud access. `deep=True` adds tier-2
    checks. Pass regions=["all"] to fan regional checks across every enabled
    region. Optionally `export` the findings to 'csv' or 'html' written into the
    workdir (`output_name` sets the filename)."""
    _validate_ips(ips, name="ips")
    tiers = (1, 2) if deep else (1,)
    review = _aws().review
    result = review.review(
        services=services,
        tiers=tiers,
        incident_start=_parse_time(incident_start, name="incident_start"),
        ips=ips,
        regions=("all" if regions in (["all"],) else regions),
        max_workers=max_workers,
    )
    out = _result(result)
    if export:
        name = output_name or f"dredge-review.{export}"
        if not name.endswith(f".{export}"):
            name = f"{name}.{export}"
        dest = _safe_path(name, create_parent=True)
        (review.to_csv if export == "csv" else review.to_html)(result, dest)
        out["exported_to"] = dest
    return out


# ===========================================================================
# AWS -- FORENSICS (reads / captures; download writes to the workdir)
# ===========================================================================


@_tool(CAP_READ, "aws", annotations=_LOCAL_WRITE)
def aws_forensics_download_s3_logs(
    bucket: str,
    destination: str,
    prefix: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    days_ago: Optional[int] = None,
    max_objects: Optional[int] = None,
    max_workers: int = 8,
) -> dict:
    """Download log objects (e.g. CloudTrail) from an S3 bucket/prefix into the
    local workdir for offline analysis. Reads cloud, writes only to
    `destination` (relative to DREDGE_MCP_WORKDIR). Passing start/end/days_ago
    uses the date-aware walk for org/Control Tower CloudTrail layouts."""
    if not bucket:
        raise ValueError("bucket is required")
    r = _aws().forensics.download_s3_logs(
        bucket,
        prefix=prefix,
        destination=_safe_path(destination, create_dir=True),
        max_objects=max_objects,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        days_ago=days_ago,
        max_workers=max_workers,
    )
    return _result(r)


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_cloudtrail_status(include_shadow_trails: bool = False) -> dict:
    """Capture the status/configuration of all CloudTrail trails (is logging on,
    event selectors, etc.). Read-only."""
    return _result(_aws().forensics.get_cloudtrail_status(include_shadow_trails=include_shadow_trails))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_iam_user_detail(user_name: str) -> dict:
    """Capture a comprehensive snapshot of an IAM user (policies, keys, groups,
    MFA). Read-only."""
    if not user_name:
        raise ValueError("user_name is required")
    return _result(_aws().forensics.get_iam_user_detail(user_name))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_s3_bucket_policy(bucket_name: str) -> dict:
    """Capture a bucket's policy, ACL and public-access-block configuration.
    Read-only."""
    if not bucket_name:
        raise ValueError("bucket_name is required")
    return _result(_aws().forensics.get_s3_bucket_policy(bucket_name))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_ec2_user_data(instance_id: str) -> dict:
    """Capture an EC2 instance's user-data script. Read-only."""
    if not instance_id:
        raise ValueError("instance_id is required")
    return _result(_aws().forensics.get_ec2_user_data(instance_id))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_lambda_environment(
    function_name: str, qualifier: Optional[str] = None
) -> dict:
    """Capture a Lambda function's environment variables (cleartext). Read-only."""
    if not function_name:
        raise ValueError("function_name is required")
    return _result(_aws().forensics.get_lambda_environment(function_name, qualifier=qualifier))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_recently_active_roles(hours: int = 24, max_roles: int = 200) -> dict:
    """List IAM roles used within the last `hours`. Read-only."""
    return _result(_aws().forensics.list_recently_active_roles(hours=hours, max_roles=max_roles))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_ssm_session_history(
    instance_id: Optional[str] = None, owner: Optional[str] = None, max_sessions: int = 100
) -> dict:
    """Retrieve completed SSM Session Manager history (optionally by instance or
    owner). Read-only."""
    return _result(
        _aws().forensics.capture_ssm_session_history(
            instance_id=instance_id, owner=owner, max_sessions=max_sessions
        )
    )


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_rds_parameter_group(group_name: str, max_params: int = 500) -> dict:
    """Retrieve all parameters from an RDS DB parameter group. Read-only."""
    if not group_name:
        raise ValueError("group_name is required")
    return _result(_aws().forensics.get_rds_parameter_group(group_name, max_params=max_params))


@_tool(CAP_READ, "aws", annotations=_READ_ONLY)
def aws_forensics_guardduty_finding_detail(detector_id: str, finding_ids: list[str]) -> dict:
    """Retrieve full GuardDuty finding objects by id. Read-only."""
    if not detector_id or not finding_ids:
        raise ValueError("detector_id and a non-empty finding_ids list are required")
    return _result(_aws().forensics.capture_guardduty_finding_detail(detector_id, *finding_ids))


# ---- forensic-capture profile: additive, non-destructive cloud writes -------


@_tool(CAP_FORENSIC_CAPTURE, "aws", annotations=_CAPTURE)
def aws_forensics_snapshot_volume(
    volume_id: str, description: str = "Dredge forensic snapshot"
) -> dict:
    """Create a forensic EBS snapshot of a single volume. ADDITIVE cloud write
    (non-destructive: it copies data, deletes nothing) -- available only under
    DREDGE_MCP_PROFILE=forensic."""
    if not volume_id:
        raise ValueError("volume_id is required")
    return _result(_aws().forensics.get_ebs_snapshot(volume_id, description=description))


@_tool(CAP_FORENSIC_CAPTURE, "aws", annotations=_CAPTURE)
def aws_forensics_snapshot_instance_volumes(
    instance_id: str,
    include_root: bool = True,
    description_prefix: str = "Dredge forensic snapshot",
) -> dict:
    """Create forensic EBS snapshots of all (or non-root) volumes on an EC2
    instance. ADDITIVE cloud write (non-destructive) -- available only under
    DREDGE_MCP_PROFILE=forensic."""
    if not instance_id:
        raise ValueError("instance_id is required")
    return _result(
        _aws().forensics.snapshot_instance_volumes(
            instance_id, include_root=include_root, description_prefix=description_prefix
        )
    )


# ===========================================================================
# KUBERNETES -- HUNT + read-only FORENSICS  (no exec, no response)
# ===========================================================================


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_hunt_events(
    namespace: Optional[str] = None,
    involved_object_kind: Optional[str] = None,
    involved_object_name: Optional[str] = None,
    reason: Optional[str] = None,
    event_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 500,
) -> dict:
    """Search Kubernetes Events, optionally scoped to a namespace/object/reason.
    Read-only. Flavor-agnostic (EKS/GKE/AKS/self-managed)."""
    r = _k8s().hunt.list_events(
        namespace=namespace,
        involved_object_kind=involved_object_kind,
        involved_object_name=involved_object_name,
        reason=reason,
        event_type=event_type,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_hunt_role_bindings_for_subject(
    kind: str, name: str, namespace: Optional[str] = None
) -> dict:
    """Find every RoleBinding/ClusterRoleBinding referencing a subject (User,
    Group, or ServiceAccount). Read-only. kind is the subject kind."""
    if not kind or not name:
        raise ValueError("kind and name are required")
    return _result(_k8s().hunt.list_role_bindings_for_subject(kind=kind, name=name, namespace=namespace))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_hunt_pods_by_service_account(namespace: str, service_account_name: str) -> dict:
    """List pods in a namespace running under a given ServiceAccount. Read-only."""
    if not namespace or not service_account_name:
        raise ValueError("namespace and service_account_name are required")
    return _result(_k8s().hunt.list_pods_by_service_account(namespace, service_account_name))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_hunt_privileged_pods(max_pods: int = 500) -> dict:
    """Flag pods with elevated host access (privileged containers, hostNetwork/
    hostPID/hostIPC). Read-only."""
    return _result(_k8s().hunt.list_privileged_pods(max_pods=max_pods))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_pod_manifest(namespace: str, name: str) -> dict:
    """Capture a pod's full spec + status. Read-only."""
    if not namespace or not name:
        raise ValueError("namespace and name are required")
    return _result(_k8s().forensics.get_pod_manifest(namespace, name))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_pod_logs(
    namespace: str,
    name: str,
    container: Optional[str] = None,
    previous: bool = False,
    tail_lines: Optional[int] = None,
) -> dict:
    """Capture container logs from a pod. Read-only. `previous=True` reads the
    prior crashed container."""
    if not namespace or not name:
        raise ValueError("namespace and name are required")
    r = _k8s().forensics.get_pod_logs(
        namespace, name, container=container, previous=previous, tail_lines=tail_lines
    )
    return _result(r)


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_pod_events(namespace: str, name: str) -> dict:
    """List Events whose involvedObject is the given pod. Read-only."""
    if not namespace or not name:
        raise ValueError("namespace and name are required")
    return _result(_k8s().forensics.get_pod_events(namespace, name))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_describe_node(name: str) -> dict:
    """Capture a node's full manifest (spec, status, conditions). Read-only."""
    if not name:
        raise ValueError("name is required")
    return _result(_k8s().forensics.describe_node(name))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_workload_manifest(kind: str, namespace: str, name: str) -> dict:
    """Capture a workload controller's manifest (Deployment/StatefulSet/
    DaemonSet). Read-only."""
    if not kind or not namespace or not name:
        raise ValueError("kind, namespace and name are required")
    return _result(_k8s().forensics.capture_workload_manifest(kind, namespace, name))


@_tool(CAP_READ, "k8s", annotations=_READ_ONLY)
def k8s_forensics_pods_on_node(name: str) -> dict:
    """List every pod currently scheduled to a node. Read-only."""
    if not name:
        raise ValueError("name is required")
    return _result(_k8s().forensics.list_pods_on_node(name))


# ===========================================================================
# GITHUB -- HUNT + read-only FORENSICS
# ===========================================================================


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_audit_log(
    actor: Optional[str] = None,
    action: Optional[str] = None,
    repo: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    include: Optional[Literal["web", "git", "all"]] = None,
    max_events: int = 500,
) -> dict:
    """Search the org/enterprise GitHub audit log by actor/action/repo/source
    IP over a time range. Read-only."""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    r = _github().hunt.search_audit_log(
        actor=actor,
        action=action,
        repo=repo,
        source_ip=source_ip,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        include=include,
        max_events=max_events,
    )
    return _result(r)


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_secret_scanning_alerts(
    repo: Optional[str] = None, state: str = "open", max_alerts: int = 100
) -> dict:
    """List secret-scanning alerts for the org or a specific repo. Read-only."""
    return _result(_github().hunt.hunt_secret_scanning_alerts(repo, state=state, max_alerts=max_alerts))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_code_scanning_alerts(
    repo: str, state: str = "open", max_alerts: int = 100
) -> dict:
    """List code-scanning alerts for a repository. Read-only."""
    if not repo:
        raise ValueError("repo is required")
    return _result(_github().hunt.hunt_code_scanning_alerts(repo, state=state, max_alerts=max_alerts))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_org_members(role: Optional[str] = None, max_members: int = 500) -> dict:
    """List organization members (optionally filtered by role, e.g. 'admin').
    Read-only."""
    return _result(_github().hunt.list_org_members(role=role, max_members=max_members))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_outside_collaborators(max_items: int = 200) -> dict:
    """List users with repository access who are not org members. Read-only."""
    return _result(_github().hunt.list_outside_collaborators(max_items=max_items))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_apps(max_items: int = 200) -> dict:
    """List GitHub App installations on the organization. Read-only."""
    return _result(_github().hunt.list_github_apps(max_items=max_items))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_hunt_actions_workflow_runs(
    repo: str, workflow_id: Optional[str] = None, status: Optional[str] = None, max_runs: int = 100
) -> dict:
    """List GitHub Actions workflow runs for a repository. Read-only."""
    if not repo:
        raise ValueError("repo is required")
    r = _github().hunt.list_actions_workflow_runs(
        repo, workflow_id=workflow_id, status=status, max_runs=max_runs
    )
    return _result(r)


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_org_settings() -> dict:
    """Capture a full configuration snapshot of the organization. Read-only."""
    return _result(_github().forensics.get_org_settings())


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_repo_metadata(repo: str) -> dict:
    """Capture the full configuration snapshot of a repository. Read-only."""
    if not repo:
        raise ValueError("repo is required")
    return _result(_github().forensics.get_repo_metadata(repo))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_repo_collaborators(repo: str, max_items: int = 200) -> dict:
    """List all collaborators on a repository (members + outside). Read-only."""
    if not repo:
        raise ValueError("repo is required")
    return _result(_github().forensics.list_repo_collaborators(repo, max_items=max_items))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_branch_protection(repo: str, branch: str) -> dict:
    """Get branch-protection rules for a repository branch. Read-only."""
    if not repo or not branch:
        raise ValueError("repo and branch are required")
    return _result(_github().forensics.get_branch_protection(repo, branch))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_org_webhooks() -> dict:
    """List all organization-level webhooks. Read-only."""
    return _result(_github().forensics.list_org_webhooks())


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_repo_webhooks(repo: str) -> dict:
    """List all repository-level webhooks. Read-only."""
    if not repo:
        raise ValueError("repo is required")
    return _result(_github().forensics.list_repo_webhooks(repo))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_commit_history(repo: str, branch: str, max_commits: int = 100) -> dict:
    """Capture the commit history for a repository branch. Read-only."""
    if not repo or not branch:
        raise ValueError("repo and branch are required")
    return _result(_github().forensics.get_commit_history(repo, branch, max_commits=max_commits))


@_tool(CAP_READ, "github", annotations=_READ_ONLY)
def github_forensics_file_at_commit(repo: str, path: str, ref: str) -> dict:
    """Retrieve a file's contents at a specific commit/branch. Read-only."""
    if not repo or not path or not ref:
        raise ValueError("repo, path and ref are required")
    return _result(_github().forensics.get_file_at_commit(repo, path, ref))


# ===========================================================================
# GCP -- HUNT (Cloud Logging; module is in-progress upstream)
# ===========================================================================


@_tool(CAP_READ, "gcp", annotations=_READ_ONLY)
def gcp_hunt_logs(
    principal_email: Optional[str] = None,
    method_name: Optional[str] = None,
    resource_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    log_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_entries: int = 500,
) -> dict:
    """Search GCP Cloud Logging by principal/method/resource/source IP over a
    time range. Read-only. (GCP module is in-progress upstream.)"""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    r = _gcp().hunt.search_logs(
        principal_email=principal_email,
        method_name=method_name,
        resource_name=resource_name,
        source_ip=source_ip,
        log_id=log_id,
        start_time=_parse_time(start_time, name="start_time"),
        end_time=_parse_time(end_time, name="end_time"),
        max_entries=max_entries,
    )
    return _result(r)


@_tool(CAP_READ, "gcp", annotations=_READ_ONLY)
def gcp_hunt_today(
    principal_email: Optional[str] = None,
    method_name: Optional[str] = None,
    resource_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    log_id: Optional[str] = None,
    max_entries: int = 500,
) -> dict:
    """Fetch today's (UTC) GCP logs with the same IR-friendly filters. Read-only."""
    _validate_ips([source_ip] if source_ip else None, name="source_ip")
    r = _gcp().hunt.search_today(
        principal_email=principal_email,
        method_name=method_name,
        resource_name=resource_name,
        source_ip=source_ip,
        log_id=log_id,
        max_entries=max_entries,
    )
    return _result(r)


if __name__ == "__main__":
    mcp.run()
