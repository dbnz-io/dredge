"""
Hardening tests for the Dredge MCP server: the no-destructive-actions
guarantee, tool safety annotations, capability profiles, provider gating, the
local-filesystem sandbox, and input validation.

These assert the *safety envelope* independent of any cloud call. `mcp` and the
`dredge` package must be importable; the whole module skips otherwise.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import server  # noqa: E402  (mcp_server is on sys.path via conftest below)


# ---------------------------------------------------------------------------
# 1. The core guarantee: NO destructive action is wired, anywhere.
# ---------------------------------------------------------------------------


def test_no_tool_is_destructive():
    for name in server._TOOL_CAPS:
        ann = getattr(server, name)._mcp_annotations
        assert ann.destructiveHint is False, f"{name} must not be destructive"


def test_server_source_never_touches_response_surface():
    # The response/containment surface (disable/delete/isolate/drain/quarantine)
    # must never be reached. Strip comments/strings-ish and assert no `.response`
    # attribute access survives in executable code.
    src = Path(server.__file__).read_text().splitlines()
    offending = [
        ln for ln in src if ".response" in ln and not ln.lstrip().startswith("#") and "`.response`" not in ln
    ]
    assert offending == [], f"server accesses .response: {offending}"


def test_dangerous_forensics_are_not_wired():
    # pod exec and VPC flow-log enablement are intentionally excluded.
    src = Path(server.__file__).read_text()
    assert "exec_pod_command" not in src
    assert "enable_vpc_flow_logs" not in src


# ---------------------------------------------------------------------------
# 2. Tool safety annotations.
# ---------------------------------------------------------------------------

# The only non-read-only tools: the local log download and the two additive
# EBS snapshot captures. Everything else is read-only + idempotent.
_NOT_READ_ONLY = {
    "aws_forensics_download_s3_logs",
    "aws_forensics_snapshot_volume",
    "aws_forensics_snapshot_instance_volumes",
}


@pytest.mark.parametrize("name", sorted(server._TOOL_CAPS))
def test_tool_annotation_shape(name):
    ann = getattr(server, name)._mcp_annotations
    assert ann.destructiveHint is False
    assert ann.readOnlyHint is (name not in _NOT_READ_ONLY), name
    assert ann.idempotentHint is (name not in _NOT_READ_ONLY), name


def test_every_tool_is_classified_with_cap_and_provider():
    assert set(server._TOOL_CAPS) == set(server._TOOL_PROVIDERS)
    for name, cap in server._TOOL_CAPS.items():
        assert cap in {server.CAP_READ, server.CAP_FORENSIC_CAPTURE}, name
        assert server._TOOL_PROVIDERS[name] in {"meta", "aws", "k8s", "github", "gcp"}, name


def test_only_snapshot_tools_need_capture_capability():
    capture = {n for n, c in server._TOOL_CAPS.items() if c == server.CAP_FORENSIC_CAPTURE}
    assert capture == {"aws_forensics_snapshot_volume", "aws_forensics_snapshot_instance_volumes"}


# ---------------------------------------------------------------------------
# 3. Capability profiles (pure policy -- no reimport per profile).
# ---------------------------------------------------------------------------


def test_analyst_profile_has_no_capture():
    analyst = server.allowed_tools("analyst")
    assert all(server._TOOL_CAPS[n] == server.CAP_READ for n in analyst)


def test_forensic_profile_adds_exactly_the_snapshots():
    added = server.allowed_tools("forensic") - server.allowed_tools("analyst")
    assert added == {"aws_forensics_snapshot_volume", "aws_forensics_snapshot_instance_volumes"}


def test_unknown_profile_falls_back_to_analyst():
    assert server.allowed_tools("wat") == server.allowed_tools("analyst")


# ---------------------------------------------------------------------------
# 4. Provider gating.
# ---------------------------------------------------------------------------


def test_aws_only_providers_hide_other_clouds():
    tools = server.allowed_tools("forensic", {"meta", "aws"})
    assert not any(n.startswith(("github_", "gcp_", "k8s_")) for n in tools)
    assert "aws_hunt_cloudtrail" in tools
    assert "dredge_capabilities" in tools


def test_full_providers_expose_all_clouds():
    tools = server.allowed_tools("analyst", {"meta", "aws", "k8s", "github", "gcp"})
    assert "github_hunt_audit_log" in tools
    assert "gcp_hunt_logs" in tools
    assert "k8s_hunt_events" in tools


def test_default_process_registers_only_analyst_aws_meta():
    # The test process sets no provider env, default profile -> analyst/AWS.
    registered = {t.name for t in server.mcp._tool_manager.list_tools()}
    expected = server.allowed_tools("analyst", {"meta", "aws"})
    assert registered == expected
    # No snapshot / other-cloud tools discoverable by default.
    assert "aws_forensics_snapshot_volume" not in registered
    assert not any(n.startswith(("github_", "gcp_", "k8s_")) for n in registered)


# ---------------------------------------------------------------------------
# 5. Local-filesystem sandbox.
# ---------------------------------------------------------------------------


def test_safe_path_confines_to_workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    ok = server._safe_path("logs/ct.json")
    assert Path(ok).resolve() == (tmp_path / "logs" / "ct.json").resolve()


@pytest.mark.parametrize("bad", ["../escape", "../../etc/passwd", "/etc/passwd", "logs/../../x"])
def test_safe_path_rejects_escape(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    with pytest.raises(ValueError, match="escapes the MCP workdir"):
        server._safe_path(bad)


def test_safe_path_rejects_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    with pytest.raises(ValueError, match="path is required"):
        server._safe_path("")


# ---------------------------------------------------------------------------
# 6. Input validation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["999.1.1.1", "not-an-ip", "10.0.0.0/99", "abc/24"])
def test_validate_ips_rejects_garbage(bad):
    with pytest.raises(ValueError, match="valid IP"):
        server._validate_ips([bad], name="ips")


@pytest.mark.parametrize("good", ["10.0.0.1", "192.168.0.0/16", "2001:db8::1", "::/0"])
def test_validate_ips_accepts_valid(good):
    assert server._validate_ips([good], name="ips") == [good]


@pytest.mark.parametrize("bad", ["12345", "12345678901a", "1234567890123", ""])
def test_account_id_validation(bad):
    with pytest.raises(ValueError, match="12-digit"):
        server._require_account_id(bad)


def test_parse_time_accepts_date_and_iso():
    assert server._parse_time("2026-08-01", name="t").year == 2026
    dt = server._parse_time("2026-08-01T12:30:00Z", name="t")
    assert dt.hour == 12 and dt.minute == 30
    assert server._parse_time(None, name="t") is None


def test_parse_time_rejects_garbage():
    with pytest.raises(ValueError, match="ISO-8601"):
        server._parse_time("last tuesday", name="t")


# ---------------------------------------------------------------------------
# 7. Guide/how-to tool: closed topic whitelist (no path traversal).
# ---------------------------------------------------------------------------


def test_guide_unknown_topic_lists_available():
    out = server.dredge_guide("../../etc/passwd")
    assert "available_topics" in out
    assert "overview" in out["available_topics"]


def test_guide_topics_map_only_into_docs():
    # Every whitelisted target is a fixed relative path with no traversal.
    for target in server._GUIDE_TOPICS.values():
        assert ".." not in target
        assert not target.startswith("/")


def test_capabilities_reports_envelope():
    caps = server.dredge_capabilities()
    assert caps["profile"] in server._PROFILE_CAPS
    assert "aws" in caps["enabled_providers"]
    assert isinstance(caps["registered_tools"], list)
    assert caps["dry_run"] is True  # analyst default
