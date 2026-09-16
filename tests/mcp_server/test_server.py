"""
Behavioral tests for the Dredge MCP server: each tool forwards to the right
Dredge namespace method with correctly-coerced arguments (time parsing, IP
validation, workdir path confinement) and serializes the OperationResult.

The underlying Dredge instance is replaced with a MagicMock via `server._d`, so
no cloud credentials or network are needed.
"""

from __future__ import annotations

import datetime as _dt
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")

import server  # noqa: E402
from dredge.aws_ir.models import OperationResult  # noqa: E402


@pytest.fixture
def fake_dredge(monkeypatch):
    """A MagicMock Dredge whose namespaces are mocks; each method returns a real
    OperationResult so serialization is exercised."""
    d = MagicMock()

    def _result(**details):
        return OperationResult(
            operation="op", target="t", success=True, details=details, errors=[]
        )

    # default: every namespace method returns a successful OperationResult
    for ns in (d.aws_ir.hunt, d.aws_ir.forensics, d.aws_ir.review):
        for attr in dir(ns):
            pass
    d._result_factory = _result
    monkeypatch.setattr(server, "_d", lambda: d)
    return d


def _ok():
    return OperationResult(operation="op", target="t", success=True, details={"x": 1}, errors=[])


# ---------------------------------------------------------------------------
# Argument forwarding + coercion
# ---------------------------------------------------------------------------


def test_cloudtrail_forwards_parsed_times_and_ip(fake_dredge):
    fake_dredge.aws_ir.hunt.lookup_events.return_value = _ok()
    out = server.aws_hunt_cloudtrail(
        user_name="alice", source_ip="10.0.0.1",
        start_time="2026-08-01", end_time="2026-08-02T10:00:00Z", max_events=10,
    )
    kwargs = fake_dredge.aws_ir.hunt.lookup_events.call_args.kwargs
    assert kwargs["user_name"] == "alice"
    assert kwargs["source_ip"] == "10.0.0.1"
    assert isinstance(kwargs["start_time"], _dt.datetime)
    assert kwargs["end_time"].hour == 10
    assert out["success"] is True and out["details"] == {"x": 1}


def test_cloudtrail_rejects_bad_source_ip_before_calling(fake_dredge):
    with pytest.raises(ValueError, match="valid IP"):
        server.aws_hunt_cloudtrail(source_ip="not-an-ip")
    fake_dredge.aws_ir.hunt.lookup_events.assert_not_called()


def test_multi_region_defaults_to_all(fake_dredge):
    fake_dredge.aws_ir.hunt.lookup_events_multi_region.return_value = _ok()
    server.aws_hunt_cloudtrail_multi_region(regions=None, user_name="bob")
    assert fake_dredge.aws_ir.hunt.lookup_events_multi_region.call_args.kwargs["regions"] == "all"
    server.aws_hunt_cloudtrail_multi_region(regions=["us-east-1", "eu-west-1"])
    assert fake_dredge.aws_ir.hunt.lookup_events_multi_region.call_args.kwargs["regions"] == [
        "us-east-1", "eu-west-1",
    ]


def test_multi_user_requires_users(fake_dredge):
    with pytest.raises(ValueError, match="non-empty"):
        server.aws_hunt_cloudtrail_multi_user(users=[])


def test_user_activity_by_ip_validates_allowlist(fake_dredge):
    with pytest.raises(ValueError, match="valid IP"):
        server.aws_hunt_user_activity_by_ip("alice", allowed_ips=["10.0.0.0/8", "bogus"])
    fake_dredge.aws_ir.hunt.hunt_user_activity_by_ip.assert_not_called()


def test_public_snapshots_validates_owner_account(fake_dredge):
    with pytest.raises(ValueError, match="12-digit"):
        server.aws_hunt_public_snapshots(owner_id="123")


def test_security_groups_by_ip_forwards(fake_dredge):
    fake_dredge.aws_ir.hunt.hunt_security_groups_by_ip.return_value = _ok()
    server.aws_hunt_security_groups_by_ip(ips=["1.2.3.4"], direction="ingress")
    args, kwargs = fake_dredge.aws_ir.hunt.hunt_security_groups_by_ip.call_args
    assert args[0] == ["1.2.3.4"] and kwargs["direction"] == "ingress"


# ---------------------------------------------------------------------------
# Local-file tools confine paths to the workdir
# ---------------------------------------------------------------------------


def test_download_s3_logs_confines_destination(fake_dredge, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    fake_dredge.aws_ir.forensics.download_s3_logs.return_value = _ok()
    server.aws_forensics_download_s3_logs(bucket="b", destination="ct", days_ago=2)
    dest = fake_dredge.aws_ir.forensics.download_s3_logs.call_args.kwargs["destination"]
    assert dest.startswith(str(tmp_path.resolve()))


def test_download_s3_logs_rejects_escape(fake_dredge, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    with pytest.raises(ValueError, match="escapes the MCP workdir"):
        server.aws_forensics_download_s3_logs(bucket="b", destination="../../evil")
    fake_dredge.aws_ir.forensics.download_s3_logs.assert_not_called()


def test_local_cloudtrail_confines_path(fake_dredge, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    fake_dredge.aws_ir.hunt.query_local_cloudtrail_logs.return_value = _ok()
    server.aws_hunt_local_cloudtrail(path="logs", user_name="alice")
    used = fake_dredge.aws_ir.hunt.query_local_cloudtrail_logs.call_args.args[0]
    assert used.startswith(str(tmp_path.resolve()))


# ---------------------------------------------------------------------------
# Review + export
# ---------------------------------------------------------------------------


def test_review_deep_selects_both_tiers(fake_dredge):
    fake_dredge.aws_ir.review.review.return_value = _ok()
    server.aws_review(deep=True)
    assert fake_dredge.aws_ir.review.review.call_args.kwargs["tiers"] == (1, 2)
    server.aws_review(deep=False)
    assert fake_dredge.aws_ir.review.review.call_args.kwargs["tiers"] == (1,)


def test_review_export_writes_into_workdir(fake_dredge, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_WORKDIR", tmp_path.resolve())
    result = _ok()
    fake_dredge.aws_ir.review.review.return_value = result
    out = server.aws_review(export="csv", output_name="posture")
    to_csv = fake_dredge.aws_ir.review.to_csv
    to_csv.assert_called_once()
    passed_result, passed_path = to_csv.call_args.args
    assert passed_result is result
    assert passed_path.startswith(str(tmp_path.resolve())) and passed_path.endswith("posture.csv")
    assert out["exported_to"].endswith("posture.csv")


# ---------------------------------------------------------------------------
# Provider-not-configured surfaces a clean tool error (not a crash)
# ---------------------------------------------------------------------------


def test_k8s_tool_errors_when_not_configured(monkeypatch):
    d = MagicMock()
    d.k8s_ir = None
    monkeypatch.setattr(server, "_d", lambda: d)
    with pytest.raises(server.DredgeMCPConfigError, match="Kubernetes is not configured"):
        server.k8s_hunt_events()


def test_github_tool_errors_when_not_configured(monkeypatch):
    d = MagicMock()
    d.github_ir = None
    monkeypatch.setattr(server, "_d", lambda: d)
    with pytest.raises(server.DredgeMCPConfigError, match="GitHub is not configured"):
        server.github_hunt_audit_log(actor="x")


def test_gcp_tool_errors_when_not_configured(monkeypatch):
    d = MagicMock()
    d.gcp_ir = None
    monkeypatch.setattr(server, "_d", lambda: d)
    with pytest.raises(server.DredgeMCPConfigError, match="GCP is not configured"):
        server.gcp_hunt_logs(principal_email="x@y.z")


# ---------------------------------------------------------------------------
# Serialization surfaces success=False results as data (not exceptions)
# ---------------------------------------------------------------------------


def test_failed_operation_returned_as_data(fake_dredge):
    failed = OperationResult(operation="op", target="t", success=False, details={}, errors=["boom"])
    fake_dredge.aws_ir.hunt.get_iam_credential_report.return_value = failed
    out = server.aws_hunt_iam_credential_report()
    assert out["success"] is False
    assert out["errors"] == ["boom"]
