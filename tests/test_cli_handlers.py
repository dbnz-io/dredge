"""Tests for dredge/cli.py's subcommand dispatch.

tests/test_cli_parsing.py only builds the parser and checks the resulting
Namespace -- it never calls args.func(args), so none of the ~53 handle_*
functions were previously exercised at all (56% coverage on cli.py before
this file). Every handler shares the same shape: parse argv -> build a
Dredge instance -> call exactly one dredge.<namespace>.<method>(...) ->
print_result(...). That shape is captured once as a parametrized table
driving a single shared test, rather than ~53 hand-written near-duplicates.
The two multi-branch time-range handlers (aws-hunt-cloudtrail,
github-hunt-audit) have their own dedicated classes below the table.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dredge import cli as dredge_cli
from dredge.aws_ir.models import OperationResult

GITHUB_ORG_ARGS = ["--github-org", "acme"]


def _get_nested(obj, path: str):
    target = obj
    for part in path.split("."):
        target = getattr(target, part)
    return target


def _run_handler(monkeypatch, capsys, argv, attr_path):
    """Patch dredge.cli.Dredge, parse argv, run its handler, return (mocked target, stdout)."""
    mock_dredge_class = MagicMock()
    mock_instance = mock_dredge_class.return_value
    monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)

    target = _get_nested(mock_instance, attr_path)
    target.return_value = OperationResult(operation="op", target="t", success=True, details={"ok": True})

    parser = dredge_cli.build_parser()
    args = parser.parse_args(argv)
    args.func(args)

    return target, capsys.readouterr().out


# ---------------------------------------------------------------------------
# The generic table: (id, argv, attr_path, expected_args, expected_kwargs)
# ---------------------------------------------------------------------------

CLI_HANDLER_CASES = [
    # --- AWS response ---
    (
        "aws-disable-access-key",
        ["aws-disable-access-key", "--user", "alice", "--access-key-id", "AKIA1"],
        "aws_ir.response.disable_access_key",
        (),
        {"user_name": "alice", "access_key_id": "AKIA1"},
    ),
    (
        "aws-delete-access-key",
        ["aws-delete-access-key", "--user", "alice", "--access-key-id", "AKIA1"],
        "aws_ir.response.delete_access_key",
        (),
        {"user_name": "alice", "access_key_id": "AKIA1"},
    ),
    (
        "aws-disable-user",
        ["aws-disable-user", "--user", "bob"],
        "aws_ir.response.disable_user",
        ("bob",),
        {},
    ),
    (
        "aws-delete-user",
        ["aws-delete-user", "--user", "carol"],
        "aws_ir.response.delete_user",
        ("carol",),
        {},
    ),
    (
        "aws-disable-role",
        ["aws-disable-role", "--role", "role-x"],
        "aws_ir.response.disable_role",
        ("role-x",),
        {},
    ),
    (
        "aws-block-s3-account",
        ["aws-block-s3-account", "--account-id", "123456789012"],
        "aws_ir.response.block_s3_public_access",
        (),
        {"account_id": "123456789012"},
    ),
    (
        "aws-block-s3-bucket",
        ["aws-block-s3-bucket", "--bucket", "my-bucket"],
        "aws_ir.response.block_s3_bucket_public_access",
        (),
        {"bucket_name": "my-bucket"},
    ),
    (
        "aws-block-s3-object",
        ["aws-block-s3-object", "--bucket", "my-bucket", "--key", "obj.txt"],
        "aws_ir.response.block_s3_object_public_access",
        (),
        {"bucket_name": "my-bucket", "key": "obj.txt"},
    ),
    (
        "aws-isolate-ec2",
        ["aws-isolate-ec2", "i-123", "i-456"],
        "aws_ir.response.isolate_ec2_instances",
        (),
        {"instance_ids": ["i-123", "i-456"], "vpc_id": None},
    ),
    (
        "aws-delete-mfa-devices",
        ["aws-delete-mfa-devices", "--user", "bob"],
        "aws_ir.response.delete_mfa_devices",
        ("bob",),
        {},
    ),
    (
        "aws-revoke-active-sessions",
        ["aws-revoke-active-sessions", "--user", "bob"],
        "aws_ir.response.revoke_active_sessions",
        ("bob",),
        {},
    ),
    (
        "aws-stop-ec2",
        ["aws-stop-ec2", "i-123"],
        "aws_ir.response.stop_ec2_instances",
        (["i-123"],),
        {},
    ),
    (
        "aws-terminate-ec2",
        ["aws-terminate-ec2", "i-123"],
        "aws_ir.response.terminate_ec2_instances",
        (["i-123"],),
        {"snapshot_first": True},
    ),
    (
        "aws-terminate-ec2-no-snapshot",
        ["aws-terminate-ec2", "i-123", "--no-snapshot"],
        "aws_ir.response.terminate_ec2_instances",
        (["i-123"],),
        {"snapshot_first": False},
    ),
    (
        "aws-block-nacl-cidrs",
        ["aws-block-nacl-cidrs", "--vpc-id", "vpc-1", "--cidr", "1.2.3.4/32"],
        "aws_ir.response.block_nacl_cidrs",
        (),
        {"vpc_id": "vpc-1", "cidrs": ["1.2.3.4/32"], "rule_number_start": 1},
    ),
    (
        "aws-disable-lambda",
        ["aws-disable-lambda", "--function-name", "fn-1"],
        "aws_ir.response.disable_lambda_function",
        ("fn-1",),
        {},
    ),
    (
        "aws-disable-kms-key",
        ["aws-disable-kms-key", "--key-id", "key-1"],
        "aws_ir.response.disable_kms_key",
        ("key-1",),
        {},
    ),
    (
        "aws-schedule-kms-deletion",
        ["aws-schedule-kms-deletion", "--key-id", "key-1"],
        "aws_ir.response.schedule_kms_key_deletion",
        ("key-1",),
        {"pending_window_days": 7},
    ),
    (
        "aws-tag-resources",
        ["aws-tag-resources", "--arn", "arn:aws:s3:::bucket", "--tag", "Key1=Value1"],
        "aws_ir.response.tag_resources",
        (),
        {"resource_arns": ["arn:aws:s3:::bucket"], "tags": {"Key1": "Value1"}},
    ),
    (
        "aws-isolate-rds",
        ["aws-isolate-rds", "db-1"],
        "aws_ir.response.isolate_rds_instance",
        ("db-1",),
        {},
    ),
    (
        "aws-stop-ecs-service",
        ["aws-stop-ecs-service", "cluster-1", "service-1"],
        "aws_ir.response.stop_ecs_service",
        ("cluster-1", "service-1"),
        {},
    ),
    (
        "aws-stop-ecs-task",
        ["aws-stop-ecs-task", "cluster-1", "task-1"],
        "aws_ir.response.stop_ecs_task",
        ("cluster-1", "task-1"),
        {},
    ),
    (
        "aws-disable-secret",
        ["aws-disable-secret", "secret-1"],
        "aws_ir.response.disable_secrets_manager_secret",
        ("secret-1",),
        {"recovery_window_days": 7},
    ),
    (
        "aws-disable-eventbridge-rule",
        ["aws-disable-eventbridge-rule", "rule-1"],
        "aws_ir.response.disable_eventbridge_rule",
        ("rule-1",),
        {"event_bus_name": "default"},
    ),
    (
        "aws-terminate-ssm-sessions",
        ["aws-terminate-ssm-sessions", "i-123"],
        "aws_ir.response.terminate_ssm_sessions",
        ("i-123",),
        {},
    ),
    (
        "aws-detach-iam-policy-user",
        ["aws-detach-iam-policy", "arn:aws:iam::aws:policy/X", "--user-name", "bob"],
        "aws_ir.response.detach_iam_policy",
        ("arn:aws:iam::aws:policy/X",),
        {"user_name": "bob", "role_name": None},
    ),
    (
        "aws-detach-iam-policy-role",
        ["aws-detach-iam-policy", "arn:aws:iam::aws:policy/X", "--role-name", "role-x"],
        "aws_ir.response.detach_iam_policy",
        ("arn:aws:iam::aws:policy/X",),
        {"user_name": None, "role_name": "role-x"},
    ),
    (
        "aws-quarantine-s3-bucket",
        ["aws-quarantine-s3-bucket", "my-bucket"],
        "aws_ir.response.quarantine_s3_bucket",
        ("my-bucket",),
        {"account_id": None},
    ),
    # --- AWS hunt/forensics ---
    (
        "aws-hunt-security-hub",
        ["aws-hunt-security-hub"],
        "aws_ir.hunt.hunt_security_hub_findings",
        (),
        {
            "severity_labels": None,
            "workflow_status": None,
            "product_name": None,
            "start_time": None,
            "end_time": None,
            "max_findings": 100,
        },
    ),
    (
        "aws-hunt-access-analyzer",
        ["aws-hunt-access-analyzer", "arn:aws:access-analyzer:us-east-1:1:analyzer/a"],
        "aws_ir.hunt.hunt_access_analyzer_findings",
        ("arn:aws:access-analyzer:us-east-1:1:analyzer/a",),
        {"status": None, "resource_type": None, "max_findings": 100},
    ),
    (
        "aws-hunt-config-history",
        ["aws-hunt-config-history", "AWS::EC2::Instance", "i-123"],
        "aws_ir.hunt.hunt_config_resource_history",
        ("AWS::EC2::Instance", "i-123"),
        {"start_time": None, "end_time": None, "max_items": 100},
    ),
    (
        "aws-iam-credential-report",
        ["aws-iam-credential-report"],
        "aws_ir.hunt.get_iam_credential_report",
        (),
        {},
    ),
    (
        "aws-hunt-guardduty",
        ["aws-hunt-guardduty", "--detector-id", "d-1"],
        "aws_ir.hunt.list_guardduty_findings",
        (),
        {
            "detector_id": "d-1",
            "severity_min": 0.0,
            "max_findings": 100,
            "finding_types": None,
            "start_time": None,
            "end_time": None,
        },
    ),
    (
        "aws-enable-vpc-flow-logs",
        ["aws-enable-vpc-flow-logs", "vpc-1"],
        "aws_ir.forensics.enable_vpc_flow_logs",
        ("vpc-1",),
        {
            "log_group_name": "/aws/vpc/flowlogs",
            "deliver_logs_permission_arn": None,
            "log_destination_type": "cloud-watch-logs",
            "log_destination": None,
            "traffic_type": "ALL",
        },
    ),
    (
        "aws-ssm-session-history",
        ["aws-ssm-session-history"],
        "aws_ir.forensics.capture_ssm_session_history",
        (),
        {"instance_id": None, "owner": None, "max_sessions": 100},
    ),
    (
        "aws-cloudtrail-status",
        ["aws-cloudtrail-status"],
        "aws_ir.forensics.get_cloudtrail_status",
        (),
        {"include_shadow_trails": False},
    ),
    (
        "aws-hunt-cloudwatch-logs",
        ["aws-hunt-cloudwatch-logs", "--log-group", "lg-1", "--query", "fields @timestamp"],
        "aws_ir.hunt.hunt_cloudwatch_logs",
        (),
        {
            "log_group": "lg-1",
            "query": "fields @timestamp",
            "start_time": None,
            "end_time": None,
            "max_results": 1000,
            "poll_interval": 1.0,
            "max_wait_seconds": 60.0,
        },
    ),
    # --- GitHub response (all require --github-org) ---
    (
        "github-block-org-member",
        [*GITHUB_ORG_ARGS, "github-block-org-member", "--username", "alice"],
        "github_ir.response.block_org_member",
        ("alice",),
        {},
    ),
    (
        "github-remove-org-member",
        [*GITHUB_ORG_ARGS, "github-remove-org-member", "--username", "alice"],
        "github_ir.response.remove_org_member",
        ("alice",),
        {},
    ),
    (
        "github-remove-repo-collaborator",
        [*GITHUB_ORG_ARGS, "github-remove-repo-collaborator", "--repo", "r1", "--username", "alice"],
        "github_ir.response.remove_repo_collaborator",
        ("r1", "alice"),
        {},
    ),
    (
        "github-revoke-deploy-key",
        [*GITHUB_ORG_ARGS, "github-revoke-deploy-key", "--repo", "r1", "--key-id", "42"],
        "github_ir.response.revoke_deploy_key",
        ("r1", 42),
        {},
    ),
    (
        "github-delete-org-webhook",
        [*GITHUB_ORG_ARGS, "github-delete-org-webhook", "--hook-id", "7"],
        "github_ir.response.delete_org_webhook",
        (7,),
        {},
    ),
    (
        "github-delete-repo-webhook",
        [*GITHUB_ORG_ARGS, "github-delete-repo-webhook", "--repo", "r1", "--hook-id", "7"],
        "github_ir.response.delete_repo_webhook",
        ("r1", 7),
        {},
    ),
    (
        "github-archive-repository",
        [*GITHUB_ORG_ARGS, "github-archive-repository", "--repo", "r1"],
        "github_ir.response.archive_repository",
        ("r1",),
        {},
    ),
    # --- GitHub hunt ---
    (
        "github-hunt-secret-scanning",
        [*GITHUB_ORG_ARGS, "github-hunt-secret-scanning"],
        "github_ir.hunt.hunt_secret_scanning_alerts",
        (None,),
        {"state": "open", "max_alerts": 100},
    ),
    (
        "github-hunt-code-scanning",
        [*GITHUB_ORG_ARGS, "github-hunt-code-scanning", "--repo", "r1"],
        "github_ir.hunt.hunt_code_scanning_alerts",
        ("r1",),
        {"state": "open", "max_alerts": 100},
    ),
    (
        "github-list-org-members",
        [*GITHUB_ORG_ARGS, "github-list-org-members"],
        "github_ir.hunt.list_org_members",
        (),
        {"role": None, "max_members": 500},
    ),
    (
        "github-list-outside-collaborators",
        [*GITHUB_ORG_ARGS, "github-list-outside-collaborators"],
        "github_ir.hunt.list_outside_collaborators",
        (),
        {"max_items": 200},
    ),
    (
        "github-list-deploy-keys",
        [*GITHUB_ORG_ARGS, "github-list-deploy-keys", "--repo", "r1"],
        "github_ir.hunt.list_deploy_keys",
        ("r1",),
        {"max_keys": 100},
    ),
    # --- GitHub forensics ---
    (
        "github-forensics-org-settings",
        [*GITHUB_ORG_ARGS, "github-forensics-org-settings"],
        "github_ir.forensics.get_org_settings",
        (),
        {},
    ),
    (
        "github-forensics-repo-metadata",
        [*GITHUB_ORG_ARGS, "github-forensics-repo-metadata", "--repo", "r1"],
        "github_ir.forensics.get_repo_metadata",
        ("r1",),
        {},
    ),
    (
        "github-forensics-repo-collaborators",
        [*GITHUB_ORG_ARGS, "github-forensics-repo-collaborators", "--repo", "r1"],
        "github_ir.forensics.list_repo_collaborators",
        ("r1",),
        {"max_items": 200},
    ),
    (
        "github-forensics-branch-protection",
        [*GITHUB_ORG_ARGS, "github-forensics-branch-protection", "--repo", "r1", "--branch", "main"],
        "github_ir.forensics.get_branch_protection",
        ("r1", "main"),
        {},
    ),
    (
        "github-forensics-org-webhooks",
        [*GITHUB_ORG_ARGS, "github-forensics-org-webhooks"],
        "github_ir.forensics.list_org_webhooks",
        (),
        {},
    ),
    (
        "github-forensics-repo-webhooks",
        [*GITHUB_ORG_ARGS, "github-forensics-repo-webhooks", "--repo", "r1"],
        "github_ir.forensics.list_repo_webhooks",
        ("r1",),
        {},
    ),
]


@pytest.mark.parametrize(
    "argv,attr_path,expected_args,expected_kwargs",
    [(c[1], c[2], c[3], c[4]) for c in CLI_HANDLER_CASES],
    ids=[c[0] for c in CLI_HANDLER_CASES],
)
def test_handler_dispatches_to_dredge(monkeypatch, capsys, argv, attr_path, expected_args, expected_kwargs):
    target, out = _run_handler(monkeypatch, capsys, argv, attr_path)
    target.assert_called_once_with(*expected_args, **expected_kwargs)
    assert '"success": true' in out


# ---------------------------------------------------------------------------
# aws-hunt-cloudtrail: 4 mutually exclusive time-range branches
# ---------------------------------------------------------------------------


class TestAwsHuntCloudtrailTimeRanges:
    def test_explicit_start_end(self, monkeypatch, capsys):
        argv = [
            "aws-hunt-cloudtrail",
            "--user",
            "alice",
            "--start-time",
            "2026-01-01T00:00:00Z",
            "--end-time",
            "2026-01-02T00:00:00Z",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"].isoformat() == "2026-01-01T00:00:00+00:00"
        assert kwargs["end_time"].isoformat() == "2026-01-02T00:00:00+00:00"
        assert kwargs["user_name"] == "alice"

    def test_today(self, monkeypatch, capsys):
        argv = ["aws-hunt-cloudtrail", "--today"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"].hour == 0
        assert kwargs["start_time"].minute == 0
        assert kwargs["end_time"] is not None

    def test_week_ago(self, monkeypatch, capsys):
        argv = ["aws-hunt-cloudtrail", "--week-ago", "2"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None
        assert kwargs["end_time"] is not None
        assert kwargs["start_time"] < kwargs["end_time"]

    def test_month_ago(self, monkeypatch, capsys):
        argv = ["aws-hunt-cloudtrail", "--month-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None
        assert kwargs["end_time"] is not None

    def test_no_time_args_both_none(self, monkeypatch, capsys):
        argv = ["aws-hunt-cloudtrail"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is None
        assert kwargs["end_time"] is None

    def test_output_csv_selected(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.lookup_events.return_value = OperationResult(
            operation="op", target="t", success=True, details={"events": [{"a": 1}]}
        )
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws-hunt-cloudtrail", "--output", "csv"])
        args.func(args)
        out = capsys.readouterr().out
        assert "a" in out.splitlines()[0]


# ---------------------------------------------------------------------------
# github-hunt-audit: same 4 time-range branches + 2 SystemExit guards
# ---------------------------------------------------------------------------


class TestGithubHuntAuditTimeRanges:
    def test_explicit_start_end(self, monkeypatch, capsys):
        argv = [
            *GITHUB_ORG_ARGS,
            "github-hunt-audit",
            "--start-time",
            "2026-01-01T00:00:00Z",
            "--end-time",
            "2026-01-02T00:00:00Z",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"].isoformat() == "2026-01-01T00:00:00+00:00"
        assert kwargs["end_time"].isoformat() == "2026-01-02T00:00:00+00:00"

    def test_today(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github-hunt-audit", "--today"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"].hour == 0

    def test_week_ago(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github-hunt-audit", "--week-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] < kwargs["end_time"]

    def test_month_ago(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github-hunt-audit", "--month-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None

    def test_no_time_args_both_none(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github-hunt-audit"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is None
        assert kwargs["end_time"] is None

    def test_missing_github_org_raises_system_exit(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["github-hunt-audit"])
        with pytest.raises(SystemExit):
            args.func(args)

    def test_github_ir_none_raises_system_exit(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        mock_instance.github_ir = None
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args([*GITHUB_ORG_ARGS, "github-hunt-audit"])
        with pytest.raises(SystemExit):
            args.func(args)


# ---------------------------------------------------------------------------
# _github_dredge: the shared guard every handle_github_* (non-hunt-audit)
# handler goes through
# ---------------------------------------------------------------------------


class TestGithubDredgeGuard:
    def test_missing_github_org_raises_system_exit(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        # No --github-org / --github-enterprise anywhere in argv.
        args = parser.parse_args(["github-archive-repository", "--repo", "r1"])
        with pytest.raises(SystemExit):
            args.func(args)


# ---------------------------------------------------------------------------
# main() -- the real entrypoint, not just args.func(args) called directly
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_parses_argv_and_dispatches(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.response.disable_user.return_value = OperationResult(
            operation="disable_user", target="user=bob", success=True, details={}
        )
        monkeypatch.setattr(
            "sys.argv", ["dredge-cli", "aws-disable-user", "--user", "bob"]
        )

        dredge_cli.main()

        mock_instance.aws_ir.response.disable_user.assert_called_once_with("bob")
        assert '"success": true' in capsys.readouterr().out
