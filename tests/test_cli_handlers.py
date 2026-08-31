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
    """Patch dredge.cli.Dredge, parse argv, run its handler, return (mocked target, stdout).

    argv is the nested form: dredge <provider> <bucket> <command> ... (e.g.
    ["aws", "hunt", "cloudtrail", "--user", "alice"])."""
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
        ["aws", "response", "disable-access-key", "--user", "alice", "--access-key-id", "AKIA1"],
        "aws_ir.response.disable_access_key",
        (),
        {"user_name": "alice", "access_key_id": "AKIA1"},
    ),
    (
        "aws-delete-access-key",
        ["aws", "response", "delete-access-key", "--user", "alice", "--access-key-id", "AKIA1"],
        "aws_ir.response.delete_access_key",
        (),
        {"user_name": "alice", "access_key_id": "AKIA1"},
    ),
    (
        "aws-disable-user",
        ["aws", "response", "disable-user", "--user", "bob"],
        "aws_ir.response.disable_user",
        ("bob",),
        {},
    ),
    (
        "aws-delete-user",
        ["aws", "response", "delete-user", "--user", "carol"],
        "aws_ir.response.delete_user",
        ("carol",),
        {},
    ),
    (
        "aws-disable-role",
        ["aws", "response", "disable-role", "--role", "role-x"],
        "aws_ir.response.disable_role",
        ("role-x",),
        {},
    ),
    (
        "aws-block-s3-account",
        ["aws", "response", "block-s3-account", "--account-id", "123456789012"],
        "aws_ir.response.block_s3_public_access",
        (),
        {"account_id": "123456789012"},
    ),
    (
        "aws-block-s3-bucket",
        ["aws", "response", "block-s3-bucket", "--bucket", "my-bucket"],
        "aws_ir.response.block_s3_bucket_public_access",
        (),
        {"bucket_name": "my-bucket"},
    ),
    (
        "aws-block-s3-object",
        ["aws", "response", "block-s3-object", "--bucket", "my-bucket", "--key", "obj.txt"],
        "aws_ir.response.block_s3_object_public_access",
        (),
        {"bucket_name": "my-bucket", "key": "obj.txt"},
    ),
    (
        "aws-isolate-ec2",
        ["aws", "response", "isolate-ec2", "i-123", "i-456"],
        "aws_ir.response.isolate_ec2_instances",
        (),
        {"instance_ids": ["i-123", "i-456"], "vpc_id": None},
    ),
    (
        "aws-delete-mfa-devices",
        ["aws", "response", "delete-mfa-devices", "--user", "bob"],
        "aws_ir.response.delete_mfa_devices",
        ("bob",),
        {},
    ),
    (
        "aws-revoke-active-sessions",
        ["aws", "response", "revoke-active-sessions", "--user", "bob"],
        "aws_ir.response.revoke_active_sessions",
        ("bob",),
        {},
    ),
    (
        "aws-stop-ec2",
        ["aws", "response", "stop-ec2", "i-123"],
        "aws_ir.response.stop_ec2_instances",
        (["i-123"],),
        {},
    ),
    (
        "aws-terminate-ec2",
        ["aws", "response", "terminate-ec2", "i-123"],
        "aws_ir.response.terminate_ec2_instances",
        (["i-123"],),
        {"snapshot_first": True},
    ),
    (
        "aws-terminate-ec2-no-snapshot",
        ["aws", "response", "terminate-ec2", "i-123", "--no-snapshot"],
        "aws_ir.response.terminate_ec2_instances",
        (["i-123"],),
        {"snapshot_first": False},
    ),
    (
        "aws-block-nacl-cidrs",
        ["aws", "response", "block-nacl-cidrs", "--vpc-id", "vpc-1", "--cidr", "1.2.3.4/32"],
        "aws_ir.response.block_nacl_cidrs",
        (),
        {"vpc_id": "vpc-1", "cidrs": ["1.2.3.4/32"], "rule_number_start": 1},
    ),
    (
        "aws-disable-lambda",
        ["aws", "response", "disable-lambda", "--function-name", "fn-1"],
        "aws_ir.response.disable_lambda_function",
        ("fn-1",),
        {},
    ),
    (
        "aws-disable-kms-key",
        ["aws", "response", "disable-kms-key", "--key-id", "key-1"],
        "aws_ir.response.disable_kms_key",
        ("key-1",),
        {},
    ),
    (
        "aws-schedule-kms-deletion",
        ["aws", "response", "schedule-kms-deletion", "--key-id", "key-1"],
        "aws_ir.response.schedule_kms_key_deletion",
        ("key-1",),
        {"pending_window_days": 7},
    ),
    (
        "aws-tag-resources",
        ["aws", "response", "tag-resources", "--arn", "arn:aws:s3:::bucket", "--tag", "Key1=Value1"],
        "aws_ir.response.tag_resources",
        (),
        {"resource_arns": ["arn:aws:s3:::bucket"], "tags": {"Key1": "Value1"}},
    ),
    (
        "aws-isolate-rds",
        ["aws", "response", "isolate-rds", "db-1"],
        "aws_ir.response.isolate_rds_instance",
        ("db-1",),
        {},
    ),
    (
        "aws-stop-ecs-service",
        ["aws", "response", "stop-ecs-service", "cluster-1", "service-1"],
        "aws_ir.response.stop_ecs_service",
        ("cluster-1", "service-1"),
        {},
    ),
    (
        "aws-stop-ecs-task",
        ["aws", "response", "stop-ecs-task", "cluster-1", "task-1"],
        "aws_ir.response.stop_ecs_task",
        ("cluster-1", "task-1"),
        {},
    ),
    (
        "aws-disable-secret",
        ["aws", "response", "disable-secret", "secret-1"],
        "aws_ir.response.disable_secrets_manager_secret",
        ("secret-1",),
        {"recovery_window_days": 7},
    ),
    (
        "aws-disable-eventbridge-rule",
        ["aws", "response", "disable-eventbridge-rule", "rule-1"],
        "aws_ir.response.disable_eventbridge_rule",
        ("rule-1",),
        {"event_bus_name": "default"},
    ),
    (
        "aws-terminate-ssm-sessions",
        ["aws", "response", "terminate-ssm-sessions", "i-123"],
        "aws_ir.response.terminate_ssm_sessions",
        ("i-123",),
        {},
    ),
    (
        "aws-detach-iam-policy-user",
        ["aws", "response", "detach-iam-policy", "arn:aws:iam::aws:policy/X", "--user-name", "bob"],
        "aws_ir.response.detach_iam_policy",
        ("arn:aws:iam::aws:policy/X",),
        {"user_name": "bob", "role_name": None},
    ),
    (
        "aws-detach-iam-policy-role",
        ["aws", "response", "detach-iam-policy", "arn:aws:iam::aws:policy/X", "--role-name", "role-x"],
        "aws_ir.response.detach_iam_policy",
        ("arn:aws:iam::aws:policy/X",),
        {"user_name": None, "role_name": "role-x"},
    ),
    (
        "aws-quarantine-s3-bucket",
        ["aws", "response", "quarantine-s3-bucket", "my-bucket"],
        "aws_ir.response.quarantine_s3_bucket",
        ("my-bucket",),
        {"account_id": None},
    ),
    # --- AWS hunt/forensics ---
    (
        "aws-hunt-security-hub",
        ["aws", "hunt", "security-hub"],
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
        ["aws", "hunt", "access-analyzer", "arn:aws:access-analyzer:us-east-1:1:analyzer/a"],
        "aws_ir.hunt.hunt_access_analyzer_findings",
        ("arn:aws:access-analyzer:us-east-1:1:analyzer/a",),
        {"status": None, "resource_type": None, "max_findings": 100},
    ),
    (
        "aws-hunt-config-history",
        ["aws", "hunt", "config-history", "AWS::EC2::Instance", "i-123"],
        "aws_ir.hunt.hunt_config_resource_history",
        ("AWS::EC2::Instance", "i-123"),
        {"start_time": None, "end_time": None, "max_items": 100},
    ),
    (
        "aws-iam-credential-report",
        ["aws", "response", "iam-credential-report"],
        "aws_ir.hunt.get_iam_credential_report",
        (),
        {},
    ),
    (
        "aws-hunt-guardduty",
        ["aws", "hunt", "guardduty", "--detector-id", "d-1"],
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
        ["aws", "response", "enable-vpc-flow-logs", "vpc-1"],
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
        ["aws", "response", "ssm-session-history"],
        "aws_ir.forensics.capture_ssm_session_history",
        (),
        {"instance_id": None, "owner": None, "max_sessions": 100},
    ),
    (
        "aws-cloudtrail-status",
        ["aws", "response", "cloudtrail-status"],
        "aws_ir.forensics.get_cloudtrail_status",
        (),
        {"include_shadow_trails": False},
    ),
    (
        "aws-download-s3-logs",
        ["aws", "forensics", "download-s3-logs", "--bucket", "b1", "--destination", "/tmp/out"],
        "aws_ir.forensics.download_s3_logs",
        ("b1",),
        {
            "prefix": None,
            "destination": "/tmp/out",
            "suffixes": (".json", ".json.gz"),
            "decompress_gzip": True,
            "max_objects": None,
            "start_time": None,
            "end_time": None,
            "days_ago": None,
            "max_workers": 8,
        },
    ),
    (
        "aws-query-cloudtrail-logs",
        ["aws", "hunt", "query-cloudtrail-logs", "--path", "/tmp/logs", "--source-ip", "1.2.3.4"],
        "aws_ir.hunt.query_local_cloudtrail_logs",
        ("/tmp/logs",),
        {
            "source_ip": "1.2.3.4",
            "user_name": None,
            "access_key_id": None,
            "event_name": None,
            "event_source": None,
            "aws_region": None,
            "account_id": None,
            "start_time": None,
            "end_time": None,
            "fields": None,
            "max_events": None,
        },
    ),
    (
        "aws-hunt-security-groups-by-ip",
        # --verbose so this goes through the generic JSON dispatch path this
        # table asserts on; the default (table) output has its own tests below.
        ["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4", "--verbose"],
        "aws_ir.hunt.hunt_security_groups_by_ip",
        (["1.2.3.4"],),
        {"direction": "both", "max_groups": 500},
    ),
    (
        "aws-hunt-exposed-secrets",
        ["aws", "hunt", "exposed-secrets"],
        "aws_ir.hunt.hunt_exposed_secrets",
        (),
        {"include": None, "keep_raw": False, "test_pairs": False, "max_ec2_instances": 500},
    ),
    (
        "aws-hunt-cloudwatch-logs",
        ["aws", "hunt", "cloudwatch-logs", "--log-group", "lg-1", "--query", "fields @timestamp"],
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
        [*GITHUB_ORG_ARGS, "github", "response", "block-org-member", "--username", "alice"],
        "github_ir.response.block_org_member",
        ("alice",),
        {},
    ),
    (
        "github-remove-org-member",
        [*GITHUB_ORG_ARGS, "github", "response", "remove-org-member", "--username", "alice"],
        "github_ir.response.remove_org_member",
        ("alice",),
        {},
    ),
    (
        "github-remove-repo-collaborator",
        [*GITHUB_ORG_ARGS, "github", "response", "remove-repo-collaborator", "--repo", "r1", "--username", "alice"],
        "github_ir.response.remove_repo_collaborator",
        ("r1", "alice"),
        {},
    ),
    (
        "github-revoke-deploy-key",
        [*GITHUB_ORG_ARGS, "github", "response", "revoke-deploy-key", "--repo", "r1", "--key-id", "42"],
        "github_ir.response.revoke_deploy_key",
        ("r1", 42),
        {},
    ),
    (
        "github-delete-org-webhook",
        [*GITHUB_ORG_ARGS, "github", "response", "delete-org-webhook", "--hook-id", "7"],
        "github_ir.response.delete_org_webhook",
        (7,),
        {},
    ),
    (
        "github-delete-repo-webhook",
        [*GITHUB_ORG_ARGS, "github", "response", "delete-repo-webhook", "--repo", "r1", "--hook-id", "7"],
        "github_ir.response.delete_repo_webhook",
        ("r1", 7),
        {},
    ),
    (
        "github-archive-repository",
        [*GITHUB_ORG_ARGS, "github", "response", "archive-repository", "--repo", "r1"],
        "github_ir.response.archive_repository",
        ("r1",),
        {},
    ),
    # --- GitHub hunt ---
    (
        "github-hunt-secret-scanning",
        [*GITHUB_ORG_ARGS, "github", "hunt", "secret-scanning"],
        "github_ir.hunt.hunt_secret_scanning_alerts",
        (None,),
        {"state": "open", "max_alerts": 100},
    ),
    (
        "github-hunt-code-scanning",
        [*GITHUB_ORG_ARGS, "github", "hunt", "code-scanning", "--repo", "r1"],
        "github_ir.hunt.hunt_code_scanning_alerts",
        ("r1",),
        {"state": "open", "max_alerts": 100},
    ),
    (
        "github-list-org-members",
        [*GITHUB_ORG_ARGS, "github", "hunt", "list-org-members"],
        "github_ir.hunt.list_org_members",
        (),
        {"role": None, "max_members": 500},
    ),
    (
        "github-list-outside-collaborators",
        [*GITHUB_ORG_ARGS, "github", "hunt", "list-outside-collaborators"],
        "github_ir.hunt.list_outside_collaborators",
        (),
        {"max_items": 200},
    ),
    (
        "github-list-deploy-keys",
        [*GITHUB_ORG_ARGS, "github", "hunt", "list-deploy-keys", "--repo", "r1"],
        "github_ir.hunt.list_deploy_keys",
        ("r1",),
        {"max_keys": 100},
    ),
    # --- GitHub forensics ---
    (
        "github-forensics-org-settings",
        [*GITHUB_ORG_ARGS, "github", "forensics", "org-settings"],
        "github_ir.forensics.get_org_settings",
        (),
        {},
    ),
    (
        "github-forensics-repo-metadata",
        [*GITHUB_ORG_ARGS, "github", "forensics", "repo-metadata", "--repo", "r1"],
        "github_ir.forensics.get_repo_metadata",
        ("r1",),
        {},
    ),
    (
        "github-forensics-repo-collaborators",
        [*GITHUB_ORG_ARGS, "github", "forensics", "repo-collaborators", "--repo", "r1"],
        "github_ir.forensics.list_repo_collaborators",
        ("r1",),
        {"max_items": 200},
    ),
    (
        "github-forensics-branch-protection",
        [*GITHUB_ORG_ARGS, "github", "forensics", "branch-protection", "--repo", "r1", "--branch", "main"],
        "github_ir.forensics.get_branch_protection",
        ("r1", "main"),
        {},
    ),
    (
        "github-forensics-org-webhooks",
        [*GITHUB_ORG_ARGS, "github", "forensics", "org-webhooks"],
        "github_ir.forensics.list_org_webhooks",
        (),
        {},
    ),
    (
        "github-forensics-repo-webhooks",
        [*GITHUB_ORG_ARGS, "github", "forensics", "repo-webhooks", "--repo", "r1"],
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
            "aws", "hunt", "cloudtrail",
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
        argv = ["aws", "hunt", "cloudtrail", "--today"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"].hour == 0
        assert kwargs["start_time"].minute == 0
        assert kwargs["end_time"] is not None

    def test_week_ago(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--week-ago", "2"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None
        assert kwargs["end_time"] is not None
        assert kwargs["start_time"] < kwargs["end_time"]

    def test_month_ago(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--month-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None
        assert kwargs["end_time"] is not None

    def test_no_time_args_both_none(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is None
        assert kwargs["end_time"] is None

    def test_max_events_zero_passed_through_for_unlimited(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--max-events", "0"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["max_events"] == 0

    def test_max_events_default_is_500(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        _, kwargs = target.call_args
        assert kwargs["max_events"] == 500

    def test_all_regions_dispatches_to_multi_region(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--access-key-id", "AKIA", "--all-regions"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events_multi_region")
        _, kwargs = target.call_args
        assert kwargs["regions"] == "all"
        assert kwargs["max_events_per_region"] == 500
        assert kwargs["max_workers"] == 12

    def test_explicit_regions_list_dispatches_to_multi_region(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--user", "x",
                "--regions", "us-east-1", "--regions", "eu-west-1", "--max-workers", "4"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events_multi_region")
        _, kwargs = target.call_args
        assert kwargs["regions"] == ["us-east-1", "eu-west-1"]
        assert kwargs["max_workers"] == 4

    def test_regions_comma_separated(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--user", "x", "--regions", "us-east-1,us-east-2"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events_multi_region")
        _, kwargs = target.call_args
        assert kwargs["regions"] == ["us-east-1", "us-east-2"]

    def test_regions_comma_and_repeated_flag_mix(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--user", "x",
                "--regions", "us-east-1, us-east-2", "--regions", "eu-west-1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events_multi_region")
        _, kwargs = target.call_args
        assert kwargs["regions"] == ["us-east-1", "us-east-2", "eu-west-1"]

    def test_regions_value_all_means_all(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--user", "x", "--regions", "all"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events_multi_region")
        _, kwargs = target.call_args
        assert kwargs["regions"] == "all"

    def test_no_region_flags_uses_single_region_lookup(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail", "--user", "x"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.lookup_events")
        target.assert_called_once()

    def test_output_csv_selected(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.lookup_events.return_value = OperationResult(
            operation="op", target="t", success=True, details={"events": [{"a": 1}]}
        )
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "cloudtrail", "--output", "csv"])
        args.func(args)
        out = capsys.readouterr().out
        assert "a" in out.splitlines()[0]


class TestReadListFile:
    def test_strips_blank_lines_and_comments(self, tmp_path):
        f = tmp_path / "list.txt"
        f.write_text("alice\n\n# a comment\nbob\n   \ncarol  \n")
        assert dredge_cli._read_list_file(str(f)) == ["alice", "bob", "carol"]


class TestAwsHuntCloudtrailMultiUserCli:
    def test_users_from_repeated_flag(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--user", "bob"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        args, kwargs = target.call_args
        assert args == (["alice", "bob"],)
        assert kwargs["mode"] == "per_user"

    def test_users_comma_separated(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice,bob,carol"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        args, kwargs = target.call_args
        assert args == (["alice", "bob", "carol"],)

    def test_users_from_file_combined_with_flag_and_deduped(self, monkeypatch, capsys, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("bob\nalice\n")
        argv = [
            "aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--users-file", str(f),
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        args, kwargs = target.call_args
        assert args == (["alice", "bob"],)

    def test_no_users_exits_with_error(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "cloudtrail-multi-user"])
        with pytest.raises(SystemExit) as exc_info:
            args.func(args)
        assert exc_info.value.code == 2
        assert "no users given" in capsys.readouterr().err

    def test_mode_batch_passed_through(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--mode", "batch"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["mode"] == "batch"

    def test_source_ip_without_event_name_forces_full_scan(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--source-ip", "1.2.3.4"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["allow_full_scan"] is True

    def test_source_ip_with_event_name_does_not_force_full_scan(self, monkeypatch, capsys):
        argv = [
            "aws", "hunt", "cloudtrail-multi-user", "--user", "alice",
            "--source-ip", "1.2.3.4", "--event-name", "ConsoleLogin",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["allow_full_scan"] is False

    def test_stop_on_error_and_output_path_passed_through(self, monkeypatch, capsys):
        argv = [
            "aws", "hunt", "cloudtrail-multi-user", "--user", "alice",
            "--stop-on-error", "--output-path", "/tmp/progress.jsonl",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["stop_on_error"] is True
        assert kwargs["output_path"] == "/tmp/progress.jsonl"

    def test_today_time_range(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--today"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["start_time"].hour == 0
        assert kwargs["end_time"] is not None

    def test_week_ago_time_range(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--week-ago", "2"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["start_time"] < kwargs["end_time"]

    def test_month_ago_time_range(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "cloudtrail-multi-user", "--user", "alice", "--month-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_cloudtrail_multi_user")
        _, kwargs = target.call_args
        assert kwargs["start_time"] < kwargs["end_time"]


class TestAwsHuntUserActivityByIpCli:
    def test_allowed_ips_from_repeated_flag(self, monkeypatch, capsys):
        argv = [
            "aws", "hunt", "user-activity-by-ip", "--user", "alice",
            "--allowed-ip", "10.0.0.0/8", "--allowed-ip", "1.2.3.4",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_user_activity_by_ip")
        args, kwargs = target.call_args
        assert args == ("alice", ["10.0.0.0/8", "1.2.3.4"])

    def test_allowed_ips_comma_separated(self, monkeypatch, capsys):
        argv = ["aws", "hunt", "user-activity-by-ip", "--user", "alice",
                "--allowed-ip", "10.0.0.0/8, 1.2.3.4"]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_user_activity_by_ip")
        args, kwargs = target.call_args
        assert args == ("alice", ["10.0.0.0/8", "1.2.3.4"])

    def test_allowed_ips_from_file(self, monkeypatch, capsys, tmp_path):
        f = tmp_path / "ips.txt"
        f.write_text("# office\n10.0.0.0/8\n")
        argv = [
            "aws", "hunt", "user-activity-by-ip", "--user", "alice", "--allowed-ips-file", str(f),
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_user_activity_by_ip")
        args, kwargs = target.call_args
        assert args == ("alice", ["10.0.0.0/8"])

    def test_no_allowed_ips_exits_with_error(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "user-activity-by-ip", "--user", "alice"])
        with pytest.raises(SystemExit) as exc_info:
            args.func(args)
        assert exc_info.value.code == 2
        assert "no allowed IPs given" in capsys.readouterr().err

    def test_max_events_and_event_name_passed_through(self, monkeypatch, capsys):
        argv = [
            "aws", "hunt", "user-activity-by-ip", "--user", "alice", "--allowed-ip", "10.0.0.0/8",
            "--max-events", "50", "--event-name", "ConsoleLogin",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.hunt.hunt_user_activity_by_ip")
        _, kwargs = target.call_args
        assert kwargs["max_events"] == 50
        assert kwargs["event_name"] == "ConsoleLogin"


class TestAwsReviewCli:
    def _run(self, monkeypatch, argv):
        from dredge.aws_ir.models import OperationResult
        mock_dredge_class = MagicMock()
        inst = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        inst.aws_ir.review.review.return_value = OperationResult(
            operation="review", target="acct", success=True,
            details={"findings": [], "summary": {}, "checks": {}, "meta": {}},
        )
        args = dredge_cli.build_parser().parse_args(argv)
        args.func(args)
        return inst.aws_ir.review.review

    def test_full_is_all_services_tier1(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "full"])
        _, kwargs = run.call_args
        assert kwargs["services"] == "all"
        assert kwargs["tiers"] == (1,)

    def test_full_deep_includes_tier2(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "full", "--deep"])
        _, kwargs = run.call_args
        assert kwargs["tiers"] == (1, 2)

    def test_service_target_runs_both_tiers(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "iam"])
        _, kwargs = run.call_args
        assert kwargs["services"] == ["iam"]
        assert kwargs["tiers"] == (1, 2)

    def test_ec2_ip_flag_flattened(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "ec2", "--ip", "1.2.3.4,10.0.0.0/8"])
        _, kwargs = run.call_args
        assert kwargs["ips"] == ["1.2.3.4", "10.0.0.0/8"]

    def test_recent_passes_incident_start(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "recent", "--incident-start", "2026-08-29T00:00:00Z"])
        _, kwargs = run.call_args
        assert kwargs["incident_start"].isoformat() == "2026-08-29T00:00:00+00:00"

    def test_all_regions_fans_out(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "full", "--all-regions"])
        _, kwargs = run.call_args
        assert kwargs["regions"] == "all"

    def test_regions_comma_separated(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "rds", "--regions", "us-east-1,eu-west-1"])
        _, kwargs = run.call_args
        assert kwargs["regions"] == ["us-east-1", "eu-west-1"]

    def test_ecs_service_command(self, monkeypatch, capsys):
        run = self._run(monkeypatch, ["aws", "review", "ecs"])
        _, kwargs = run.call_args
        assert kwargs["services"] == ["ecs"]
        assert kwargs["tiers"] == (1, 2)

    def test_writes_csv_and_html(self, monkeypatch, capsys, tmp_path):
        csv_p = tmp_path / "r.csv"
        html_p = tmp_path / "r.html"
        self._run(monkeypatch, ["aws", "review", "full", "--csv", str(csv_p), "--html", str(html_p)])
        assert csv_p.exists() and html_p.exists()
        assert csv_p.read_text().startswith("severity,service,")
        assert "<!doctype html>" in html_p.read_text()

    def test_no_files_still_prints_summary(self, monkeypatch, capsys):
        self._run(monkeypatch, ["aws", "review", "full"])
        assert '"success": true' in capsys.readouterr().out


class TestAwsDownloadS3LogsDateFilter:
    def test_days_ago_passed_through(self, monkeypatch, capsys):
        argv = [
            "aws", "forensics", "download-s3-logs", "--bucket", "b1", "--destination", "/tmp/out", "--days-ago", "2",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.forensics.download_s3_logs")
        _, kwargs = target.call_args
        assert kwargs["days_ago"] == 2
        assert kwargs["start_time"] is None

    def test_start_time_and_end_time_parsed(self, monkeypatch, capsys):
        argv = [
            "aws", "forensics", "download-s3-logs", "--bucket", "b1", "--destination", "/tmp/out",
            "--start-time", "2026-08-26T00:00:00Z", "--end-time", "2026-08-27T00:00:00Z",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.forensics.download_s3_logs")
        _, kwargs = target.call_args
        assert kwargs["start_time"].isoformat() == "2026-08-26T00:00:00+00:00"
        assert kwargs["end_time"].isoformat() == "2026-08-27T00:00:00+00:00"

    def test_max_workers_passed_through(self, monkeypatch, capsys):
        argv = [
            "aws", "forensics", "download-s3-logs", "--bucket", "b1", "--destination", "/tmp/out", "--max-workers", "16",
        ]
        target, out = _run_handler(monkeypatch, capsys, argv, "aws_ir.forensics.download_s3_logs")
        _, kwargs = target.call_args
        assert kwargs["max_workers"] == 16


class TestAwsQueryCloudtrailLogsFieldsFlag:
    def test_fields_flag_split_on_comma(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.query_local_cloudtrail_logs.return_value = OperationResult(
            operation="query_local_cloudtrail_logs", target="t", success=True, details={"events": []}
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args([
            "aws", "hunt", "query-cloudtrail-logs", "--path", "/tmp/logs",
            "--fields", "eventName,sourceIPAddress,userIdentity.arn",
        ])
        args.func(args)

        _, kwargs = mock_instance.aws_ir.hunt.query_local_cloudtrail_logs.call_args
        assert kwargs["fields"] == ["eventName", "sourceIPAddress", "userIdentity.arn"]

    def test_no_fields_flag_passes_none(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.query_local_cloudtrail_logs.return_value = OperationResult(
            operation="query_local_cloudtrail_logs", target="t", success=True, details={"events": []}
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "query-cloudtrail-logs", "--path", "/tmp/logs"])
        args.func(args)

        _, kwargs = mock_instance.aws_ir.hunt.query_local_cloudtrail_logs.call_args
        assert kwargs["fields"] is None


class TestAwsHuntCloudtrailSourceIpFullScan:
    def test_source_ip_alone_auto_enables_full_scan_and_warns(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.lookup_events.return_value = OperationResult(
            operation="lookup_events", target="t", success=True, details={"events": []}
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "cloudtrail", "--source-ip", "1.2.3.4"])
        args.func(args)

        _, kwargs = mock_instance.aws_ir.hunt.lookup_events.call_args
        assert kwargs["allow_full_scan"] is True

        captured = capsys.readouterr()
        assert "note:" in captured.err
        assert "--source-ip" in captured.err
        assert '"success"' not in captured.err  # warning is stderr-only, JSON stays on stdout

    def test_source_ip_with_user_does_not_warn_or_force_full_scan(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.lookup_events.return_value = OperationResult(
            operation="lookup_events", target="t", success=True, details={"events": []}
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(
            ["aws", "hunt", "cloudtrail", "--user", "alice", "--source-ip", "1.2.3.4"]
        )
        args.func(args)

        _, kwargs = mock_instance.aws_ir.hunt.lookup_events.call_args
        assert kwargs["allow_full_scan"] is False
        assert capsys.readouterr().err == ""

    def test_no_source_ip_does_not_warn(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.lookup_events.return_value = OperationResult(
            operation="lookup_events", target="t", success=True, details={"events": []}
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "cloudtrail", "--user", "alice"])
        args.func(args)

        _, kwargs = mock_instance.aws_ir.hunt.lookup_events.call_args
        assert kwargs["allow_full_scan"] is False
        assert capsys.readouterr().err == ""


class TestMainCleansUpValueErrors:
    def test_value_error_prints_clean_message_and_exits_1(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.side_effect = ValueError(
            "Invalid IP or CIDR: 'not-an-ip'"
        )
        monkeypatch.setattr(
            "sys.argv",
            ["dredge", "aws", "hunt", "security-groups-by-ip", "--ip", "not-an-ip"],
        )

        with pytest.raises(SystemExit) as exc_info:
            dredge_cli.main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert captured.err.strip() == "Error: Invalid IP or CIDR: 'not-an-ip'"
        assert captured.out == ""


# ---------------------------------------------------------------------------
# github-hunt-audit: same 4 time-range branches + 2 SystemExit guards
# ---------------------------------------------------------------------------


class TestGithubHuntAuditTimeRanges:
    def test_explicit_start_end(self, monkeypatch, capsys):
        argv = [
            *GITHUB_ORG_ARGS,
            "github", "hunt", "audit",
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
        argv = [*GITHUB_ORG_ARGS, "github", "hunt", "audit", "--today"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"].hour == 0

    def test_week_ago(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github", "hunt", "audit", "--week-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] < kwargs["end_time"]

    def test_month_ago(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github", "hunt", "audit", "--month-ago", "1"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is not None

    def test_no_time_args_both_none(self, monkeypatch, capsys):
        argv = [*GITHUB_ORG_ARGS, "github", "hunt", "audit"]
        target, out = _run_handler(monkeypatch, capsys, argv, "github_ir.hunt.search_audit_log")
        _, kwargs = target.call_args
        assert kwargs["start_time"] is None
        assert kwargs["end_time"] is None

    def test_missing_github_org_raises_system_exit(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["github", "hunt", "audit"])
        with pytest.raises(SystemExit):
            args.func(args)

    def test_github_ir_none_raises_system_exit(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        mock_instance.github_ir = None
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        parser = dredge_cli.build_parser()
        args = parser.parse_args([*GITHUB_ORG_ARGS, "github", "hunt", "audit"])
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
        args = parser.parse_args(["github", "response", "archive-repository", "--repo", "r1"])
        with pytest.raises(SystemExit):
            args.func(args)


# ---------------------------------------------------------------------------
# main() -- the real entrypoint, not just args.func(args) called directly
# ---------------------------------------------------------------------------


class TestAwsHuntSecurityGroupsByIpTable:
    def test_default_output_is_a_table(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip",
            target="ips=185.69.122.229",
            success=True,
            details={
                "matches": [{
                    "group_id": "sg-04820972",
                    "group_name": "vpn-bind-sg",
                    "vpc_id": "vpc-1",
                    "matched_rules": [{
                        "direction": "ingress", "protocol": "tcp",
                        "from_port": 443, "to_port": 443,
                        "cidr": "185.69.122.229/32",
                        "match_type": "explicit",
                        "matched_targets": ["185.69.122.229/32"],
                    }],
                }],
                "statistics": {"groups_scanned": 10, "groups_matched": 1},
            },
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "185.69.122.229"])
        args.func(args)

        out = capsys.readouterr().out
        assert (
            "Group name" in out and "ID" in out and "Direction" in out
            and "Match" in out and "Matched targets" in out
        )
        assert "vpn-bind-sg" in out
        assert "sg-04820972" in out
        assert "Inbound" in out
        assert "Explicit" in out
        assert "185.69.122.229/32" in out
        # No raw JSON leakage in the default table view
        assert '"success"' not in out

    def test_match_type_shown_as_wildcard_for_open_rules(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": [{
                "group_id": "sg-open", "group_name": "web-open",
                "matched_rules": [
                    {"direction": "ingress", "match_type": "wildcard", "matched_targets": ["1.2.3.4/32"]},
                ],
            }]},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4"])
        args.func(args)

        out = capsys.readouterr().out
        assert "Wildcard" in out
        assert "*" in out

    def test_direction_labels_and_splits_rows_per_direction(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": [{
                "group_id": "sg-1", "group_name": "sg",
                "matched_rules": [
                    {"direction": "ingress", "matched_targets": ["1.2.3.4/32"]},
                    {"direction": "egress", "matched_targets": ["1.2.3.4/32"]},
                ],
            }]},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4"])
        args.func(args)

        out = capsys.readouterr().out
        assert "Inbound" in out
        assert "Outbound" in out
        # Same target, two directions -> two distinct rows
        assert out.count("1.2.3.4/32") == 2

    def test_dedupes_matched_targets_across_rules(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": [{
                "group_id": "sg-1", "group_name": "sg",
                "matched_rules": [
                    {"matched_targets": ["1.2.3.4/32"]},
                    {"matched_targets": ["1.2.3.4/32", "10.0.0.0/8"]},
                ],
            }]},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4"])
        args.func(args)

        out = capsys.readouterr().out
        assert out.count("1.2.3.4/32") == 1
        assert "10.0.0.0/8" in out

    def test_no_matches_prints_placeholder(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": []},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "9.9.9.9"])
        args.func(args)

        assert "(no results)" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "cli_value,lib_value",
        [("inbound", "ingress"), ("outbound", "egress"), ("both", "both")],
    )
    def test_direction_flag_translated_for_the_library_call(
        self, monkeypatch, capsys, cli_value, lib_value,
    ):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": []},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(
            ["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4", "--direction", cli_value]
        )
        args.func(args)

        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.assert_called_once_with(
            ["1.2.3.4"], direction=lib_value, max_groups=500,
        )

    def test_verbose_prints_full_json(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_security_groups_by_ip.return_value = OperationResult(
            operation="hunt_security_groups_by_ip", target="t", success=True,
            details={"matches": [{"group_id": "sg-1", "group_name": "sg", "matched_rules": []}]},
        )

        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt", "security-groups-by-ip", "--ip", "1.2.3.4", "--verbose"])
        args.func(args)

        out = capsys.readouterr().out
        assert '"success": true' in out
        assert '"matched_rules"' in out


class TestAwsHuntExposedSecretsUnredacted:
    def test_unredacted_writes_raw_values_to_file_mode_0600(self, monkeypatch, capsys, tmp_path):
        import json
        import stat

        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.hunt.hunt_exposed_secrets.return_value = OperationResult(
            operation="hunt_exposed_secrets",
            target="sources=lambda",
            success=True,
            details={
                "credentials": [{"hash": "abc123", "category": "Generic Secret"}],
                "raw_values": {"abc123": "super-secret-plaintext"},
                "statistics": {"scanned": {"lambda": 1}, "findings": 1},
            },
        )

        out_path = tmp_path / "raw.json"
        parser = dredge_cli.build_parser()
        args = parser.parse_args([
            "aws", "hunt", "exposed-secrets", "--include", "lambda", "--unredacted", str(out_path),
        ])
        args.func(args)

        written = json.loads(out_path.read_text())
        assert written == {"abc123": "super-secret-plaintext"}
        mode = stat.S_IMODE(out_path.stat().st_mode)
        assert mode == 0o600

        printed = capsys.readouterr().out
        assert "super-secret-plaintext" not in printed
        assert "raw_values" not in printed


class TestMain:
    def test_main_parses_argv_and_dispatches(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.response.disable_user.return_value = OperationResult(
            operation="disable_user", target="user=bob", success=True, details={}
        )
        monkeypatch.setattr(
            "sys.argv", ["dredge-cli", "aws", "response", "disable-user", "--user", "bob"]
        )

        dredge_cli.main()

        mock_instance.aws_ir.response.disable_user.assert_called_once_with("bob")
        assert '"success": true' in capsys.readouterr().out

    def test_main_parses_nested_argv_and_dispatches(self, monkeypatch, capsys):
        mock_dredge_class = MagicMock()
        mock_instance = mock_dredge_class.return_value
        monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)
        mock_instance.aws_ir.response.disable_user.return_value = OperationResult(
            operation="disable_user", target="user=bob", success=True, details={}
        )
        monkeypatch.setattr(
            "sys.argv", ["dredge-cli", "aws", "response", "disable-user", "--user", "bob"]
        )

        dredge_cli.main()

        mock_instance.aws_ir.response.disable_user.assert_called_once_with("bob")
        assert '"success": true' in capsys.readouterr().out


class TestNestedCliStructure:
    def test_nested_invocation_dispatches_to_handler(self, monkeypatch, capsys):
        target, out = _run_handler(
            monkeypatch, capsys,
            ["aws", "hunt", "access-analyzer", "arn:aws:access-analyzer:us-east-1:1:analyzer/a"],
            "aws_ir.hunt.hunt_access_analyzer_findings",
        )
        target.assert_called_once()
        assert '"success": true' in out

    def test_bare_provider_prints_help_not_error(self, capsys):
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws"])
        args.func(args)
        out = capsys.readouterr().out
        assert "<bucket>" in out
        assert "hunt" in out and "response" in out and "forensics" in out

    def test_bare_bucket_prints_help_not_error(self, capsys):
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["aws", "hunt"])
        args.func(args)
        out = capsys.readouterr().out
        assert "<command>" in out
        assert "access-analyzer" in out

    def test_provider_help_lists_buckets(self, capsys):
        parser = dredge_cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["aws", "-h"])
        out = capsys.readouterr().out
        assert "response" in out and "hunt" in out and "forensics" in out

    def test_bucket_help_lists_commands(self, capsys):
        parser = dredge_cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["k8s", "forensics", "-h"])
        out = capsys.readouterr().out
        assert "get-pod-manifest" in out
        assert "exec-pod-command" in out

    def test_top_level_grouped_help_shows_nested_invocations(self, capsys):
        parser = dredge_cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["-h"])
        out = capsys.readouterr().out
        assert "aws hunt access-analyzer" in out
        assert "AWS — Hunt & Investigate:" in out
        assert "Kubernetes — Forensics:" in out

    def test_unknown_provider_errors(self, capsys):
        parser = dredge_cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["nope", "hunt", "x"])

    def test_exec_pod_command_positional_not_shadowed_by_provider_dest(self):
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["k8s", "forensics", "exec-pod-command", "mypod", "ls", "tmp"])
        assert args.provider == "k8s"
        assert args.command == ["ls", "tmp"]
        assert args.name == "mypod"
