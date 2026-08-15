# tests/test_cli_parsing.py

import argparse
from datetime import datetime, timezone

import pytest

from dredge import cli as dredge_cli
from dredge.auth import AwsAuthConfig
from dredge.github_ir.config import GitHubIRConfig

def test_cli_has_expected_subcommands():
    parser = dredge_cli.build_parser()

    # Find the existing subparsers action without creating a new one
    subparsers_action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    subparsers = subparsers_action.choices

    # Basic commands we expect to exist
    for cmd in [
        "aws-disable-access-key",
        "aws-disable-user",
        "aws-hunt-cloudtrail",
        "github-hunt-audit",
    ]:
        assert cmd in subparsers


def test_cli_parses_aws_hunt_cloudtrail_args():
    parser = dredge_cli.build_parser()
    args = parser.parse_args(
        [
            "--aws-profile",
            "backdoor",
            "--region",
            "us-east-1",
            "aws-hunt-cloudtrail",
            "--user",
            "alice",
            "--max-events",
            "10",
        ]
    )

    assert args.command == "aws-hunt-cloudtrail"
    assert args.user == "alice"
    assert args.max_events == 10
    assert args.aws_profile == "backdoor"
    assert args.aws_region == "us-east-1"


# ---------------------------------------------------------------------------
# Pure helpers -- parse_iso_datetime, compute_relative_range,
# build_aws_auth_from_args, build_github_config_from_args, print_result
# ---------------------------------------------------------------------------


class TestParseIsoDatetime:
    def test_none_returns_none(self):
        assert dredge_cli.parse_iso_datetime(None) is None

    def test_valid_iso_parsed(self):
        dt = dredge_cli.parse_iso_datetime("2026-01-01T12:00:00+00:00")
        assert dt == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_trailing_z_treated_as_utc(self):
        dt = dredge_cli.parse_iso_datetime("2026-01-01T12:00:00Z")
        assert dt == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_naive_datetime_gets_utc_tzinfo(self):
        dt = dredge_cli.parse_iso_datetime("2026-01-01T12:00:00")
        assert dt.tzinfo == timezone.utc

    def test_invalid_string_raises_argument_type_error(self):
        with pytest.raises(argparse.ArgumentTypeError):
            dredge_cli.parse_iso_datetime("not-a-date")


class TestComputeRelativeRange:
    def test_weeks_ago(self):
        start, end = dredge_cli.compute_relative_range(weeks_ago=2)
        assert start is not None and end is not None
        assert start < end

    def test_months_ago(self):
        start, end = dredge_cli.compute_relative_range(months_ago=1)
        assert start is not None and end is not None
        assert start < end

    def test_neither_returns_none_none(self):
        assert dredge_cli.compute_relative_range() == (None, None)


class TestBuildAwsAuthFromArgs:
    def _namespace(self, **overrides):
        base = dict(
            aws_profile=None,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            aws_role_arn=None,
            aws_external_id=None,
            aws_region=None,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_no_aws_attrs_set_returns_none(self):
        assert dredge_cli.build_aws_auth_from_args(self._namespace()) is None

    def test_profile_set_returns_aws_auth_config(self):
        result = dredge_cli.build_aws_auth_from_args(self._namespace(aws_profile="backdoor"))
        assert isinstance(result, AwsAuthConfig)
        assert result.profile_name == "backdoor"


class TestBuildGithubConfigFromArgs:
    def _namespace(self, **overrides):
        base = dict(github_org=None, github_enterprise=None, github_token=None)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_neither_org_nor_enterprise_returns_none(self):
        assert dredge_cli.build_github_config_from_args(self._namespace()) is None

    def test_org_set_returns_github_ir_config(self):
        result = dredge_cli.build_github_config_from_args(self._namespace(github_org="acme"))
        assert isinstance(result, GitHubIRConfig)
        assert result.org == "acme"


class TestBuildParserVersionFallback:
    def test_package_not_found_falls_back_to_development(self, monkeypatch):
        def _raise_not_found(_name):
            raise dredge_cli.PackageNotFoundError

        monkeypatch.setattr(dredge_cli, "version", _raise_not_found)
        parser = dredge_cli.build_parser()
        version_action = next(a for a in parser._actions if isinstance(a, argparse._VersionAction))
        assert version_action.version == "dredge development"


class TestPrintResult:
    def test_json_output(self, capsys):
        dredge_cli.print_result({"operation": "op", "success": True}, output="json")
        out = capsys.readouterr().out
        assert '"success": true' in out

    def test_csv_output_with_list_of_dicts(self, capsys):
        data = {"details": {"events": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]}}
        dredge_cli.print_result(data, output="csv")
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert lines[0] == "id,name"
        assert "1,a" in lines[1]

    def test_csv_falls_back_to_json_when_no_list_found(self, capsys):
        data = {"details": {"status": "ok"}}
        dredge_cli.print_result(data, output="csv")
        out = capsys.readouterr().out
        assert '"status": "ok"' in out

    def test_csv_non_dict_list_item_raises_value_error(self):
        # Characterizes a real bug, not the intended behavior: fieldnames is
        # only ever populated from dict items' own keys (`if isinstance(ev,
        # dict): fieldnames.update(ev.keys())`) -- "value" (the column name
        # the non-dict fallback branch writes to) is never added to
        # fieldnames itself. So ANY non-dict item in the list -- whether
        # it's the only item or mixed in with real dicts -- makes
        # writerow({"value": ...}) fail with "dict contains fields not in
        # fieldnames: 'value'", crashing --output csv entirely instead of
        # producing the documented single-"value"-column fallback row.
        # Confirmed for both the all-scalar and dict+scalar-mixed case.
        for details in ({"results": ["a", "b"]}, {"results": [{"id": 1}, "a"]}):
            with pytest.raises(ValueError, match="fieldnames"):
                dredge_cli.print_result({"details": details}, output="csv")

    def test_unknown_output_format_falls_back_to_json(self, capsys):
        dredge_cli.print_result({"operation": "op"}, output="xml")
        out = capsys.readouterr().out
        assert '"operation": "op"' in out
