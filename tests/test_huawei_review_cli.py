from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from dredge.cli import build_parser
from dredge.huawei_ir.models import OperationResult
from dredge.huawei_ir.review import SERVICES


@pytest.mark.parametrize("prefix", [
    ["huawei", "--huawei-profile", "all", "--huawei-region", "all"],
    ["--huawei-profile", "all", "--huawei-region", "all", "huawei"],
])
def test_cli_sweep_reports_and_no_aws(prefix, tmp_path, capsys):
    csv_path, html_path = tmp_path / "out.csv", tmp_path / "out.html"
    args = build_parser().parse_args(prefix + ["review", "full", "--deep", "--sso-login", "--csv", str(csv_path), "--html", str(html_path),
        "--include", "vpc-open-critical-ports,iam-login-protection", "--exclude", "iam-admin-groups", "--ip", "203.0.113.1", "--incident-start", "2026-01-01T00:00:00Z"])
    result = OperationResult("review_multi_profile", "all", True, {"findings": [], "complete": False})
    with patch("dredge.huawei_ir.review_multi_profile", return_value=result) as run, patch("dredge.cli.Dredge") as aws:
        args.func(args)
    aws.assert_not_called()
    assert run.call_args.kwargs["regions"] == "all"
    assert run.call_args.kwargs["profiles"] == "all"
    assert run.call_args.kwargs["tiers"] == (1, 2)
    assert run.call_args.kwargs["sso_login"] is True
    assert run.call_args.kwargs["include"] == ["vpc-open-critical-ports", "iam-login-protection"]
    assert run.call_args.kwargs["incident_start"] == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert csv_path.exists() and "INCOMPLETE" in html_path.read_text()
    assert '"complete": false' in capsys.readouterr().out


@pytest.mark.parametrize("service", ["full", *SERVICES])
def test_all_review_commands(service):
    args = build_parser().parse_args(["huawei", "review", service, "--all-regions"])
    with patch("dredge.huawei_ir.review_multi_profile", return_value=OperationResult("review", "all", True)) as run:
        args.func(args)
    assert run.call_args.kwargs["services"] == (None if service == "full" else [service])
    assert run.call_args.kwargs["tiers"] == ((1,) if service == "full" else (1, 2))
    assert run.call_args.kwargs["regions"] == "all"


def test_cli_explicit_regions_and_koocli():
    args = build_parser().parse_args(["huawei", "--huawei-profile-source", "koocli", "--huawei-profile", "audit", "review", "rds",
                                     "--regions", "cn-north-4,ap-southeast-1", "--max-resources", "50"])
    with patch("dredge.huawei_ir.review_multi_profile", return_value=OperationResult("review", "all", True)) as run:
        args.func(args)
    assert run.call_args.kwargs["profile_source"] == "koocli"
    assert run.call_args.kwargs["regions"] == ["cn-north-4", "ap-southeast-1"]
    assert run.call_args.kwargs["max_resources"] == 50
