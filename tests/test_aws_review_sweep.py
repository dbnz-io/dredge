import csv
import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError, SSOTokenLoadError

from dredge.auth import AwsAuthConfig
from dredge.aws_ir import profile_sweep, review_sweep
from dredge.aws_ir.models import OperationResult
from dredge.aws_ir.review import AwsIRReview
from dredge.cli import build_parser


CHECKS = ["iam-weak-role-trust", "rds-public-instances"]


def denied():
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "PRIVATE ERROR BODY"}}, "Read")


@pytest.fixture
def environment(monkeypatch):
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION"):
        monkeypatch.delenv(name, raising=False)
    catalog = {"profiles": {"alpha": {"region": "us-east-1"}, "beta": {"region": "eu-west-1"}}}
    monkeypatch.setattr(profile_sweep, "_profile_catalog", lambda: catalog)
    state = SimpleNamespace(catalog=catalog, configs=[], sessions=[], calls=[], auth_errors={},
                            discovery_errors={}, check_errors={}, clean_regions=set())

    def factory(config):
        state.configs.append(config)
        session = MagicMock(region_name=config.region_name)
        session.owner = None
        profile = config.profile_name

        def client(name, **kwargs):
            region = kwargs.get("region_name", config.region_name)
            state.calls.append((profile, name, region))
            if name != "sts":
                thread = threading.get_ident()
                assert session.owner in (None, thread), "A profile session crossed worker threads"
                session.owner = thread
            api = MagicMock()
            if name == "sts":
                if profile in state.auth_errors:
                    api.get_caller_identity.side_effect = state.auth_errors[profile]
                else:
                    account = "111111111111" if profile == "alpha" else "222222222222"
                    api.get_caller_identity.return_value = {
                        "Account": account, "Arn": f"arn:aws:iam::{account}:role/{profile}",
                    }
            elif name == "ec2":
                if profile in state.discovery_errors:
                    api.describe_regions.side_effect = state.discovery_errors[profile]
                else:
                    regions = ["us-east-1", "eu-west-1"] if profile == "alpha" else ["us-east-1"]
                    api.describe_regions.return_value = {"Regions": [
                        *[{"RegionName": r, "OptInStatus": "opted-in"} for r in regions],
                        {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
                    ]}
            elif name == "iam":
                api.get_paginator.return_value.paginate.return_value = [{"Roles": [{
                    "RoleName": "shared-name", "AssumeRolePolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Principal": "*"}]},
                }]}]
            elif name == "rds":
                api.meta.region_name = region
                if (profile, region) in state.check_errors:
                    api.get_paginator.return_value.paginate.side_effect = state.check_errors[profile, region]
                else:
                    api.get_paginator.return_value.paginate.return_value = [{"DBInstances": [{
                        "DBInstanceIdentifier": "shared-name",
                        "PubliclyAccessible": (profile, region) not in state.clean_regions,
                    }]}]
            else:
                raise AssertionError(f"Unexpected AWS API: {name}")
            return api

        session.client.side_effect = client
        state.sessions.append(session)
        return SimpleNamespace(get_session=lambda: session)

    monkeypatch.setattr(profile_sweep, "AwsSessionFactory", factory)
    return state


def test_all_profiles_regions_run_globals_once_with_attribution(environment):
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS, max_workers=2)
    assert result.success
    findings = result.details["findings"]
    assert len(findings) == 5
    assert sum(name == "iam" for _, name, _ in environment.calls) == 2
    assert sum(name == "rds" for _, name, _ in environment.calls) == 3
    assert len({f["account_id"] for f in findings}) == 2
    assert all(f["principal_arn"].endswith(f["profile"]) for f in findings)
    assert {(f["profile"], f["region"]) for f in findings if f["service"] == "rds"} == {
        ("alpha", "us-east-1"), ("alpha", "eu-west-1"), ("beta", "us-east-1"),
    }
    assert result.details["summary"] == {"CRITICAL": 5}
    assert all(cfg.region_name != "all" and cfg.profile_name != "all" for cfg in environment.configs)


def test_authentication_failure_keeps_other_profile(environment):
    environment.auth_errors["alpha"] = NoCredentialsError()
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS)
    assert not result.success
    assert not result.details["profiles"]["alpha"]["authenticated"]
    assert result.details["profiles"]["beta"]["success"]
    assert {f["profile"] for f in result.details["findings"]} == {"beta"}
    assert result.details["checks"]["iam-weak-role-trust"]["status"] == "partial"


def test_discovery_failure_preserves_global_checks(environment):
    environment.discovery_errors["alpha"] = denied()
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS)
    assert not result.success
    alpha = result.details["profiles"]["alpha"]
    assert alpha["checks"]["iam-weak-role-trust"]["status"] == "ran"
    assert alpha["checks"]["rds-public-instances"]["status"] == "skipped"
    assert "AccessDenied" in alpha["errors"][0]
    assert "PRIVATE ERROR BODY" not in json.dumps(result.details)
    assert sum(name == "rds" for _, name, _ in environment.calls) == 1
    assert len(result.details["findings"]) == 3


def test_regional_check_failure_isolated_even_when_other_region_has_no_findings(environment):
    environment.check_errors["alpha", "eu-west-1"] = denied()
    environment.clean_regions.add(("alpha", "us-east-1"))
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS)
    assert not result.success
    check = result.details["profiles"]["alpha"]["checks"]["rds-public-instances"]
    assert check["status"] == "partial"
    assert check["by_region"]["us-east-1"]["count"] == 0
    assert result.details["profiles"]["beta"]["success"]
    assert "PRIVATE ERROR BODY" not in json.dumps(result.details)


@pytest.mark.parametrize("options", [{"services": ["iam"], "include": ["iam-weak-role-trust"]},
                                         {"include": ["iam-weak-role-trust"]},
                                         {"include": ["ec2-sg-references-ip"]}])
def test_global_or_skipped_checks_need_no_region_discovery(environment, options):
    result = review_sweep.review_multi_profile(regions="all", **options)
    assert result.success
    assert not any(name == "ec2" for _, name, _ in environment.calls)
    assert all(not record["regions"] for record in result.details["profiles"].values())


def test_profile_defaults_and_explicit_regions(environment):
    result = review_sweep.review_multi_profile(include=CHECKS)
    assert result.success
    assert {(p, r) for p, service, r in environment.calls if service == "rds"} == {
        ("alpha", "us-east-1"), ("beta", "eu-west-1"),
    }
    environment.calls.clear()
    result = review_sweep.review_multi_profile(profiles=["alpha"], regions=["eu-west-2", "eu-west-2"], include=CHECKS)
    assert result.success
    assert [(p, r) for p, service, r in environment.calls if service == "rds"] == [("alpha", "eu-west-2")]
    assert not any(service == "ec2" for _, service, _ in environment.calls)


def test_sso_is_shared_with_secret_hunt(environment, monkeypatch):
    environment.catalog["profiles"]["alpha"]["sso_session"] = "team"
    environment.catalog["profiles"]["beta"]["sso_session"] = "team"
    environment.auth_errors.update(alpha=SSOTokenLoadError(error_msg="missing"), beta=SSOTokenLoadError(error_msg="missing"))
    login = MagicMock(side_effect=lambda _: environment.auth_errors.clear())
    monkeypatch.setattr(profile_sweep, "_login_sso", login)
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS, sso_login=True)
    assert result.success
    login.assert_called_once_with(["--sso-session=team"])


@pytest.mark.parametrize("options", [
    {"max_workers": 0}, {"max_workers": 33}, {"regions": []}, {"regions": "us-east-1"},
    {"profiles": []}, {"auth": AwsAuthConfig(access_key_id="EXAMPLE", secret_access_key="EXAMPLE")},
    {"services": ["wrong"]}, {"services": "iam"}, {"tiers": (3,)}, {"include": ["wrong"]},
    {"exclude": "iam-weak-role-trust"}, {"ips": ["not-an-ip"]}, {"ips": "192.0.2.1"},
    {"incident_start": "yesterday"},
])
def test_validation_precedes_authentication(environment, options):
    with pytest.raises(ValueError):
        review_sweep.review_multi_profile(**options)
    assert not environment.configs


def test_csv_html_include_profile_context_and_failure_details(environment, tmp_path):
    environment.check_errors["alpha", "eu-west-1"] = denied()
    result = review_sweep.review_multi_profile(regions="all", include=CHECKS)
    csv_path, html_path = tmp_path / "review.csv", tmp_path / "review.html"
    AwsIRReview.to_csv(result, csv_path)
    AwsIRReview.to_html(result, html_path)
    with csv_path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert {row["profile"] for row in rows} == {"alpha", "beta"}
    assert {row["account_id"] for row in rows} == {"111111111111", "222222222222"}
    assert all(row["principal_arn"] for row in rows)
    rendered = html_path.read_text()
    assert "Review incomplete." in rendered
    assert "eu-west-1: ClientError (AccessDenied)" in rendered
    assert 'id="profile-filter"' in rendered
    assert "PRIVATE ERROR BODY" not in rendered


def test_all_auth_failures_cannot_render_clean_report_and_profile_names_are_escaped(environment, tmp_path):
    label = '<script>alert("profile")</script>'
    environment.catalog["profiles"] = {label: {}}
    environment.auth_errors[label] = NoCredentialsError()
    result = review_sweep.review_multi_profile(include=CHECKS)
    assert not result.success and not result.details["findings"]
    path = tmp_path / "failed.html"
    AwsIRReview.to_html(result, path)
    rendered = path.read_text()
    assert label not in rendered
    assert "&lt;script&gt;" in rendered
    assert "NoCredentialsError" in rendered
    assert "No findings collected; review incomplete" in rendered


@pytest.mark.parametrize("prefix", [
    ["aws", "--aws-profile", "all", "--aws-region", "all"],
    ["--aws-profile", "all", "--region", "all", "aws"],
])
@pytest.mark.parametrize("service", ["full", "iam", "ecs"])
def test_cli_flag_positions_and_service_commands(prefix, service, capsys):
    args = build_parser().parse_args([*prefix, "review", service, "--sso-login", "--max-workers", "2"])
    with patch.object(review_sweep, "review_multi_profile", return_value=OperationResult("review", "all", True)) as run:
        args.func(args)
    options = run.call_args.kwargs
    assert options["profiles"] == options["regions"] == "all"
    assert options["auth"].profile_name is None and options["auth"].region_name is None
    assert options["sso_login"] and options["max_workers"] == 2
    assert options["services"] == ("all" if service == "full" else [service])
    assert options["tiers"] == ((1,) if service == "full" else (1, 2))
    assert json.loads(capsys.readouterr().out)["success"]


@pytest.mark.parametrize("flags, leaf_flags, profiles, regions", [
    (["--aws-profile", "all", "--aws-region", "eu-west-2"], [], "all", None),
    (["--aws-profile", "all"], ["--all-regions"], "all", "all"),
    (["--aws-profile", "all"], ["--regions", "us-east-1,eu-west-1"], "all", ["us-east-1", "eu-west-1"]),
    (["--aws-profile", "alpha", "--aws-region", "all"], [], None, "all"),
    (["--aws-profile", "alpha"], ["--sso-login"], None, None),
])
def test_cli_single_all_flag_and_existing_region_flags(flags, leaf_flags, profiles, regions, capsys):
    args = build_parser().parse_args(["aws", *flags, "review", "full", "--deep", *leaf_flags])
    with patch.object(review_sweep, "review_multi_profile", return_value=OperationResult("review", "all", True)) as run:
        args.func(args)
    options = run.call_args.kwargs
    assert options["profiles"] == profiles and options["regions"] == regions
    assert options["tiers"] == (1, 2)
    if "eu-west-2" in flags:
        assert options["auth"].region_name == "eu-west-2"
