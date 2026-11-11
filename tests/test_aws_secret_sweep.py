import json
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError, SSOTokenLoadError, EndpointConnectionError

from dredge.auth import AwsAuthConfig
from dredge.aws_ir.models import OperationResult
from dredge.aws_ir import secret_sweep as sweep
from dredge.aws_ir import profile_sweep as profiles
from dredge.cli import build_parser


def denied(message="sensitive response body"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": message}}, "DescribeRegions")


def finding_result(keep_raw=False):
    details = {"credentials": [{"hash": "same-hash", "category": "GitHub Token", "severity": "CRITICAL",
                                "detection_method": "regex:github_token", "redacted_value": "ghp_***tail",
                                "sources": [{"resource_id": "function", "location_type": "lambda_env"}],
                                "live_test_result": None}], "statistics": {"findings": 1, "scanned": {"lambda": 1}}}
    if keep_raw:
        details["raw_values"] = {"same-hash": "secret-plaintext"}
    return OperationResult("hunt_exposed_secrets", "sources=lambda", True, details)


@pytest.fixture
def environment(monkeypatch):
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION"):
        monkeypatch.delenv(name, raising=False)
    catalog = {"profiles": {"alpha": {"region": "us-east-1"}, "beta": {"region": "eu-west-1"}}}
    monkeypatch.setattr(profiles, "_profile_catalog", lambda: catalog)
    configurations, sessions = [], []
    failures = {}
    def factory(config):
        configurations.append(config)
        session = MagicMock()
        session.profile = config.profile_name
        session.owner = None
        sts, ec2 = MagicMock(), MagicMock()
        sts.get_caller_identity.side_effect = lambda: identity(config.profile_name)
        ec2.describe_regions.return_value = {"Regions": [
            {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "eu-west-1", "OptInStatus": "opted-in"},
            {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
        ]}
        session.client.side_effect = lambda name, **kwargs: sts if name == "sts" else ec2
        sessions.append(session)
        return SimpleNamespace(get_session=lambda: session)
    def identity(profile):
        error = failures.get(profile)
        if error:
            raise error
        return {"Account": "111111111111", "Arn": f"arn:aws:iam::111111111111:role/{profile}"}
    monkeypatch.setattr(profiles, "AwsSessionFactory", factory)
    with patch.object(sweep.AwsIRHunt, "hunt_exposed_secrets", autospec=True) as scan:
        def execute(hunt, **kwargs):
            session = hunt._services._session
            owner = threading.get_ident()
            assert session.owner in (None, owner), "A session was shared by multiple workers"
            session.owner = owner
            return finding_result(kwargs.get("keep_raw"))
        scan.side_effect = execute
        yield SimpleNamespace(catalog=catalog, configs=configurations, sessions=sessions,
                              failures=failures, scan=scan)


def test_all_profiles_enabled_regions_attribution_dedup(environment):
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all")
    assert result.success
    assert environment.scan.call_count == 4
    assert {cfg.profile_name for cfg in environment.configs} == {"alpha", "beta"}
    assert "all" not in {cfg.region_name for cfg in environment.configs}
    assert len(result.details["credentials"]) == 1
    sources = result.details["credentials"][0]["sources"]
    assert {(s["profile"], s["region"]) for s in sources} == {
        ("alpha", "eu-west-1"), ("alpha", "us-east-1"), ("beta", "eu-west-1"), ("beta", "us-east-1")}
    assert all(s["account_id"] == "111111111111" for s in sources)
    # Different profiles/roles in one account are deliberately not skipped.
    assert len({s["principal_arn"] for s in sources}) == 2
    assert "raw_values" not in result.details


def test_authentication_failure_does_not_stop_other_profiles(environment):
    environment.failures["alpha"] = NoCredentialsError()
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all")
    assert not result.success
    assert not result.details["profiles"]["alpha"]["authenticated"]
    assert result.details["profiles"]["beta"]["authenticated"]
    assert environment.scan.call_count == 2


def test_one_region_failure_keeps_other_regions_and_profiles(environment):
    def scan(hunt, **kwargs):
        if hunt._services._region == "eu-west-1":
            raise RuntimeError("secret in exception body")
        return finding_result()
    environment.scan.side_effect = scan
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all")
    assert not result.success
    assert "secret in exception body" not in json.dumps(result.details)
    assert result.details["profiles"]["alpha"]["regions"]["us-east-1"]["success"]
    assert len(result.details["credentials"][0]["sources"]) == 2


def test_region_discovery_denied_does_not_fall_back_to_other_partition(environment, monkeypatch):
    original = profiles._authenticate
    def authenticate(*args):
        factory, region, identity = original(*args)
        factory.get_session().client("ec2").describe_regions.side_effect = denied()
        return factory, region, identity
    monkeypatch.setattr(profiles, "_authenticate", authenticate)
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all")
    assert not result.success
    environment.scan.assert_not_called()
    assert "sensitive response body" not in json.dumps(result.details)
    assert "AccessDenied" in result.details["profiles"]["alpha"]["errors"][0]


def test_s3_once_per_profile_and_never_per_region(environment):
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all", scan_s3=["s3://bucket/target/"])
    assert environment.scan.call_count == 6
    calls = [call for call in environment.scan.call_args_list if call.kwargs["scan_s3"]]
    assert len(calls) == 2
    assert all(call.kwargs["include"] == [] for call in calls)
    assert all(call.kwargs["scan_cloudwatch"] is None for call in calls)
    assert set(result.details["profiles"]["alpha"]["regions"]) == {"global", "us-east-1", "eu-west-1"}


def test_s3_only_skips_region_discovery_and_exports_raw_only_at_top(environment):
    result = sweep.hunt_exposed_secrets_multi_profile(regions="all", include=[], scan_s3=["s3://bucket/path"], keep_raw=True)
    assert environment.scan.call_count == 2
    for session in environment.sessions:
        session.client("ec2").describe_regions.assert_not_called()
    assert result.details["raw_values"] == {"same-hash": "secret-plaintext"}
    assert "secret-plaintext" not in json.dumps(result.details["profiles"])


def test_explicit_regions_and_profile_region_defaults(environment):
    result = sweep.hunt_exposed_secrets_multi_profile(profiles=["beta"], regions=["eu-west-1", "eu-west-1"])
    assert result.success
    assert environment.scan.call_count == 1
    environment.sessions[0].client("ec2").describe_regions.assert_not_called()
    environment.scan.reset_mock()
    sweep.hunt_exposed_secrets_multi_profile()
    assert {call.args[0]._services._region for call in environment.scan.call_args_list} == {"us-east-1", "eu-west-1"}


def test_sso_login_once_for_shared_session_and_source_profile(environment, monkeypatch):
    environment.catalog["profiles"] = {"alpha": {"sso_session": "shared"}, "beta": {"source_profile": "alpha", "role_arn": "arn:aws:iam::111111111111:role/B"}}
    environment.failures.update(alpha=SSOTokenLoadError(error_msg="missing"), beta=SSOTokenLoadError(error_msg="missing"))
    def login(arguments):
        assert arguments == ["--sso-session=shared"]
        environment.failures.clear()
    login_mock = MagicMock(side_effect=login)
    monkeypatch.setattr(profiles, "_login_sso", login_mock)
    result = sweep.hunt_exposed_secrets_multi_profile(sso_login=True)
    assert result.success
    login_mock.assert_called_once()
    assert len(environment.configs) == 3  # Rebuild the first session after login.


def test_sso_login_failure_not_repeated_or_leaked(environment, monkeypatch):
    for name in ("alpha", "beta"):
        environment.catalog["profiles"][name]["sso_session"] = "shared"
        environment.failures[name] = SSOTokenLoadError(error_msg="SECRET")
    login = MagicMock(side_effect=RuntimeError("SECRET"))
    monkeypatch.setattr(profiles, "_login_sso", login)
    result = sweep.hunt_exposed_secrets_multi_profile(sso_login=True)
    assert not result.success
    login.assert_called_once()
    assert "SECRET" not in json.dumps(result.details)
    environment.scan.assert_not_called()


def test_sso_is_opt_in_and_access_denied_does_not_trigger_login(environment, monkeypatch):
    environment.catalog["profiles"]["alpha"]["sso_session"] = "shared"
    environment.failures["alpha"] = SSOTokenLoadError(error_msg="missing")
    login = MagicMock()
    monkeypatch.setattr(profiles, "_login_sso", login)
    result = sweep.hunt_exposed_secrets_multi_profile()
    assert "login_hint" in result.details["profiles"]["alpha"]
    login.assert_not_called()
    environment.failures["alpha"] = denied()
    sweep.hunt_exposed_secrets_multi_profile(sso_login=True)
    login.assert_not_called()


def test_sso_retry_failure_is_isolated(environment, monkeypatch):
    environment.catalog["profiles"]["alpha"]["sso_session"] = "shared"
    environment.failures["alpha"] = SSOTokenLoadError(error_msg="missing")
    monkeypatch.setattr(profiles, "_login_sso", MagicMock())
    result = sweep.hunt_exposed_secrets_multi_profile(sso_login=True)
    assert not result.success
    assert result.details["profiles"]["beta"]["authenticated"]


def test_legacy_sso_and_source_profile_cycles():
    catalog = {"profiles": {"old": {"sso_start_url": "https://example.awsapps.com/start", "sso_region": "eu-west-1"},
                            "a": {"source_profile": "b"}, "b": {"source_profile": "a"}}}
    key, arguments = profiles._sso_source("old", catalog)
    assert key[0] == "legacy"
    assert arguments == ["--profile=old"]
    assert profiles._sso_source("a", catalog) is None


def test_login_uses_argv_and_stderr(monkeypatch):
    monkeypatch.setattr(profiles.shutil, "which", lambda _: "/example/aws")
    with patch.object(profiles.subprocess, "run") as run:
        profiles._login_sso(["--sso-session=shared session"])
        assert run.call_args.args[0] == ["/example/aws", "sso", "login", "--sso-session=shared session"]
        assert run.call_args.kwargs["stdout"] is profiles.sys.stderr
        assert not run.call_args.kwargs.get("shell")
    monkeypatch.setattr(profiles.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError):
        profiles._login_sso([])


@pytest.mark.parametrize("options", [
    {"max_workers": 0}, {"max_workers": 33}, {"regions": "us-east-1"}, {"regions": []},
    {"regions": ["all"]}, {"profiles": "alpha"}, {"profiles": []}, {"include": ["unknown"]},
    {"scan_s3": "s3://bucket/path"}, {"scan_s3": ["s3://bucket/"]}, {"scan_cloudwatch": ["logs"]},
    {"max_ec2_instances": -1}, {"auth": AwsAuthConfig(access_key_id="ak", secret_access_key="sk")},
    {"auth": AwsAuthConfig(region_name="all")},
])
def test_validation_before_auth(environment, options):
    with pytest.raises(ValueError):
        sweep.hunt_exposed_secrets_multi_profile(**options)
    assert not environment.configs


def test_empty_profile_catalog(environment):
    environment.catalog["profiles"] = {}
    with pytest.raises(ValueError, match="No configured AWS profiles"):
        sweep.hunt_exposed_secrets_multi_profile()


def test_profile_catalog_reads_both_aws_files(tmp_path, monkeypatch):
    config = tmp_path / "config"
    credentials = tmp_path / "credentials"
    config.write_text("[profile sso-audit]\nsso_session=team\nregion=eu-west-1\n[sso-session team]\nsso_region=eu-west-1\nsso_start_url=https://example.awsapps.com/start\n")
    credentials.write_text("[static-audit]\naws_access_key_id=EXAMPLE\naws_secret_access_key=EXAMPLE\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    assert set(profiles._profile_catalog()["profiles"]) == {"sso-audit", "static-audit"}


@pytest.mark.parametrize("prefix", [["aws", "--aws-profile", "all", "--aws-region", "all"],
                                    ["--aws-profile", "all", "--aws-region", "all", "aws"]])
def test_cli_all_flag_positions(prefix, capsys):
    args = build_parser().parse_args([*prefix, "hunt", "exposed-secrets", "--sso-login", "--max-workers", "2"])
    with patch.object(sweep, "hunt_exposed_secrets_multi_profile", return_value=finding_result()) as run:
        args.func(args)
        kwargs = run.call_args.kwargs
        assert kwargs["profiles"] == "all" and kwargs["regions"] == "all"
        assert kwargs["auth"].profile_name is None and kwargs["auth"].region_name is None
        assert kwargs["max_workers"] == 2 and kwargs["sso_login"]
        assert json.loads(capsys.readouterr().out)["success"]


def test_all_flags_rejected_for_mutating_command():
    args = build_parser().parse_args(["aws", "--aws-profile", "all", "response", "disable-user", "--user", "someone"])
    with pytest.raises(ValueError, match="exposed-secrets"):
        args.func(args)


def test_source_api_error_body_redacted_and_transport_failure_isolated():
    from dredge.aws_ir.hunt import AwsIRHunt
    from dredge.config import DredgeConfig
    services = MagicMock()
    services.lambda_.get_paginator.return_value.paginate.side_effect = denied("SECRET")
    services.ecs.get_paginator.return_value.paginate.side_effect = EndpointConnectionError(endpoint_url="https://redacted.example")
    result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["lambda", "ecs"])
    assert not result.success
    assert "SECRET" not in json.dumps(result.details)
    assert result.details["scan_errors"] == ["lambda: AccessDenied", "ecs: EndpointConnectionError"]
