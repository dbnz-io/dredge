import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir.auth import HuaweiAuthError
from dredge.huawei_ir.profiles import IamDiscovery, load_profiles, validate_sso_profile


def write_profiles(tmp_path, monkeypatch, content):
    path = tmp_path / "credentials"
    path.write_text(content)
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(path))
    return path


def test_sdk_metadata_excludes_secrets_and_resolves_session(tmp_path, monkeypatch):
    write_profiles(tmp_path, monkeypatch, """
[basic]
ak = secret-ak
sk = secret-sk
[basic.dev]
project_id = p
region = ap-southeast-1
[sso-session corp]
sso_start_url = https://idcenter.huaweicloud.com/corp/portal
sso_region = ap-southeast-1
[sso.prod]
sso_session = corp
account_id = account
permission_set_name = Audit
""")
    catalog = load_profiles()
    assert set(catalog) == {"basic", "dev", "prod"}
    assert catalog["prod"]["sso_region"] == "ap-southeast-1"
    assert catalog["prod"]["session_name"] == "sdk:corp"
    assert "secret-ak" not in json.dumps(catalog) and "secret-sk" not in json.dumps(catalog)
    validate_sso_profile(catalog["prod"])


@pytest.mark.parametrize("content", ["[basic.same]\n[sso.same]\n", "[basic.all]\n", "[sso.]\n", "[bad\nSECRET"])
def test_invalid_profile_file_sanitized(tmp_path, monkeypatch, content):
    write_profiles(tmp_path, monkeypatch, content)
    with pytest.raises(HuaweiAuthError) as error:
        load_profiles()
    assert "SECRET" not in str(error.value)


def test_missing_file_and_bad_source(tmp_path, monkeypatch):
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(tmp_path / "absent"))
    assert load_profiles() == {}
    with pytest.raises(ValueError, match="profile_source"):
        load_profiles("unknown")


def test_koocli_metadata_only_and_no_login():
    data = {"profiles": [dict(name="static", mode="AKSK", secretAccessKey="UNEXPECTED-SECRET"),
        dict(name="sso", mode="SSO", region="ap-southeast-1", projectId="project",
             ssoParam=dict(startUrl="https://idcenter.huaweicloud.com/corp/portal", ssoRegion="ap-southeast-1"),
             ssoAuth=dict(accessTokenResult={"accessToken": "SECRET"}, accountId="account", agencyUrn="urn"))]}
    with patch("dredge.huawei_ir.profiles.shutil.which", return_value="/opt/bin/hcloud"), patch(
        "dredge.huawei_ir.profiles.subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(data))) as run:
        catalog = load_profiles("koocli")
    assert list(catalog) == ["sso"]
    assert catalog["sso"]["session_name"] == "koocli:sso"
    assert "SECRET" not in json.dumps(catalog)
    assert run.call_args.args[0] == ["/opt/bin/hcloud", "configure", "list", "--cli-output=json"]
    assert run.call_args.kwargs["capture_output"] is True
    assert run.call_args.kwargs["timeout"] == 20


def test_koocli_missing_and_errors_sanitized():
    with patch("dredge.huawei_ir.profiles.shutil.which", return_value=None):
        with pytest.raises(HuaweiAuthError, match="hcloud on PATH"):
            load_profiles("koocli")
    with patch("dredge.huawei_ir.profiles.shutil.which", return_value="/opt/hcloud"), patch(
        "dredge.huawei_ir.profiles.subprocess.run", side_effect=RuntimeError("SECRET")):
        with pytest.raises(HuaweiAuthError) as error:
            load_profiles("koocli")
        assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("changes", [{"account_id": "****"}, {"account_id": None},
    {"agency_urn": "also-urn"}, {"sso_start_url": "http://insecure.invalid"}, {"sso_region": "invalid"}])
def test_sso_selectors_required_and_unambiguous(changes):
    profile = dict(sso_start_url="https://idcenter.huaweicloud.com/corp/portal", sso_region="ap-southeast-1",
                   account_id="account", permission_set_name="Audit")
    with pytest.raises(HuaweiAuthError):
        validate_sso_profile({**profile, **changes})


def discovery(projects, **page_extra):
    value = object.__new__(IamDiscovery)
    value.call = MagicMock(side_effect=[{"regions": [{"id": "ap-southeast-1"}, {"id": "cn-north-4"}]},
                                       {"projects": projects, **page_extra}])
    return value


def test_region_project_mapping_subprojects_and_account_guard():
    iam = discovery([
        dict(id="p1", name="ap-southeast-1", domain_id="a"),
        dict(id="p2", name="ap-southeast-1_team", domain_id="a"),
        dict(id="p3", name="cn-north-4", domain_id="a", enabled=False),
        dict(id="p4", name="cn-north-4", domain_id="other"),
        dict(id="p5", name="custom-unmapped", domain_id="a"),
        dict(id="domain", name="a", domain_id="a", is_domain=True),
    ])
    scopes, skipped = iam.scopes(regions="all", account_id="a")
    assert [s["project_id"] for s in scopes] == ["p1", "p2"]
    assert {s["reason"] for s in skipped} == {"project_account_mismatch", "project_region_or_account_unresolved"}


def test_region_filter_and_explicit_project_validation():
    iam = discovery([dict(id="p1", name="ap-southeast-1", domain_id="a"), dict(id="p2", name="cn-north-4", domain_id="a")])
    assert [s["project_id"] for s in iam.scopes(regions=["cn-north-4"])[0]] == ["p2"]
    iam.call.side_effect = [{"regions": [{"id": "cn-north-4"}]},
                            {"project": dict(id="p1", name="cn-north-4", domain_id="a")}]
    assert iam.scopes(project_id="p1", account_id="a")[0][0]["region"] == "cn-north-4"
    assert iam.call.call_args.args[0] == "keystone_show_project"


@pytest.mark.parametrize("scenario", ["region", "empty", "pagination", "mismatch"])
def test_discovery_never_silently_falls_back(scenario):
    iam = discovery([] if scenario == "empty" else [dict(id="p", name="cn-north-4", domain_id="other")],
                    **({"links": {"next": "https://untrusted.invalid/next"}} if scenario == "pagination" else {}))
    with pytest.raises(HuaweiAuthError):
        iam.scopes(regions=["ap-southeast-99"] if scenario == "region" else "all", account_id="a")


def test_real_iam_sdk_requests_refresh_credentials_without_domain_lookup():
    pytest.importorskip("huaweicloudsdkiam")
    from huaweicloudsdkcore.auth.credentials import BasicCredentials
    credentials = BasicCredentials("old-ak", "sk").with_security_token("old-token")
    def refresh(http):
        credentials.with_ak("new-ak").with_security_token("new-token")
    with patch.object(credentials, "process_sts", side_effect=refresh) as refresh_mock, patch(
        "huaweicloudsdkcore.client.Client.do_http_request", return_value=SimpleNamespace(to_json_object=lambda: {})) as call:
        iam = IamDiscovery(lambda: credentials)
        call.assert_not_called()
        for operation in ("keystone_list_auth_projects", "keystone_list_regions"):
            iam.call(operation)
        iam.call("keystone_show_project", project_id="p1")
        assert call.call_count == 3 and refresh_mock.call_count == 3
        assert iam.client.get_credentials().ak == "new-ak"
        assert iam.client.get_credentials().security_token == "new-token"
        assert call.call_args.kwargs["path_params"]["project_id"] == "p1"
