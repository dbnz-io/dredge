import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir import HuaweiAuthConfig, HuaweiIRReview, review_multi_profile
from dredge.huawei_ir.services import HuaweiServiceRegistry
from dredge.huawei_ir.auth import HuaweiAuthError

pytest.importorskip("huaweicloudsdkrds")


@pytest.fixture
def credentials_file(tmp_path, monkeypatch):
    path = tmp_path / "credentials"
    path.write_text("""
[sso-session corp]
sso_start_url=https://idcenter.huaweicloud.com/corp/portal
sso_region=ap-southeast-1
[sso.audit]
sso_session=corp
account_id=all
permission_set_name=Audit
""")
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("HUAWEICLOUD_SDK_PROJECT_ID", "unrelated-environment-project")
    return path


class Boundary:
    def __init__(self):
        self.calls = []
        self.denied = set()

    def request(self, client, **request):
        operation = request["request_type"]
        creds = client.get_credentials()
        account = (getattr(creds, "ak", "") or "").split("-")[0]
        project = getattr(creds, "project_id", None)
        self.calls.append((operation, account, project))
        if operation in self.denied or project in self.denied:
            raise RuntimeError("NEVER-EXPORT-SECRET")
        query = dict(request["query_params"])
        if operation == "RegisterClientRequest":
            data = {"client_info": dict(client_id="id", client_secret="client-secret", client_secret_expires_at=time.time()+10000)}
        elif operation == "StartDeviceAuthorizationRequest":
            data = dict(device_code="device-secret", user_code="CODE", verification_uri="https://idcenter.huaweicloud.com/verify", expires_in=600, interval=1)
        elif operation == "CreateTokenRequest":
            data = {"token_info": dict(access_token="access-secret", refresh_token="refresh-secret", expires_in=3600)}
        elif operation == "ListAccountsRequest":
            data = {"account_list": [dict(account_id="a", account_name="Prod"), dict(account_id="b", account_name="Dev")]}
        elif operation == "ListAccountAgenciesRequest":
            data = {"agency_list": [dict(account_id=query["account_id"], agency_urn="iam::"+query["account_id"]+":agency:audit", permission_set_name="Audit")]}
        elif operation == "GetAgencyCredentialsRequest":
            data = {"agency_credentials": dict(access_key_id=query["target_account_id"]+"-ak", secret_access_key="agency-secret", session_token="agency-token", expiration=time.time()+3600)}
        elif operation == "KeystoneListRegionsRequest":
            data = {"regions": [{"id": "ap-southeast-1"}, {"id": "cn-north-4"}]}
        elif operation == "KeystoneListAuthProjectsRequest":
            data = {"projects": [dict(id=account+"-p1", name="ap-southeast-1", domain_id=account), dict(id=account+"-p2", name="cn-north-4", domain_id=account)]}
        elif operation == "KeystoneShowProjectRequest":
            data = {"project": dict(id=account+"-p1", domain_id=account, name="ap-southeast-1")}
        elif operation == "KeystoneListAuthDomainsRequest":
            data = {"domains": [{"id": account}]}
        elif operation == "ShowDomainPasswordPolicyRequest":
            data = {"password_policy": {"minimum_password_length": 6}}
        elif operation == "ListInstancesRequest":
            data = {"instances": [{"id": "db", "public_ips": ["203.0.113.1"]}], "total_count": 1}
        else:
            raise AssertionError(operation)
        return SimpleNamespace(to_json_object=lambda: data, to_dict=lambda: data)


@pytest.fixture
def http():
    backend = Boundary()
    with patch("huaweicloudsdkcore.client.Client.do_http_request", autospec=True, side_effect=backend.request), patch("dredge.huawei_ir.sso.time.sleep"):
        yield backend


def test_sso_global_once_per_identity_regional_per_project(credentials_file, http, tmp_path):
    notify = MagicMock()
    result = review_multi_profile(regions="all", sso_login=True, cache_dir=tmp_path / "cache", notify=notify,
                                 include=["iam-password-policy", "rds-public-instances"])
    assert result.success and result.details["complete"], result.details
    assert result.details["total_findings"] == 6
    operations = [c[0] for c in http.calls]
    assert operations.count("StartDeviceAuthorizationRequest") == 1
    assert operations.count("ShowDomainPasswordPolicyRequest") == 2
    assert operations.count("ListInstancesRequest") == 4
    assert len(result.details["checks"]["iam-password-policy"]["by_scope"]) == 2
    assert {f["project_id"] for f in result.details["findings"]} == {None, "a-p1", "a-p2", "b-p1", "b-p2"}
    assert all(f["agency_urn"] == "iam::"+f["account_id"]+":agency:audit" for f in result.details["findings"])
    assert all(project.startswith(account+"-") for operation, account, project in http.calls if operation == "ListInstancesRequest")
    assert "secret" not in json.dumps(result.details)
    # The second run uses the native cache and does not prompt.
    result = review_multi_profile(regions="all", cache_dir=tmp_path / "cache", include=["iam-password-policy"])
    assert result.success and notify.call_count == 1


def test_global_review_needs_no_region_or_project_discovery(credentials_file, http, tmp_path):
    http.denied.update(("KeystoneListRegionsRequest", "KeystoneListAuthProjectsRequest"))
    result = review_multi_profile(sso_login=True, cache_dir=tmp_path, include=["iam-password-policy"])
    assert result.success and result.details["complete"]
    assert result.details["total_findings"] == 2
    assert not any(c[0] in http.denied for c in http.calls)


@pytest.mark.parametrize("denied,count", [("a-p1", 5), ("KeystoneListRegionsRequest", 2), ("ShowDomainPasswordPolicyRequest", 4)])
def test_failure_isolation_preserves_other_scope_evidence(credentials_file, http, tmp_path, denied, count):
    http.denied.add(denied)
    result = review_multi_profile(regions="all", sso_login=True, cache_dir=tmp_path,
                                 include=["iam-password-policy", "rds-public-instances"])
    assert not result.success and not result.details["complete"]
    assert result.details["total_findings"] == count
    assert "NEVER-EXPORT" not in json.dumps(result.details)


def test_explicit_library_credentials_multi_region_and_thresholds(http, monkeypatch):
    monkeypatch.delenv("HUAWEICLOUD_SDK_PROJECT_ID", raising=False)
    cfg = HuaweiAuthConfig(region_name="cn-north-4", access_key_id="a-ak", secret_access_key="sk", timeout=8)
    result = HuaweiIRReview(HuaweiServiceRegistry(cfg)).review(regions="all", include=["iam-password-policy", "rds-public-instances"], min_password_length=15)
    assert result.success and result.details["total_findings"] == 3
    assert result.details["meta"]["thresholds"]["min_password_length"] == 15
    assert result.details["profiles"]["default-chain"]["authenticated"]


def test_default_chain_respects_environment_project(http, monkeypatch):
    monkeypatch.setenv("HUAWEICLOUD_SDK_AK", "a-ak")
    monkeypatch.setenv("HUAWEICLOUD_SDK_SK", "sk")
    monkeypatch.setenv("HUAWEICLOUD_SDK_REGION", "ap-southeast-1")
    monkeypatch.setenv("HUAWEICLOUD_SDK_PROJECT_ID", "a-p1")
    result = review_multi_profile(profiles=None, include=["rds-public-instances"])
    assert result.success and result.details["total_findings"] == 1
    assert any(c[0] == "KeystoneShowProjectRequest" for c in http.calls)
    assert not any(c[0] == "KeystoneListAuthProjectsRequest" for c in http.calls)


def test_failed_auth_does_not_attempt_review(credentials_file, http, tmp_path):
    result = review_multi_profile(regions="all", cache_dir=tmp_path, include=["rds-public-instances"])
    assert not result.success and not result.details["complete"]
    assert not http.calls
    assert "--sso-login" in json.dumps(result.details)


@pytest.mark.parametrize("options", [
    {"max_workers": 0}, {"max_workers": True}, {"timeout": 0}, {"profiles": []},
    {"regions": "not_a_region"}, {"project_id": ""}, {"include": ["bad"]}, {"include": []},
    {"services": ["rds"], "include": ["iam-password-policy"]}, {"auth": object()},
])
def test_invalid_selection_before_auth(options):
    with patch("dredge.huawei_ir.review_sweep.load_profiles") as load:
        with pytest.raises(ValueError):
            review_multi_profile(**options)
        load.assert_not_called()
