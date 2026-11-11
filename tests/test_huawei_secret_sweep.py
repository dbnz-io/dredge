import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir.auth import HuaweiAuthError
from dredge.huawei_ir.models import OperationResult
from dredge.huawei_ir.secret_sweep import hunt_exposed_secrets_multi_profile

pytest.importorskip("huaweicloudsdkidentitycenteroidc")
pytest.importorskip("huaweicloudsdkidentitycenterportalapi")
pytest.importorskip("huaweicloudsdkiam")

TOKEN = "ghp_" + "aB3cD4" * 6


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    path = tmp_path / "credentials"
    path.write_text("""
[sso-session corporate]
sso_start_url=https://idcenter.huaweicloud.com/corp/portal
sso_region=ap-southeast-1
[sso.prod]
sso_session=corporate
account_id=a
permission_set_name=Audit
[sso.dev]
sso_session=corporate
account_id=b
permission_set_name=Audit
""")
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("HUAWEICLOUD_SDK_PROJECT_ID", "unrelated-environment-project")
    monkeypatch.setenv("HUAWEICLOUD_SDK_AK", "unrelated-environment-ak")
    monkeypatch.setenv("HUAWEICLOUD_SDK_SK", "unrelated-environment-sk")
    return path


class MockHuawei:
    """One mocked HTTP boundary for the real SDK/auth/discovery/scan pipeline."""
    def __init__(self):
        self.calls = []
        self.denied_accounts = set()
        self.denied_projects = set()
        self.extra_project = False
        self.discovered_scopes = []

    def request(self, client, **request):
        operation = request["request_type"]
        self.calls.append(operation)
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
            account = query["account_id"]
            data = {"agency_list": [dict(account_id=account, agency_urn="iam::"+account+":agency:audit", permission_set_name="Audit")]}
        elif operation == "GetAgencyCredentialsRequest":
            account = query["target_account_id"]
            if account in self.denied_accounts:
                raise RuntimeError("SECRET server error with sensitive payload")
            data = {"agency_credentials": dict(access_key_id=account+"-ak", secret_access_key="agency-secret",
                     session_token="agency-token", expiration=time.time()+3600)}
        elif operation == "KeystoneListRegionsRequest":
            data = {"regions": [{"id": "ap-southeast-1"}, {"id": "cn-north-4"}]}
        elif operation == "KeystoneListAuthProjectsRequest":
            account = client.get_credentials().ak.split("-")[0]
            data = {"projects": [dict(id=account+"-p1", name="ap-southeast-1", domain_id=account),
                                  dict(id=account+"-p2", name="cn-north-4", domain_id=account)]}
            if self.extra_project:
                data["projects"].append(dict(id=account+"-p3", name="ap-southeast-1_team", domain_id=account))
        elif operation in ("ListFunctionsRequest", "ShowFunctionConfigRequest"):
            pid = client.get_credentials().project_id
            self.discovered_scopes.append((client.get_credentials().ak, pid))
            if pid in self.denied_projects:
                raise RuntimeError("SECRET project permission error")
            data = {"functions": [{"func_urn": "urn:function"}]} if operation == "ListFunctionsRequest" else {"user_data": json.dumps({"TOKEN": TOKEN})}
        else:
            raise AssertionError("Unexpected API request: " + operation)
        return SimpleNamespace(to_json_object=lambda: data, to_dict=lambda: data)


@pytest.fixture
def http():
    backend = MockHuawei()
    with patch("huaweicloudsdkcore.client.Client.do_http_request", autospec=True, side_effect=backend.request), patch(
        "dredge.huawei_ir.sso.time.sleep"):
        yield backend


def test_all_profiles_regions_shared_login_and_dedup(profiles, http, tmp_path):
    notify = MagicMock()
    result = hunt_exposed_secrets_multi_profile(regions="all", sso_login=True, include=["functiongraph"],
                                               cache_dir=tmp_path / "cache", notify=notify)
    assert result.success and result.details["complete"], result.errors
    assert http.calls.count("StartDeviceAuthorizationRequest") == 1
    assert http.calls.count("GetAgencyCredentialsRequest") == 2
    assert result.details["statistics"] == dict(profiles=2, authenticated_profiles=2, scope_scans=4, findings=1)
    sources = result.details["findings"][0]["sources"]
    assert {(s["profile"], s["account_id"], s["region"], s["project_id"]) for s in sources} == {
        ("dev", "b", "ap-southeast-1", "b-p1"), ("dev", "b", "cn-north-4", "b-p2"),
        ("prod", "a", "ap-southeast-1", "a-p1"), ("prod", "a", "cn-north-4", "a-p2")}
    assert all(pid.startswith(ak[0]+"-") for ak, pid in http.discovered_scopes)
    serialized = json.dumps(result.details)
    for secret in (TOKEN, "access-secret", "refresh-secret", "client-secret", "agency-secret", "agency-token", "unrelated-environment"):
        assert secret not in serialized
    # A second invocation reuses the persisted session without any interactive opt-in.
    result = hunt_exposed_secrets_multi_profile(regions="all", include=["functiongraph"], cache_dir=tmp_path / "cache", notify=notify)
    assert result.success and http.calls.count("StartDeviceAuthorizationRequest") == 1
    assert notify.call_count == 1


def test_partial_auth_failure_keeps_other_account_findings(profiles, http, tmp_path):
    http.denied_accounts.add("a")
    result = hunt_exposed_secrets_multi_profile(regions="all", sso_login=True, include=["functiongraph"], cache_dir=tmp_path)
    assert not result.success and not result.details["complete"]
    assert result.details["statistics"]["scope_scans"] == 2
    assert result.details["profiles"]["prod"]["errors"]
    assert not result.details["profiles"]["prod"]["authenticated"]
    assert len(result.details["findings"]) == 1
    assert "SECRET" not in json.dumps(result.details)


def test_project_permission_failure_is_isolated(profiles, http, tmp_path):
    http.denied_projects.add("a-p1")
    result = hunt_exposed_secrets_multi_profile(regions="all", sso_login=True, include=["functiongraph"], cache_dir=tmp_path)
    assert not result.success and not result.details["complete"]
    assert len({s["project_id"] for s in result.details["findings"][0]["sources"]}) == 3
    assert len(result.details["profiles"]["prod"]["scopes"]) == 2
    assert "SECRET" not in json.dumps(result.details)


def test_one_profile_expands_explicit_all_assigned_accounts(profiles, http, tmp_path):
    profiles.write_text(profiles.read_text().split("[sso.prod]")[0] + """
[sso.all-accounts]
sso_session=corporate
account_id=all
permission_set_name=all
""")
    result = hunt_exposed_secrets_multi_profile(profiles=["all-accounts"], regions="all", sso_login=True,
                                               include=["functiongraph"], keep_raw=True, cache_dir=tmp_path)
    assert result.success and result.details["statistics"]["scope_scans"] == 4
    assert len(result.details["raw_values"]) == 1
    assert TOKEN in result.details["raw_values"].values()


def test_no_login_optin_reports_profiles_without_prompt(profiles, http, tmp_path):
    result = hunt_exposed_secrets_multi_profile(regions="all", include=["functiongraph"], cache_dir=tmp_path)
    assert not result.success and not result.details["complete"]
    assert not http.calls
    assert all("--sso-login" in r["errors"][0] for r in result.details["profiles"].values())


def test_obs_once_per_account_not_per_project(profiles, http, tmp_path):
    http.extra_project = True
    with patch("dredge.huawei_ir.secret_sweep.HuaweiIRHunt.hunt_exposed_secrets", autospec=True, return_value=OperationResult(
        "hunt", "test", True, {"complete": True})) as hunt:
        result = hunt_exposed_secrets_multi_profile(regions=["ap-southeast-1"], project_id="all", sso_login=True,
            include=[], scan_obs=["obs://bucket/config/"], cache_dir=tmp_path)
    assert result.success and hunt.call_count == 2
    assert all(r["scopes"][0]["project_id"] is None for r in result.details["profiles"].values())


def test_incomplete_scan_status_and_inventory_are_preserved(profiles, http, tmp_path):
    with patch("dredge.huawei_ir.secret_sweep.HuaweiIRHunt.hunt_exposed_secrets", autospec=True, return_value=OperationResult(
        "hunt", "test", True, {"complete": False, "scanners": {"functiongraph": {"truncated": True}},
            "inventory": [{"hash": "hash", "assessment": "intended_secret_storage"}],
            "uninspected": [{"resource_id": "f", "reason": "encrypted"}]})):
        result = hunt_exposed_secrets_multi_profile(profiles="prod", regions="all", sso_login=True,
                                                   include=["functiongraph"], cache_dir=tmp_path)
    assert result.success and not result.details["complete"]
    assert {i["project_id"] for i in result.details["inventory"]} == {"a-p1", "a-p2"}
    assert all(i["profile"] == "prod" for i in result.details["uninspected"])


@pytest.mark.parametrize("options", [
    {"max_workers": 0}, {"max_workers": True}, {"max_workers": 33}, {"timeout": 0},
    {"include": ["bad"]}, {"include": ["cce"], "k8s_services": object()},
    {"scan_obs": ["obs://bucket/config/"], "regions": "all"},
    {"scan_obs": ["obs://bucket/"]}, {"scan_lts": ["group/stream"]},
    {"content_max_bytes": 0}, {"profiles": []}, {"profiles": ["prod", "all"]},
    {"regions": "https://bad.invalid"}, {"project_id": ""}, {"made_up": True},
])
def test_invalid_options_fail_before_any_auth(options):
    with patch("dredge.huawei_ir.secret_sweep.load_profiles") as load:
        with pytest.raises((ValueError, TypeError)):
            hunt_exposed_secrets_multi_profile(**options)
        load.assert_not_called()


def test_sdk_basic_credentials_discover_projects_without_prior_project(profiles, http, tmp_path):
    profiles.write_text("[basic.audit]\nak=a-ak\nsk=static-secret\n")
    result = hunt_exposed_secrets_multi_profile(regions="all", include=["functiongraph"], cache_dir=tmp_path)
    assert result.success and result.details["statistics"]["scope_scans"] == 2
    assert "ListAccountsRequest" not in http.calls
    assert all(pid.startswith("a-") for _, pid in http.discovered_scopes)


def test_failed_discovery_marks_basic_auth_incomplete(profiles):
    profiles.write_text("[basic.audit]\nak=a-ak\nsk=static-secret\n")
    with patch("dredge.huawei_ir.secret_sweep.IamDiscovery", side_effect=HuaweiAuthError("Discovery denied")):
        result = hunt_exposed_secrets_multi_profile(regions="all", include=["functiongraph"])
    assert not result.success and not result.details["complete"]
    assert not result.details["profiles"]["audit"]["authenticated"]


def test_independent_sso_sessions_login_separately(profiles, http, tmp_path):
    profiles.write_text("\n".join(
        f"[sso.{name}]\nsso_start_url=https://idcenter.huaweicloud.com/corp/portal\nsso_region=ap-southeast-1\n"
        f"account_id={account}\npermission_set_name=Audit\n" for name, account in (("prod", "a"), ("dev", "b"))))
    result = hunt_exposed_secrets_multi_profile(regions="all", sso_login=True, include=["functiongraph"], cache_dir=tmp_path)
    assert result.success and http.calls.count("StartDeviceAuthorizationRequest") == 2


def test_bounded_workers(profiles):
    import threading
    profiles.write_text("\n".join(f"[basic.p{i}]\nak=a-ak\nsk=sk\n" for i in range(4)))
    barrier, lock = threading.Barrier(2), threading.Lock()
    active, peak = 0, 0
    def scan(*args):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            barrier.wait(timeout=5)
            return [({"account_id": "a", "project_id": "p", "region": "ap-southeast-1"},
                     OperationResult("hunt", "p", True, {"complete": True}))], []
        finally:
            with lock:
                active -= 1
    with patch("dredge.huawei_ir.secret_sweep._scan_identity", side_effect=scan) as worker:
        result = hunt_exposed_secrets_multi_profile(regions="all", max_workers=2, include=["functiongraph"])
    assert result.success and worker.call_count == 4 and peak == 2
