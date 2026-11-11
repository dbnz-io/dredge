import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir.auth import HuaweiAuthError
from dredge.huawei_ir.sso import AgencyCredentialProvider, IdentityCenterApi, SsoApiError, SsoSession, TokenCache

pytest.importorskip("huaweicloudsdkidentitycenteroidc")
pytest.importorskip("huaweicloudsdkidentitycenterportalapi")

PROFILE = dict(sso_start_url="https://idcenter.huaweicloud.com/example/portal",
               sso_region="ap-southeast-1", session_name="corporate")


@pytest.fixture
def session(tmp_path):
    with patch("dredge.huawei_ir.sso.IdentityCenterApi") as api, patch("dredge.huawei_ir.sso.time.time", return_value=1000):
        s = SsoSession(PROFILE, cache_dir=tmp_path / "cache", notify=MagicMock())
        s.api = api.return_value
        yield s


def cached(session, expires=2000):
    session.data = {"access_token": "access-secret", "refresh_token": "refresh-secret", "expires_at": expires,
                    "client": {"client_id": "client", "client_secret": "client-secret", "client_secret_expires_at": 9999}}


def device_api(session, *poll_responses):
    def call(operation, **kwargs):
        if operation == "register_client":
            return {"client_info": {"client_id": "client", "client_secret": "client-secret", "client_secret_expires_at": 9999}}
        if operation == "start_device_authorization":
            return dict(device_code="device-secret", user_code="USER-CODE", verification_uri="https://idcenter.huaweicloud.com/verify",
                        expires_in=600, interval=1)
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response
    responses = iter(poll_responses or [{"token_info": {"access_token": "new-access", "expires_in": 3600}}])
    session.api.oidc_call.side_effect = call


def test_device_pending_slowdown_then_success_and_private_cache(session):
    device_api(session, SsoApiError("token", "IIC.1608", 400), SsoApiError("token", "slow_down", 400),
               {"token_info": {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}})
    with patch("dredge.huawei_ir.sso.time.sleep") as sleep:
        assert session.token(allow_login=True) == "new-access"
    assert [c.args[0] for c in sleep.call_args_list] == [1, 1, 6]
    assert session.token() == "new-access"
    assert session.data["expires_at"] == 4600
    notice = session.notify.call_args.args[0]
    assert "USER-CODE" in notice and "device-secret" not in notice and "client-secret" not in notice
    assert session.cache.path.stat().st_mode & 0o777 == 0o600
    assert session.cache.directory.stat().st_mode & 0o777 == 0o700
    assert session.cache.read()["refresh_token"] == "new-refresh"


def test_cached_session_and_refresh_skip_login(session):
    cached(session)
    assert session.token() == "access-secret"
    session.api.oidc_call.assert_not_called()
    session.data["expires_at"] = 999
    session.api.oidc_call.return_value = {"token_info": {"access_token": "fresh", "expires_in": 4000}}
    assert session.token() == "fresh"
    assert session.api.oidc_call.call_args.kwargs["grant_type"] == "refresh_token"
    session.notify.assert_not_called()


def test_missing_session_does_not_prompt_without_optin(session):
    with pytest.raises(HuaweiAuthError, match="--sso-login"):
        session.token()
    session.api.oidc_call.assert_not_called()


def test_refresh_rejection_reauth_drops_previous_users_refresh_token(session):
    cached(session, expires=999)
    device_api(session, SsoApiError("token", "invalid_grant", 400),
               {"token_info": {"access_token": "different-user", "expires_in": 3600}})
    with patch("dredge.huawei_ir.sso.time.sleep"):
        assert session.token(allow_login=True) == "different-user"
    assert "refresh_token" not in session.data


def test_refresh_service_failure_does_not_prompt(session):
    cached(session, expires=999)
    session.api.oidc_call.side_effect = SsoApiError("token", "server_error", 500)
    with pytest.raises(SsoApiError, match="500"):
        session.token(allow_login=True)
    session.notify.assert_not_called()


def test_device_denial_only_prompts_once(session):
    device_api(session, SsoApiError("token", "IIC.1613", 404))
    with patch("dredge.huawei_ir.sso.time.sleep"):
        with pytest.raises(SsoApiError, match="IIC.1613"):
            session.token(allow_login=True)
    with pytest.raises(HuaweiAuthError, match="--sso-login"):
        session.token(allow_login=True)
    assert session.notify.call_count == 1


def test_device_timeout(session):
    device_api(session)
    with patch("dredge.huawei_ir.sso.time.monotonic", side_effect=[0, 601]):
        with pytest.raises(HuaweiAuthError, match="timed out"):
            session.token(allow_login=True)


def test_portal_unauthorized_refreshes_once(session):
    cached(session)
    session.api.portal_call.side_effect = [SsoApiError("list_accounts", "IIC.1604", 401), {"account_list": []}]
    session.api.oidc_call.return_value = {"token_info": {"access_token": "fresh", "expires_in": 3600}}
    assert session.call("list_accounts") == {"account_list": []}
    assert session.api.portal_call.call_args.args[1] == "fresh"
    assert session.api.portal_call.call_count == 2


def test_portal_forbidden_not_retried(session):
    cached(session)
    session.api.portal_call.side_effect = SsoApiError("list_accounts", "forbidden", 403)
    with pytest.raises(SsoApiError):
        session.call("list_accounts")
    session.api.oidc_call.assert_not_called()


def test_portal_pagination_stall_detected(session):
    cached(session)
    session.api.portal_call.side_effect = [
        {"account_list": [{"account_id": "a"}], "page_info": {"next_marker": "next"}},
        {"account_list": [{"account_id": "b"}], "page_info": {}},
    ]
    assert [a["account_id"] for a in session.pages("list_accounts", "account_list")] == ["a", "b"]
    assert session.api.portal_call.call_args.kwargs["marker"] == "next"
    session.api.portal_call.side_effect = None
    session.api.portal_call.return_value = {"page_info": {"next_marker": "same"}}
    with pytest.raises(HuaweiAuthError, match="stalled"):
        list(session.pages("list_accounts", "account_list"))


def test_agency_credentials_refresh_and_project_isolation(session):
    session.call = MagicMock(side_effect=[
        {"agency_credentials": dict(access_key_id="first", secret_access_key="sk", session_token="token", expiration=2000)},
        {"agency_credentials": dict(access_key_id="second", secret_access_key="sk", session_token="fresh-token", expiration=1900000000000)},
    ])
    provider = AgencyCredentialProvider(session, "account", "urn")
    first = provider("p1")
    assert provider("p2").project_id == "p2" and first.project_id == "p1"
    assert session.call.call_count == 1
    provider.value["expiration"] = 1100
    assert provider("p3").ak == "second"
    assert provider.value["expiration"] == 1900000000


def test_agency_missing_or_expired_credentials(session):
    session.call = MagicMock(return_value={})
    provider = AgencyCredentialProvider(session, "account", "urn")
    with pytest.raises(HuaweiAuthError, match="incomplete"):
        provider()
    session.call.return_value = {"agency_credentials": dict(access_key_id="ak", secret_access_key="sk", session_token="t", expiration=900)}
    with pytest.raises(HuaweiAuthError, match="expired"):
        provider()


def test_cache_rejects_symlinks_and_public_permissions(tmp_path):
    cache = TokenCache("key", tmp_path / "cache")
    cache.write({"access_token": "private"})
    os.chmod(cache.path, 0o644)
    with pytest.raises(HuaweiAuthError, match="securely"):
        cache.read()
    cache.path.unlink()
    other = tmp_path / "other"
    other.write_text("{}")
    cache.path.symlink_to(other)
    with pytest.raises(HuaweiAuthError):
        cache.read()
    link = tmp_path / "link"
    link.symlink_to(cache.directory, target_is_directory=True)
    with pytest.raises(HuaweiAuthError):
        TokenCache("key", link).write({})


def test_session_cache_identity_separation(tmp_path):
    with patch("dredge.huawei_ir.sso.IdentityCenterApi"):
        a = SsoSession(PROFILE, cache_dir=tmp_path)
        b = SsoSession({**PROFILE, "session_name": "other-user"}, cache_dir=tmp_path)
        c = SsoSession({**PROFILE, "sso_region": "cn-north-4"}, cache_dir=tmp_path)
        assert len({a.cache.path, b.cache.path, c.cache.path}) == 3


@pytest.mark.parametrize("operation,body", [
    ("register_client", dict(client_name="dredge-ir", client_type="public", token_endpoint_auth_method="client_secret_post",
                             scopes=["openid"], grant_types=["urn:ietf:params:oauth:grant-type:device_code"], response_types=["code"])),
    ("start_device_authorization", dict(client_id="id", client_secret="secret", start_url=PROFILE["sso_start_url"])),
    ("create_token", dict(client_id="id", client_secret="secret", grant_type="refresh_token", refresh_token="refresh")),
])
def test_real_oidc_request_contract(operation, body):
    api = IdentityCenterApi("ap-southeast-1")
    with patch("huaweicloudsdkcore.client.Client.do_http_request", return_value=SimpleNamespace(to_json_object=lambda: {})) as call:
        assert api.oidc_call(operation, **body) == {}
        request = call.call_args.kwargs
        assert all(getattr(request["body"], key) == value for key, value in body.items())
        assert api.oidc._config.ignore_ssl_verification is False
        assert api.oidc._config.retry_times == 0


@pytest.mark.parametrize("operation,kwargs", [
    ("list_accounts", dict(limit=100, marker="next")),
    ("list_account_agencies", dict(account_id="account", limit=100)),
    ("get_agency_credentials", dict(target_account_id="account", agency_urn="urn")),
])
def test_real_portal_request_contract(operation, kwargs):
    api = IdentityCenterApi("ap-southeast-1")
    with patch("huaweicloudsdkcore.client.Client.do_http_request", return_value=SimpleNamespace(to_json_object=lambda: {})) as call:
        api.portal_call(operation, "access-secret", **kwargs)
        assert call.call_args.kwargs["header_params"]["access-token"] == "access-secret"
        assert api.portal._endpoints == ["https://portal-identitycenter.myhuaweicloud.com"]


def test_api_error_never_returns_credential_body():
    api = IdentityCenterApi("cn-north-4")
    with patch("huaweicloudsdkcore.client.Client.do_http_request", side_effect=RuntimeError("SECRET")):
        with pytest.raises(SsoApiError) as error:
            api.portal_call("list_accounts", "access-secret")
        assert "SECRET" not in str(error.value) and "access-secret" not in str(error.value)


def test_sdk_response_preserves_tokens_and_keys_inside_auth_boundary():
    from huaweicloudsdkidentitycenteroidc.v1 import CreateTokenResponse, TokenInfoDto
    from huaweicloudsdkidentitycenterportalapi.v1 import GetAgencyCredentialsResponse, AgencyCredentials
    token = CreateTokenResponse(token_info=TokenInfoDto(access_token="real-access", expires_in=3600))
    token.raw_content = b'{"token_info":{"access_token":"real-access","expires_in":3600}}'
    credentials = GetAgencyCredentialsResponse(agency_credentials=AgencyCredentials(
        access_key_id="real-ak", secret_access_key="real-sk", session_token="real-st", expiration=1900000000))
    credentials.raw_content = json.dumps({"agency_credentials": dict(access_key_id="real-ak", secret_access_key="real-sk",
        session_token="real-st", expiration=1900000000)}).encode()
    api = IdentityCenterApi("ap-southeast-1")
    with patch("huaweicloudsdkcore.client.Client.do_http_request", side_effect=[token, credentials]):
        assert api.oidc_call("create_token", client_id="id", client_secret="secret", grant_type="refresh_token"
                            )["token_info"]["access_token"] == "real-access"
        assert api.portal_call("get_agency_credentials", "token", target_account_id="a", agency_urn="u"
                              )["agency_credentials"]["secret_access_key"] == "real-sk"
