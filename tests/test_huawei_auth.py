import builtins
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir.auth import HuaweiAuthError, HuaweiCredentialFactory
from dredge.huawei_ir.config import HuaweiAuthConfig
from dredge.huawei_ir.services import HuaweiServiceError, HuaweiServiceRegistry

sdk = pytest.importorskip("huaweicloudsdkcore")
from huaweicloudsdkcore.auth.credentials import BasicCredentials


def config(**kwargs):
    return HuaweiAuthConfig(region_name="cn-north-4", project_id="project", **kwargs)


@pytest.mark.parametrize("kwargs", [
    {"access_key_id": "AK"}, {"secret_access_key": "SK"}, {"security_token": "token"},
    {"access_key_id": "AK", "secret_access_key": "SK", "profile_name": "audit"},
    {"timeout": 0}, {"timeout": True},
])
def test_invalid_auth(kwargs):
    with pytest.raises(ValueError):
        config(**kwargs)


def test_region_and_project_env(monkeypatch):
    monkeypatch.setenv("HUAWEICLOUD_SDK_REGION", "cn-north-4")
    monkeypatch.setenv("HUAWEICLOUD_SDK_PROJECT_ID", "project")
    assert HuaweiAuthConfig().region_name == "cn-north-4"
    assert HuaweiAuthConfig().project_id == "project"
    with pytest.raises(ValueError):
        HuaweiAuthConfig(region_name="https://untrusted.invalid/path")


def test_explicit_keys_token_precede_environment(monkeypatch):
    monkeypatch.setenv("HUAWEICLOUD_SDK_AK", "environment-ak")
    monkeypatch.setenv("HUAWEICLOUD_SDK_SK", "environment-sk")
    cfg = config(access_key_id="explicit-ak", secret_access_key="explicit-sk", security_token="temporary-token")
    factory = HuaweiCredentialFactory(cfg)
    credentials = factory.get_credentials()
    assert credentials.ak == "explicit-ak"
    assert credentials.sk == "explicit-sk"
    assert credentials.security_token == "temporary-token"
    assert factory.get_credentials() is credentials
    assert "explicit-ak" not in repr(cfg)
    assert "explicit-sk" not in repr(cfg)
    assert "temporary-token" not in repr(cfg)


def test_environment_and_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("HUAWEICLOUD_SDK_AK", "environment-ak")
    monkeypatch.setenv("HUAWEICLOUD_SDK_SK", "environment-sk")
    assert HuaweiCredentialFactory(config()).get_credentials().ak == "environment-ak"
    path = tmp_path / "credentials"
    path.write_text("[basic.audit]\nak=profile-ak\nsk=profile-sk\nsecurity_token=session-token\nproject_id=profile-project\n")
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(path))
    monkeypatch.delenv("HUAWEICLOUD_SDK_PROJECT_ID", raising=False)
    credentials = HuaweiCredentialFactory(HuaweiAuthConfig(region_name="cn-north-4", profile_name="audit")).get_credentials()
    assert (credentials.ak, credentials.project_id, credentials.security_token) == ("profile-ak", "profile-project", "session-token")


def test_callback_is_reinvoked_and_errors_sanitized():
    callback = MagicMock(side_effect=[BasicCredentials("first", "sk", "project"), BasicCredentials("second", "sk", "project")])
    factory = HuaweiCredentialFactory(config(credential_provider=callback))
    assert factory.get_credentials().ak == "first"
    assert factory.get_credentials().ak == "second"
    callback.side_effect = RuntimeError("sensitive-token")
    with pytest.raises(HuaweiAuthError) as exc:
        factory.get_credentials()
    assert "sensitive-token" not in str(exc.value)
    callback.side_effect = None
    callback.return_value = object()
    with pytest.raises(HuaweiAuthError, match="BasicCredentials"):
        factory.get_credentials()


def test_project_required_without_discovery(monkeypatch):
    monkeypatch.delenv("HUAWEICLOUD_SDK_PROJECT_ID", raising=False)
    factory = HuaweiCredentialFactory(HuaweiAuthConfig(region_name="cn-north-4", access_key_id="ak", secret_access_key="sk"))
    with pytest.raises(HuaweiAuthError, match="project_id"):
        factory.get_credentials()


@pytest.mark.parametrize("service,operation,params", [
    ("functiongraph", "list_functions", {"marker": "0", "maxitems": "100"}),
    ("functiongraph", "show_function_config", {"function_urn": "urn"}),
    ("ecs", "list_servers_details", {"limit": 100, "marker": "id"}),
    ("ecs", "show_server", {"server_id": "id"}),
    ("cae", "list_environments", {"x_enterprise_project_id": "0"}),
    ("cae", "list_applications", {"x_environment_id": "env"}),
    ("cae", "list_components", {"application_id": "app", "x_environment_id": "env", "limit": "100", "offset": "0"}),
    ("cae", "list_component_configurations", {"application_id": "app", "component_id": "component", "x_environment_id": "env", "display_mode": "latestEffective"}),
    ("lts", "list_logs", {"log_group_id": "group", "log_stream_id": "stream", "body": {"start_time": "1", "end_time": "2", "limit": 100}}),
    ("csms", "show_secret_version", {"secret_name": "secret", "version_id": "latest"}),
])
def test_real_sdk_request_contract(service, operation, params):
    registry = HuaweiServiceRegistry(config(access_key_id="ak", secret_access_key="sk"))
    with patch("huaweicloudsdkcore.client.Client.do_http_request", return_value=SimpleNamespace(to_dict=lambda: {"ok": True})) as request:
        assert registry.call(service, operation, **params) == {"ok": True}
        assert request.call_count == 1
        client = registry._clients[service]
        assert client.get_credentials().project_id == "project"
        assert client._config.ignore_ssl_verification is False
        assert client._config.retry_times == 0
        if service == "lts":
            assert request.call_args.kwargs["body"].limit == 100


def test_sdk_error_body_never_returned():
    registry = HuaweiServiceRegistry(config(access_key_id="ak", secret_access_key="sk"))
    with patch("huaweicloudsdkcore.client.Client.do_http_request", side_effect=RuntimeError("SECRET")):
        with pytest.raises(HuaweiServiceError) as exc:
            registry.call("functiongraph", "list_functions")
        assert "SECRET" not in str(exc.value)


def test_obs_uses_rotating_credentials_and_verifies_tls():
    pytest.importorskip("obs")
    first = BasicCredentials("first", "sk", "project").with_security_token("token-one")
    second = BasicCredentials("second", "sk", "project").with_security_token("token-two")
    registry = HuaweiServiceRegistry(config(credential_provider=MagicMock(side_effect=[first, second])))
    with patch("obs.ObsClient") as obs:
        obs.return_value.listObjects.return_value = SimpleNamespace(status=200, body={})
        for _ in range(2):
            registry.obs_call("listObjects", bucketName="bucket", prefix="target/")
        assert obs.call_args.kwargs["ssl_verify"] is True
        assert obs.call_args.kwargs["max_retry_count"] == 0
        assert obs.return_value.refresh.call_args.args == ("second", "sk", "token-two")
        registry.close()
        obs.return_value.close.assert_called_once()


def test_obs_refresh_and_range_header():
    pytest.importorskip("obs")
    credential = BasicCredentials("old", "sk", "project")
    def refresh(http):
        credential.with_ak("fresh").with_security_token("fresh-token")
    registry = HuaweiServiceRegistry(config(credential_provider=lambda: credential))
    with patch.object(credential, "process_sts", side_effect=refresh) as refresh_mock, patch("obs.ObsClient") as obs:
        obs.return_value.getObject.return_value = SimpleNamespace(status=206)
        registry.obs_call("getObject", bucketName="bucket", objectKey="path", headers={"range": "0-99", "if_match": "etag"})
        assert refresh_mock.call_count == 1
        obs.return_value.refresh.assert_called_once_with("fresh", "sk", "fresh-token")
        assert obs.return_value.getObject.call_args.kwargs["headers"].range == "0-99"
        obs.return_value.getObject.return_value = SimpleNamespace(status=403, errorMessage="SECRET")
        with pytest.raises(HuaweiServiceError, match="HTTP 403") as exc:
            registry.obs_call("getObject", bucketName="bucket", objectKey="path")
        assert "SECRET" not in str(exc.value)


def test_missing_extra_gives_actionable_message():
    original = builtins.__import__
    def without_sdk(name, *args, **kwargs):
        if name.startswith("huaweicloudsdk"):
            raise ImportError("missing optional dependency")
        return original(name, *args, **kwargs)
    with patch("builtins.__import__", side_effect=without_sdk):
        with pytest.raises(HuaweiAuthError, match="dredge-ir\\[huawei\\]"):
            HuaweiCredentialFactory(config()).get_credentials()
