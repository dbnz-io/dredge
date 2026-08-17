from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client as k8s_client
from kubernetes.config.config_exception import ConfigException

from dredge.k8s_ir.config import K8sAuthConfig
from dredge.k8s_ir.services import K8sClientFactory


class TestTokenAuth:
    def test_static_token_sets_api_key(self):
        cfg = K8sAuthConfig(
            token="my-token",
            api_server="https://cluster.example.com",
            ca_cert_file="/tmp/ca.pem",
            verify_ssl=False,
        )
        configuration = K8sClientFactory(cfg)._build_configuration()

        assert configuration.host == "https://cluster.example.com"
        assert configuration.verify_ssl is False
        assert configuration.ssl_ca_cert == "/tmp/ca.pem"
        assert configuration.api_key["BearerToken"] == "my-token"
        assert configuration.refresh_api_key_hook is None

    def test_static_token_takes_precedence_over_kubeconfig(self):
        cfg = K8sAuthConfig(
            token="my-token",
            api_server="https://cluster.example.com",
            kubeconfig_path="/should/be/ignored",
        )
        with patch("dredge.k8s_ir.services.config.load_kube_config") as mock_load:
            configuration = K8sClientFactory(cfg)._build_configuration()

        mock_load.assert_not_called()
        assert configuration.api_key["BearerToken"] == "my-token"

    def test_token_provider_is_reinvoked_every_call(self):
        provider = MagicMock(side_effect=["token-1", "token-2", "token-3"])
        cfg = K8sAuthConfig(token_provider=provider, api_server="https://cluster.example.com")
        configuration = K8sClientFactory(cfg)._build_configuration()

        assert configuration.refresh_api_key_hook is not None

        configuration.get_api_key_with_prefix("BearerToken", alias="authorization")
        configuration.get_api_key_with_prefix("BearerToken", alias="authorization")
        configuration.get_api_key_with_prefix("BearerToken", alias="authorization")

        assert provider.call_count == 3
        assert configuration.api_key["BearerToken"] == "token-3"

    def test_token_provider_no_dredge_side_caching(self):
        # Even a single get_api_key_with_prefix call re-invokes the provider --
        # there is no cached "still valid" check performed by dredge itself.
        provider = MagicMock(return_value="fresh-token")
        cfg = K8sAuthConfig(token_provider=provider, api_server="https://cluster.example.com")
        configuration = K8sClientFactory(cfg)._build_configuration()

        configuration.get_api_key_with_prefix("BearerToken", alias="authorization")
        assert provider.call_count == 1
        configuration.get_api_key_with_prefix("BearerToken", alias="authorization")
        assert provider.call_count == 2


class TestInClusterAuth:
    def test_in_cluster_flag_loads_incluster_config(self):
        cfg = K8sAuthConfig(in_cluster=True)

        with patch("dredge.k8s_ir.services.config.load_incluster_config") as mock_load:
            configuration = K8sClientFactory(cfg)._build_configuration()

        mock_load.assert_called_once()
        assert mock_load.call_args.kwargs["client_configuration"] is configuration


class TestKubeconfigAuth:
    def test_kubeconfig_path_and_context_passed_through(self):
        cfg = K8sAuthConfig(kubeconfig_path="/home/user/.kube/config", context="prod-cluster")

        with patch("dredge.k8s_ir.services.config.load_kube_config") as mock_load:
            configuration = K8sClientFactory(cfg)._build_configuration()

        mock_load.assert_called_once_with(
            config_file="/home/user/.kube/config",
            context="prod-cluster",
            client_configuration=configuration,
        )

    def test_context_only_uses_default_kubeconfig_location(self):
        cfg = K8sAuthConfig(context="staging")

        with patch("dredge.k8s_ir.services.config.load_kube_config") as mock_load:
            K8sClientFactory(cfg)._build_configuration()

        assert mock_load.call_args.kwargs["config_file"] is None
        assert mock_load.call_args.kwargs["context"] == "staging"


class TestDefaultAuth:
    def test_default_tries_incluster_first(self):
        cfg = K8sAuthConfig()

        with patch("dredge.k8s_ir.services.config.load_incluster_config") as mock_incluster, \
             patch("dredge.k8s_ir.services.config.load_kube_config") as mock_kubeconfig:
            K8sClientFactory(cfg)._build_configuration()

        mock_incluster.assert_called_once()
        mock_kubeconfig.assert_not_called()

    def test_default_falls_back_to_kubeconfig_when_not_in_cluster(self):
        cfg = K8sAuthConfig()

        with patch(
            "dredge.k8s_ir.services.config.load_incluster_config",
            side_effect=ConfigException("not in cluster"),
        ), patch("dredge.k8s_ir.services.config.load_kube_config") as mock_kubeconfig:
            configuration = K8sClientFactory(cfg)._build_configuration()

        mock_kubeconfig.assert_called_once_with(client_configuration=configuration)


class TestGetApiClient:
    def test_returns_api_client_wrapping_configuration(self):
        cfg = K8sAuthConfig(token="tok", api_server="https://x")
        api_client = K8sClientFactory(cfg).get_api_client()

        assert isinstance(api_client, k8s_client.ApiClient)
        assert api_client.configuration.host == "https://x"
