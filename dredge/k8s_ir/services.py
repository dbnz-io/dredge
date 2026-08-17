from __future__ import annotations

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

from .config import K8sAuthConfig


class K8sClientFactory:
    """
    Responsible for building a kubernetes.client.ApiClient according to
    K8sAuthConfig.

    - If an explicit token / token_provider is given: authenticate directly
      against api_server with that bearer token, no kubeconfig involved.
    - Else if in_cluster=True: use the mounted service account token.
    - Else if kubeconfig_path / context is given: load that kubeconfig
      ("auth like kubectl" -- this is where cloud-specific exec plugins
      such as `aws eks get-token` / `gke-gcloud-auth-plugin` are resolved,
      entirely outside dredge's knowledge).
    - Else: try in-cluster config, falling back to the default kubeconfig
      location.
    """

    def __init__(self, auth_config: K8sAuthConfig) -> None:
        self._auth_config = auth_config

    def get_api_client(self) -> client.ApiClient:
        configuration = self._build_configuration()
        return client.ApiClient(configuration)

    # ------------ internal helpers ------------

    def _build_configuration(self) -> client.Configuration:
        cfg = self._auth_config

        if cfg.token or cfg.token_provider:
            return self._build_token_configuration()

        configuration = client.Configuration()

        if cfg.in_cluster:
            config.load_incluster_config(client_configuration=configuration)
            return configuration

        if cfg.kubeconfig_path or cfg.context:
            config.load_kube_config(
                config_file=cfg.kubeconfig_path,
                context=cfg.context,
                client_configuration=configuration,
            )
            return configuration

        # Default: try in-cluster, fall back to default kubeconfig location.
        try:
            config.load_incluster_config(client_configuration=configuration)
        except ConfigException:
            config.load_kube_config(client_configuration=configuration)

        return configuration

    def _build_token_configuration(self) -> client.Configuration:
        cfg = self._auth_config
        configuration = client.Configuration()

        configuration.host = cfg.api_server
        configuration.verify_ssl = cfg.verify_ssl
        if cfg.ca_cert_file:
            configuration.ssl_ca_cert = cfg.ca_cert_file

        configuration.api_key_prefix["BearerToken"] = "Bearer"

        if cfg.token_provider:
            token_provider = cfg.token_provider

            def _refresh(config_to_update: client.Configuration) -> None:
                # Always re-invoked before every request (no dredge-side
                # caching) -- see K8sAuthConfig's docstring for rationale.
                config_to_update.api_key["BearerToken"] = token_provider()

            configuration.refresh_api_key_hook = _refresh
        else:
            configuration.api_key["BearerToken"] = cfg.token

        return configuration


class K8sServiceRegistry:
    """
    Central place to create and share typed Kubernetes API clients.
    """

    def __init__(self, api_client: client.ApiClient) -> None:
        self._api_client = api_client

        # Lazily initialized clients
        self._core_v1 = None
        self._apps_v1 = None
        self._rbac_v1 = None
        self._networking_v1 = None

    @property
    def core_v1(self) -> client.CoreV1Api:
        if self._core_v1 is None:
            self._core_v1 = client.CoreV1Api(self._api_client)
        return self._core_v1

    @property
    def apps_v1(self) -> client.AppsV1Api:
        if self._apps_v1 is None:
            self._apps_v1 = client.AppsV1Api(self._api_client)
        return self._apps_v1

    @property
    def rbac_v1(self) -> client.RbacAuthorizationV1Api:
        if self._rbac_v1 is None:
            self._rbac_v1 = client.RbacAuthorizationV1Api(self._api_client)
        return self._rbac_v1

    @property
    def networking_v1(self) -> client.NetworkingV1Api:
        if self._networking_v1 is None:
            self._networking_v1 = client.NetworkingV1Api(self._api_client)
        return self._networking_v1
