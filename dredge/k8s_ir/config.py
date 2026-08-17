from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


TokenProvider = Callable[[], str]


@dataclass
class K8sAuthConfig:
    """
    Defines how Dredge should authenticate to a Kubernetes cluster.

    Precedence (if multiple fields are set):
      1) Explicit bearer token / token_provider (+ api_server, ca_cert_file)
      2) in_cluster=True (mounted service account token)
      3) kubeconfig_path / context ("auth like kubectl")
      4) Default: try in-cluster config, fall back to default kubeconfig location

    token_provider (if set) is re-invoked before EVERY API call via the
    kubernetes client's refresh_api_key_hook -- there is no dredge-side
    caching of the returned token. Callers who need caching (e.g. because
    their provider does a slow network call) should implement it inside
    their own callable.
    """
    # Explicit service-account / bearer-token auth
    token: Optional[str] = None
    token_provider: Optional[TokenProvider] = None
    api_server: Optional[str] = None
    ca_cert_file: Optional[str] = None
    verify_ssl: bool = True

    # In-cluster (mounted service account token)
    in_cluster: bool = False

    # Kubeconfig-based auth
    kubeconfig_path: Optional[str] = None
    context: Optional[str] = None

    # Default namespace for namespaced operations when a caller omits one
    namespace: Optional[str] = None
