from __future__ import annotations

from ..config import DredgeConfig
from .config import K8sAuthConfig
from .services import K8sClientFactory, K8sServiceRegistry
from .response import K8sIRResponse
from .forensics import K8sIRForensics
from .hunt import K8sIRHunt


class K8sIRNamespace:
    """
    Grouping for Kubernetes Incident Response functionality.

        dredge.k8s_ir.hunt.list_events(...)
        dredge.k8s_ir.response.quarantine_pod(...)
        dredge.k8s_ir.forensics.get_pod_manifest(...)
    """

    def __init__(self, config: K8sAuthConfig, dredge_config: DredgeConfig) -> None:
        api_client = K8sClientFactory(config).get_api_client()
        self._services = K8sServiceRegistry(api_client)
        self.response = K8sIRResponse(self._services, dredge_config)
        self.forensics = K8sIRForensics(self._services, dredge_config)
        self.hunt = K8sIRHunt(self._services, dredge_config)
