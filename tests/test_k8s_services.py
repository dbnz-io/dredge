from unittest.mock import MagicMock

import pytest
from kubernetes import client as k8s_client

from dredge.k8s_ir.services import K8sServiceRegistry


def make_registry():
    api_client = MagicMock()
    return K8sServiceRegistry(api_client), api_client


class TestK8sServiceRegistry:
    def test_core_v1_lazy_loaded(self):
        reg, api_client = make_registry()
        core = reg.core_v1
        assert isinstance(core, k8s_client.CoreV1Api)
        assert core.api_client is api_client

    def test_core_v1_cached_on_second_access(self):
        reg, _ = make_registry()
        c1 = reg.core_v1
        c2 = reg.core_v1
        assert c1 is c2

    @pytest.mark.parametrize(
        "prop_name,api_cls",
        [
            ("apps_v1", k8s_client.AppsV1Api),
            ("rbac_v1", k8s_client.RbacAuthorizationV1Api),
            ("networking_v1", k8s_client.NetworkingV1Api),
        ],
    )
    def test_lazy_loaded(self, prop_name, api_cls):
        reg, api_client = make_registry()
        instance = getattr(reg, prop_name)
        assert isinstance(instance, api_cls)
        assert instance.api_client is api_client

    @pytest.mark.parametrize("prop_name", ["apps_v1", "rbac_v1", "networking_v1"])
    def test_cached_on_second_access(self, prop_name):
        reg, _ = make_registry()
        c1 = getattr(reg, prop_name)
        c2 = getattr(reg, prop_name)
        assert c1 is c2
