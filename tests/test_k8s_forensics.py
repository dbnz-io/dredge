from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.exceptions import ApiException

from dredge.k8s_ir.forensics import K8sIRForensics
from dredge.config import DredgeConfig


def make_services():
    return MagicMock()


def make_api_exception(status=403, reason="Forbidden"):
    return ApiException(status=status, reason=reason)


def obj(**kwargs):
    return SimpleNamespace(**kwargs)


class TestGetPodManifest:
    def test_happy_path(self):
        services = make_services()
        pod = MagicMock()
        pod.to_dict.return_value = {"metadata": {"name": "p"}}
        services.core_v1.read_namespaced_pod.return_value = pod

        result = K8sIRForensics(services, DredgeConfig()).get_pod_manifest("ns", "p")

        assert result.success is True
        assert result.details["manifest"] == {"metadata": {"name": "p"}}

    def test_error(self):
        services = make_services()
        services.core_v1.read_namespaced_pod.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).get_pod_manifest("ns", "p")
        assert result.success is False


class TestGetPodLogs:
    def test_happy_path_default_kwargs(self):
        services = make_services()
        services.core_v1.read_namespaced_pod_log.return_value = "log line 1\nlog line 2"

        result = K8sIRForensics(services, DredgeConfig()).get_pod_logs("ns", "p")

        assert result.success is True
        assert result.details["logs"] == "log line 1\nlog line 2"
        services.core_v1.read_namespaced_pod_log.assert_called_once_with("p", "ns", previous=False)

    def test_container_and_tail_lines_forwarded(self):
        services = make_services()
        K8sIRForensics(services, DredgeConfig()).get_pod_logs(
            "ns", "p", container="sidecar", previous=True, tail_lines=50,
        )
        services.core_v1.read_namespaced_pod_log.assert_called_once_with(
            "p", "ns", previous=True, container="sidecar", tail_lines=50,
        )

    def test_error(self):
        services = make_services()
        services.core_v1.read_namespaced_pod_log.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).get_pod_logs("ns", "p")
        assert result.success is False


class TestGetPodEvents:
    def test_happy_path(self):
        services = make_services()
        ev = MagicMock()
        ev.to_dict.return_value = {"reason": "Killing"}
        services.core_v1.list_namespaced_event.return_value = obj(items=[ev])

        result = K8sIRForensics(services, DredgeConfig()).get_pod_events("ns", "p")

        assert result.success is True
        assert result.details["events"] == [{"reason": "Killing"}]
        services.core_v1.list_namespaced_event.assert_called_once_with(
            "ns", field_selector="involvedObject.kind=Pod,involvedObject.name=p,involvedObject.namespace=ns",
        )

    def test_error(self):
        services = make_services()
        services.core_v1.list_namespaced_event.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).get_pod_events("ns", "p")
        assert result.success is False


class TestDescribeNode:
    def test_happy_path(self):
        services = make_services()
        node = MagicMock()
        node.to_dict.return_value = {"metadata": {"name": "n"}}
        services.core_v1.read_node.return_value = node

        result = K8sIRForensics(services, DredgeConfig()).describe_node("n")

        assert result.success is True
        assert result.details["manifest"] == {"metadata": {"name": "n"}}

    def test_error(self):
        services = make_services()
        services.core_v1.read_node.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).describe_node("n")
        assert result.success is False


class TestCaptureWorkloadManifest:
    @pytest.mark.parametrize("kind,attr", [
        ("deployment", "read_namespaced_deployment"),
        ("statefulset", "read_namespaced_stateful_set"),
        ("daemonset", "read_namespaced_daemon_set"),
    ])
    def test_happy_path(self, kind, attr):
        services = make_services()
        manifest = MagicMock()
        manifest.to_dict.return_value = {"metadata": {"name": "w"}}
        getattr(services.apps_v1, attr).return_value = manifest

        result = K8sIRForensics(services, DredgeConfig()).capture_workload_manifest(kind, "ns", "w")

        assert result.success is True
        assert result.details["manifest"] == {"metadata": {"name": "w"}}
        getattr(services.apps_v1, attr).assert_called_once_with("w", "ns")

    def test_unsupported_kind(self):
        services = make_services()
        result = K8sIRForensics(services, DredgeConfig()).capture_workload_manifest("bogus", "ns", "w")
        assert result.success is False
        assert "Unsupported kind" in result.errors[0]

    def test_api_error(self):
        services = make_services()
        services.apps_v1.read_namespaced_deployment.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).capture_workload_manifest("deployment", "ns", "w")
        assert result.success is False


class TestListPodsOnNode:
    def test_happy_path(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.return_value = obj(items=[
            obj(metadata=obj(namespace="ns", name="p1"), status=obj(phase="Running")),
        ])

        result = K8sIRForensics(services, DredgeConfig()).list_pods_on_node("n")

        assert result.success is True
        assert result.details["pods"] == [{"namespace": "ns", "name": "p1", "phase": "Running"}]
        assert result.details["statistics"]["total_pods"] == 1
        services.core_v1.list_pod_for_all_namespaces.assert_called_once_with(field_selector="spec.nodeName=n")

    def test_error(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.side_effect = make_api_exception()
        result = K8sIRForensics(services, DredgeConfig()).list_pods_on_node("n")
        assert result.success is False


class TestExecPodCommand:
    def test_happy_path(self):
        services = make_services()
        with patch("dredge.k8s_ir.forensics.stream", return_value="ps output") as mock_stream:
            result = K8sIRForensics(services, DredgeConfig()).exec_pod_command(
                "ns", "p", ["ps", "aux"], container="app",
            )

        assert result.success is True
        assert result.details["output"] == "ps output"
        assert result.details["command"] == ["ps", "aux"]
        mock_stream.assert_called_once()
        args, kwargs = mock_stream.call_args
        assert args[0] is services.core_v1.connect_get_namespaced_pod_exec
        assert args[1] == "p"
        assert args[2] == "ns"
        assert kwargs["container"] == "app"
        assert kwargs["command"] == ["ps", "aux"]

    def test_error(self):
        services = make_services()
        with patch("dredge.k8s_ir.forensics.stream", side_effect=make_api_exception()):
            result = K8sIRForensics(services, DredgeConfig()).exec_pod_command("ns", "p", ["ls"])
        assert result.success is False
