from __future__ import annotations

from typing import Any, Dict, List, Optional

from kubernetes.client.exceptions import ApiException
from kubernetes.stream import stream

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import K8sServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)

_WORKLOAD_READERS = {
    "deployment": lambda apps, namespace, name: apps.read_namespaced_deployment(name, namespace),
    "statefulset": lambda apps, namespace, name: apps.read_namespaced_stateful_set(name, namespace),
    "daemonset": lambda apps, namespace, name: apps.read_namespaced_daemon_set(name, namespace),
}


class K8sIRForensics:
    """
    Read-only evidence-capture actions.
    """

    def __init__(self, services: K8sServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def get_pod_manifest(self, namespace: str, name: str) -> OperationResult:
        """
        Capture the full spec + status of a pod.
        """
        result = OperationResult(
            operation="get_pod_manifest",
            target=f"namespace={namespace},pod={name}",
            success=True,
        )

        try:
            pod = self._services.core_v1.read_namespaced_pod(name, namespace)
            result.details["manifest"] = pod.to_dict()
            _log.info(event("k8s_ir_forensics", "get_pod_manifest.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "get_pod_manifest.error", target=result.target, error=str(exc)))

        return result

    def get_pod_logs(
        self,
        namespace: str,
        name: str,
        *,
        container: Optional[str] = None,
        previous: bool = False,
        tail_lines: Optional[int] = None,
    ) -> OperationResult:
        """
        Capture container logs from a pod.
        """
        result = OperationResult(
            operation="get_pod_logs",
            target=f"namespace={namespace},pod={name}",
            success=True,
        )

        kwargs: Dict[str, Any] = {"previous": previous}
        if container:
            kwargs["container"] = container
        if tail_lines is not None:
            kwargs["tail_lines"] = tail_lines

        try:
            logs = self._services.core_v1.read_namespaced_pod_log(name, namespace, **kwargs)
            result.details["logs"] = logs
            _log.info(event("k8s_ir_forensics", "get_pod_logs.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "get_pod_logs.error", target=result.target, error=str(exc)))

        return result

    def get_pod_events(self, namespace: str, name: str) -> OperationResult:
        """
        List Events whose involvedObject is the given pod.
        """
        result = OperationResult(
            operation="get_pod_events",
            target=f"namespace={namespace},pod={name}",
            success=True,
        )

        try:
            field_selector = (
                f"involvedObject.kind=Pod,involvedObject.name={name},involvedObject.namespace={namespace}"
            )
            events = self._services.core_v1.list_namespaced_event(namespace, field_selector=field_selector)
            result.details["events"] = [e.to_dict() for e in events.items]
            _log.info(event("k8s_ir_forensics", "get_pod_events.success", target=result.target, count=len(events.items)))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "get_pod_events.error", target=result.target, error=str(exc)))

        return result

    def describe_node(self, name: str) -> OperationResult:
        """
        Capture the full manifest (spec, status, conditions) of a node.
        """
        result = OperationResult(
            operation="describe_node",
            target=f"node={name}",
            success=True,
        )

        try:
            node = self._services.core_v1.read_node(name)
            result.details["manifest"] = node.to_dict()
            _log.info(event("k8s_ir_forensics", "describe_node.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "describe_node.error", target=result.target, error=str(exc)))

        return result

    def capture_workload_manifest(self, kind: str, namespace: str, name: str) -> OperationResult:
        """
        Capture the full manifest of a workload controller before mutating it.

        kind must be one of: "deployment", "statefulset", "daemonset".
        """
        result = OperationResult(
            operation="capture_workload_manifest",
            target=f"kind={kind},namespace={namespace},name={name}",
            success=True,
        )

        reader = _WORKLOAD_READERS.get(kind)
        if reader is None:
            result.add_error(f"Unsupported kind for capture_workload_manifest: {kind!r}")
            return result

        try:
            manifest = reader(self._services.apps_v1, namespace, name)
            result.details["manifest"] = manifest.to_dict()
            _log.info(event("k8s_ir_forensics", "capture_workload_manifest.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "capture_workload_manifest.error", target=result.target, error=str(exc)))

        return result

    def list_pods_on_node(self, name: str) -> OperationResult:
        """
        List every pod currently scheduled to a node.
        """
        result = OperationResult(
            operation="list_pods_on_node",
            target=f"node={name}",
            success=True,
        )

        try:
            pods = self._services.core_v1.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={name}")
            result.details["pods"] = [
                {"namespace": p.metadata.namespace, "name": p.metadata.name, "phase": p.status.phase}
                for p in pods.items
            ]
            result.details["statistics"] = {"total_pods": len(pods.items)}
            _log.info(event("k8s_ir_forensics", "list_pods_on_node.success", target=result.target, count=len(pods.items)))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "list_pods_on_node.error", target=result.target, error=str(exc)))

        return result

    def exec_pod_command(
        self,
        namespace: str,
        name: str,
        command: List[str],
        *,
        container: Optional[str] = None,
    ) -> OperationResult:
        """
        Run a diagnostic command inside a running pod and capture its output.

        Best-effort: requires pod exec permission and a running, non-crashlooping
        container with a usable shell/binary on PATH. NOT a substitute for a
        real filesystem/memory forensic capture.
        """
        result = OperationResult(
            operation="exec_pod_command",
            target=f"namespace={namespace},pod={name}",
            success=True,
        )

        kwargs: Dict[str, Any] = {
            "command": command,
            "stderr": True,
            "stdin": False,
            "stdout": True,
            "tty": False,
        }
        if container:
            kwargs["container"] = container

        try:
            output = stream(
                self._services.core_v1.connect_get_namespaced_pod_exec,
                name,
                namespace,
                **kwargs,
            )
            result.details["output"] = output
            result.details["command"] = command
            _log.info(event("k8s_ir_forensics", "exec_pod_command.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_forensics", "exec_pod_command.error", target=result.target, error=str(exc)))

        return result
