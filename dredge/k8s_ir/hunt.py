from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from kubernetes.client.exceptions import ApiException

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import K8sServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)


class K8sIRHunt:
    """
    Hunt / search utilities over the standard Kubernetes API.

    v1 uses the built-in Events API only -- flavor-agnostic, no audit-log
    plumbing required. Cloud-specific audit log retrieval (EKS -> CloudWatch,
    GKE -> Cloud Logging) is out of scope here; compose with aws_ir.hunt /
    gcp_ir.hunt for that.
    """

    def __init__(self, services: K8sServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    # =====================
    # Events
    # =====================

    def list_events(
        self,
        *,
        namespace: Optional[str] = None,
        involved_object_kind: Optional[str] = None,
        involved_object_name: Optional[str] = None,
        reason: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 500,
        page_size: int = 100,
    ) -> OperationResult:
        """
        Search Kubernetes Events, optionally scoped to a namespace.

        involved_object_kind / involved_object_name are applied server-side
        via field_selector. reason, event_type, and the time window are
        applied client-side, since server-side support for them is
        inconsistent across API server versions -- mirrors the AWS hunt
        pattern of picking the most specific server-side filter and
        applying the rest client-side.
        """
        now = datetime.now(timezone.utc)
        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        target_bits = []
        if namespace:
            target_bits.append(f"namespace={namespace}")
        if involved_object_kind:
            target_bits.append(f"involved_object_kind={involved_object_kind}")
        if involved_object_name:
            target_bits.append(f"involved_object_name={involved_object_name}")
        if reason:
            target_bits.append(f"reason={reason}")
        target_bits.append(f"time={start_time.isoformat()}..{end_time.isoformat()}")

        result = OperationResult(operation="list_events", target=",".join(target_bits), success=True)

        field_selector_parts = []
        if involved_object_kind:
            field_selector_parts.append(f"involvedObject.kind={involved_object_kind}")
        if involved_object_name:
            field_selector_parts.append(f"involvedObject.name={involved_object_name}")
        field_selector = ",".join(field_selector_parts) or None

        core = self._services.core_v1
        events: List[Dict[str, Any]] = []
        continue_token: Optional[str] = None
        total_api_calls = 0

        try:
            while len(events) < max_events:
                kwargs: Dict[str, Any] = {"limit": min(page_size, max_events - len(events))}
                if field_selector:
                    kwargs["field_selector"] = field_selector
                if continue_token:
                    kwargs["_continue"] = continue_token

                if namespace:
                    resp = core.list_namespaced_event(namespace, **kwargs)
                else:
                    resp = core.list_event_for_all_namespaces(**kwargs)
                total_api_calls += 1

                for e in resp.items:
                    if len(events) >= max_events:
                        break

                    event_time = e.last_timestamp or e.event_time or e.first_timestamp
                    if event_time is not None and not (start_time <= event_time <= end_time):
                        continue
                    if reason and e.reason != reason:
                        continue
                    if event_type and e.type != event_type:
                        continue

                    events.append(self._normalize_event(e))

                continue_token = resp.metadata._continue
                if not continue_token or not resp.items:
                    break

        except ApiException as exc:
            result.add_error(f"Failed to list events: {exc}")
            _log.error(event("k8s_ir_hunt", "list_events.error", target=result.target, error=str(exc)))

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "api_calls": total_api_calls,
            "time_range": {"start_time": start_time.isoformat(), "end_time": end_time.isoformat()},
        }
        _log.info(event("k8s_ir_hunt", "list_events.complete", target=result.target, total=len(events)))
        return result

    @staticmethod
    def _normalize_event(e: Any) -> Dict[str, Any]:
        return {
            "namespace": e.metadata.namespace,
            "name": e.metadata.name,
            "reason": e.reason,
            "message": e.message,
            "type": e.type,
            "involved_object_kind": e.involved_object.kind if e.involved_object else None,
            "involved_object_name": e.involved_object.name if e.involved_object else None,
            "involved_object_namespace": e.involved_object.namespace if e.involved_object else None,
            "source_component": e.source.component if e.source else None,
            "first_timestamp": e.first_timestamp.isoformat() if e.first_timestamp else None,
            "last_timestamp": e.last_timestamp.isoformat() if e.last_timestamp else None,
            "count": e.count,
        }

    # =====================
    # RBAC: who can do what
    # =====================

    def list_role_bindings_for_subject(
        self,
        *,
        kind: str,
        name: str,
        namespace: Optional[str] = None,
    ) -> OperationResult:
        """
        Find every RoleBinding and ClusterRoleBinding that references a given
        subject (kind="User"|"Group"|"ServiceAccount", name=subject name).

        Useful for scoping the blast radius of a compromised principal.
        """
        result = OperationResult(
            operation="list_role_bindings_for_subject",
            target=f"kind={kind},name={name}" + (f",namespace={namespace}" if namespace else ""),
            success=True,
        )

        rbac = self._services.rbac_v1
        matched_role_bindings: List[Dict[str, Any]] = []
        matched_cluster_role_bindings: List[Dict[str, Any]] = []

        try:
            if namespace:
                role_bindings = rbac.list_namespaced_role_binding(namespace).items
            else:
                role_bindings = rbac.list_role_binding_for_all_namespaces().items

            for rb in role_bindings:
                if self._subjects_match(rb.subjects, kind, name):
                    matched_role_bindings.append({
                        "namespace": rb.metadata.namespace,
                        "name": rb.metadata.name,
                        "role_ref": rb.role_ref.name,
                    })

            for crb in rbac.list_cluster_role_binding().items:
                if self._subjects_match(crb.subjects, kind, name):
                    matched_cluster_role_bindings.append({
                        "name": crb.metadata.name,
                        "role_ref": crb.role_ref.name,
                    })

        except ApiException as exc:
            result.add_error(f"Failed to list role bindings: {exc}")
            _log.error(event("k8s_ir_hunt", "list_role_bindings_for_subject.error", target=result.target, error=str(exc)))

        result.details["role_bindings"] = matched_role_bindings
        result.details["cluster_role_bindings"] = matched_cluster_role_bindings
        result.details["statistics"] = {
            "role_bindings": len(matched_role_bindings),
            "cluster_role_bindings": len(matched_cluster_role_bindings),
        }
        _log.info(event("k8s_ir_hunt", "list_role_bindings_for_subject.complete", target=result.target))
        return result

    @staticmethod
    def _subjects_match(subjects: Optional[List[Any]], kind: str, name: str) -> bool:
        if not subjects:
            return False
        return any(s.kind == kind and s.name == name for s in subjects)

    # =====================
    # ServiceAccounts: what's using one
    # =====================

    def list_pods_by_service_account(self, namespace: str, service_account_name: str) -> OperationResult:
        """
        List pods in a namespace running under a given ServiceAccount.
        """
        result = OperationResult(
            operation="list_pods_by_service_account",
            target=f"namespace={namespace},service_account={service_account_name}",
            success=True,
        )

        try:
            pods = self._services.core_v1.list_namespaced_pod(
                namespace,
                field_selector=f"spec.serviceAccountName={service_account_name}",
            )
            result.details["pods"] = [
                {"name": p.metadata.name, "phase": p.status.phase, "node": p.spec.node_name}
                for p in pods.items
            ]
            result.details["statistics"] = {"total_pods": len(pods.items)}
            _log.info(event("k8s_ir_hunt", "list_pods_by_service_account.complete", target=result.target, count=len(pods.items)))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.error(event("k8s_ir_hunt", "list_pods_by_service_account.error", target=result.target, error=str(exc)))

        return result

    # =====================
    # Exposure: privileged pods
    # =====================

    def list_privileged_pods(self, *, max_pods: int = 500) -> OperationResult:
        """
        Flag pods running with elevated host access: privileged containers,
        hostNetwork, hostPID, or hostIPC.
        """
        result = OperationResult(operation="list_privileged_pods", target="cluster", success=True)

        flagged: List[Dict[str, Any]] = []
        total_scanned = 0
        continue_token: Optional[str] = None

        try:
            while total_scanned < max_pods:
                kwargs: Dict[str, Any] = {"limit": min(100, max_pods - total_scanned)}
                if continue_token:
                    kwargs["_continue"] = continue_token

                resp = self._services.core_v1.list_pod_for_all_namespaces(**kwargs)

                for pod in resp.items:
                    if total_scanned >= max_pods:
                        break
                    total_scanned += 1

                    reasons: List[str] = []
                    spec = pod.spec
                    if spec.host_network:
                        reasons.append("hostNetwork")
                    if spec.host_pid:
                        reasons.append("hostPID")
                    if spec.host_ipc:
                        reasons.append("hostIPC")

                    privileged_containers = [
                        c.name for c in (spec.containers or [])
                        if c.security_context and c.security_context.privileged
                    ]
                    if privileged_containers:
                        reasons.append("privilegedContainer")

                    if reasons:
                        flagged.append({
                            "namespace": pod.metadata.namespace,
                            "name": pod.metadata.name,
                            "reasons": reasons,
                            "privileged_containers": privileged_containers,
                        })

                continue_token = resp.metadata._continue
                if not continue_token or not resp.items:
                    break

        except ApiException as exc:
            result.add_error(f"Failed to list pods: {exc}")
            _log.error(event("k8s_ir_hunt", "list_privileged_pods.error", error=str(exc)))

        result.details["flagged_pods"] = flagged
        result.details["statistics"] = {"pods_scanned": total_scanned, "pods_flagged": len(flagged)}
        _log.info(event("k8s_ir_hunt", "list_privileged_pods.complete", scanned=total_scanned, flagged=len(flagged)))
        return result
