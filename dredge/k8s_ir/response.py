from __future__ import annotations

from typing import Any, Dict, List, Optional

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import K8sServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)

_QUARANTINE_LABEL_KEY = "dredge.io/quarantine"

_SA_TOKEN_SECRET_TYPE = "kubernetes.io/service-account-token"
_SA_TOKEN_SECRET_NAME_ANNOTATION = "kubernetes.io/service-account.name"


class K8sIRResponse:
    """
    High-level Kubernetes incident *response* actions.

    These operate against the standard Kubernetes API and therefore behave
    identically regardless of who manages the control plane (EKS, GKE, AKS,
    or self-managed) -- the only cluster-flavor-specific piece is auth
    (see K8sAuthConfig), not these methods.
    """

    def __init__(self, services: K8sServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    # --------------------
    # RBAC: RoleBindings / ClusterRoleBindings
    # --------------------

    def revoke_role_binding(self, namespace: str, name: str) -> OperationResult:
        """
        Delete a RoleBinding, revoking whatever access it granted.
        """
        result = OperationResult(
            operation="revoke_role_binding",
            target=f"namespace={namespace},role_binding={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "revoke_role_binding.dry_run", target=result.target))
            return result

        rbac = self._services.rbac_v1

        try:
            prior = rbac.read_namespaced_role_binding(name, namespace)
            result.details["rollback_state"] = prior.to_dict()
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "revoke_role_binding.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            rbac.delete_namespaced_role_binding(name, namespace)
            result.details["status"] = "RoleBinding deleted"
            _log.info(event("k8s_ir_response", "revoke_role_binding.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "revoke_role_binding.error", target=result.target, error=str(exc)))

        return result

    def revoke_cluster_role_binding(self, name: str) -> OperationResult:
        """
        Delete a ClusterRoleBinding, revoking whatever cluster-wide access it granted.
        """
        result = OperationResult(
            operation="revoke_cluster_role_binding",
            target=f"cluster_role_binding={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "revoke_cluster_role_binding.dry_run", target=result.target))
            return result

        rbac = self._services.rbac_v1

        try:
            prior = rbac.read_cluster_role_binding(name)
            result.details["rollback_state"] = prior.to_dict()
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "revoke_cluster_role_binding.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            rbac.delete_cluster_role_binding(name)
            result.details["status"] = "ClusterRoleBinding deleted"
            _log.info(event("k8s_ir_response", "revoke_cluster_role_binding.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "revoke_cluster_role_binding.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # RBAC: ServiceAccounts
    # --------------------

    def disable_service_account(self, namespace: str, name: str) -> OperationResult:
        """
        Disable a ServiceAccount by:
          - Deleting its bound service-account-token Secrets
          - Removing every RoleBinding in the namespace that references it
          - Removing every ClusterRoleBinding that references it
        """
        result = OperationResult(
            operation="disable_service_account",
            target=f"namespace={namespace},service_account={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "disable_service_account.dry_run", target=result.target))
            return result

        core = self._services.core_v1
        rbac = self._services.rbac_v1

        try:
            # 1) Delete bound service-account-token Secrets
            secrets_deleted: List[str] = []
            secrets = core.list_namespaced_secret(namespace)
            for secret in secrets.items:
                if secret.type != _SA_TOKEN_SECRET_TYPE:
                    continue
                annotations = secret.metadata.annotations or {}
                if annotations.get(_SA_TOKEN_SECRET_NAME_ANNOTATION) != name:
                    continue
                secret_name = secret.metadata.name
                try:
                    core.delete_namespaced_secret(secret_name, namespace)
                    secrets_deleted.append(secret_name)
                except ApiException as exc:
                    result.add_error(f"Failed to delete token secret {secret_name}: {exc}")
                    _log.warning(event("k8s_ir_response", "disable_service_account.secret_error", secret=secret_name, error=str(exc)))
            result.details["token_secrets_deleted"] = secrets_deleted

            # 2) Remove RoleBindings referencing this ServiceAccount
            role_bindings_removed: List[str] = []
            for rb in rbac.list_namespaced_role_binding(namespace).items:
                if not self._subjects_reference_sa(rb.subjects, namespace, name):
                    continue
                rb_name = rb.metadata.name
                try:
                    rbac.delete_namespaced_role_binding(rb_name, namespace)
                    role_bindings_removed.append(rb_name)
                except ApiException as exc:
                    result.add_error(f"Failed to remove role binding {rb_name}: {exc}")
                    _log.warning(event("k8s_ir_response", "disable_service_account.role_binding_error", role_binding=rb_name, error=str(exc)))
            result.details["role_bindings_removed"] = role_bindings_removed

            # 3) Remove ClusterRoleBindings referencing this ServiceAccount
            cluster_role_bindings_removed: List[str] = []
            for crb in rbac.list_cluster_role_binding().items:
                if not self._subjects_reference_sa(crb.subjects, namespace, name):
                    continue
                crb_name = crb.metadata.name
                try:
                    rbac.delete_cluster_role_binding(crb_name)
                    cluster_role_bindings_removed.append(crb_name)
                except ApiException as exc:
                    result.add_error(f"Failed to remove cluster role binding {crb_name}: {exc}")
                    _log.warning(event("k8s_ir_response", "disable_service_account.cluster_role_binding_error", cluster_role_binding=crb_name, error=str(exc)))
            result.details["cluster_role_bindings_removed"] = cluster_role_bindings_removed

            _log.info(event("k8s_ir_response", "disable_service_account.success", target=result.target))

        except ApiException as exc:
            result.add_error(f"Fatal error disabling service account: {exc}")
            _log.error(event("k8s_ir_response", "disable_service_account.fatal", target=result.target, error=str(exc)))

        return result

    @staticmethod
    def _subjects_reference_sa(subjects: Optional[List[Any]], namespace: str, name: str) -> bool:
        if not subjects:
            return False
        for subject in subjects:
            if subject.kind != "ServiceAccount":
                continue
            if subject.name != name:
                continue
            # Subject namespace defaults to the binding's own namespace when omitted.
            if (subject.namespace or namespace) != namespace:
                continue
            return True
        return False

    def delete_service_account(self, namespace: str, name: str) -> OperationResult:
        """
        Fully delete a ServiceAccount:

          1) Call disable_service_account() to strip its tokens and bindings
          2) Delete the ServiceAccount object itself

        NOTE: This is destructive. Prefer disable_service_account for
        containment and only delete when you're sure.
        """
        disable_result = self.disable_service_account(namespace, name)

        result = OperationResult(
            operation="delete_service_account",
            target=f"namespace={namespace},service_account={name}",
            success=disable_result.success,
            details=dict(disable_result.details),
            errors=list(disable_result.errors),
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        if not disable_result.success:
            result.add_error(
                f"Aborting deletion of service account {name}: disable_service_account "
                "reported failures. Resolve errors and retry."
            )
            return result

        try:
            self._services.core_v1.delete_namespaced_service_account(name, namespace)
            result.details["service_account_deleted"] = True
            _log.info(event("k8s_ir_response", "delete_service_account.success", target=result.target))
        except ApiException as exc:
            result.add_error(f"Failed to delete service account {name}: {exc}")
            _log.warning(event("k8s_ir_response", "delete_service_account.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Workloads: Pods / Deployments
    # --------------------

    def delete_pod(self, namespace: str, name: str, *, grace_period_seconds: int = 0) -> OperationResult:
        """
        Force-delete a pod.
        """
        result = OperationResult(
            operation="delete_pod",
            target=f"namespace={namespace},pod={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "delete_pod.dry_run", target=result.target))
            return result

        try:
            self._services.core_v1.delete_namespaced_pod(
                name, namespace, grace_period_seconds=grace_period_seconds,
            )
            result.details["status"] = "Pod deleted"
            _log.info(event("k8s_ir_response", "delete_pod.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "delete_pod.error", target=result.target, error=str(exc)))

        return result

    def scale_deployment(self, namespace: str, name: str, replicas: int = 0) -> OperationResult:
        """
        Scale a Deployment to the given replica count (default 0, i.e. stop it).
        """
        result = OperationResult(
            operation="scale_deployment",
            target=f"namespace={namespace},deployment={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "scale_deployment.dry_run", target=result.target))
            return result

        apps = self._services.apps_v1

        try:
            prior = apps.read_namespaced_deployment_scale(name, namespace)
            result.details["rollback_state"] = {"replicas": prior.spec.replicas}
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "scale_deployment.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            apps.patch_namespaced_deployment_scale(name, namespace, {"spec": {"replicas": replicas}})
            result.details["replicas"] = replicas
            _log.info(event("k8s_ir_response", "scale_deployment.success", target=result.target, replicas=replicas))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "scale_deployment.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Nodes
    # --------------------

    def cordon_node(self, name: str) -> OperationResult:
        """
        Mark a node unschedulable. Running pods are left in place -- use
        drain_node to also evict them.
        """
        result = OperationResult(
            operation="cordon_node",
            target=f"node={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "cordon_node.dry_run", target=result.target))
            return result

        core = self._services.core_v1

        try:
            prior = core.read_node(name)
            result.details["rollback_state"] = {"unschedulable": bool(prior.spec.unschedulable)}
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "cordon_node.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            core.patch_node(name, {"spec": {"unschedulable": True}})
            result.details["unschedulable"] = True
            _log.info(event("k8s_ir_response", "cordon_node.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "cordon_node.error", target=result.target, error=str(exc)))

        return result

    def drain_node(
        self,
        name: str,
        *,
        grace_period_seconds: int = 30,
        ignore_daemonsets: bool = True,
    ) -> OperationResult:
        """
        Cordon a node and evict every pod running on it.

        DaemonSet-owned pods are skipped by default (ignore_daemonsets=True)
        since they will be immediately rescheduled by their controller and
        cannot be meaningfully drained.
        """
        result = OperationResult(
            operation="drain_node",
            target=f"node={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "drain_node.dry_run", target=result.target))
            return result

        core = self._services.core_v1

        try:
            core.patch_node(name, {"spec": {"unschedulable": True}})
            result.details["cordoned"] = True
        except ApiException as exc:
            result.add_error(f"Failed to cordon node: {exc}")
            _log.error(event("k8s_ir_response", "drain_node.cordon_fatal", target=result.target, error=str(exc)))
            return result

        try:
            pods = core.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={name}")
        except ApiException as exc:
            result.add_error(f"Failed to list pods on node: {exc}")
            _log.error(event("k8s_ir_response", "drain_node.list_fatal", target=result.target, error=str(exc)))
            return result

        evicted: List[str] = []
        skipped_daemonsets: List[str] = []

        for pod in pods.items:
            pod_name = pod.metadata.name
            pod_namespace = pod.metadata.namespace
            owner_kinds = {ref.kind for ref in (pod.metadata.owner_references or [])}

            if ignore_daemonsets and "DaemonSet" in owner_kinds:
                skipped_daemonsets.append(f"{pod_namespace}/{pod_name}")
                continue

            eviction = client.V1Eviction(
                metadata=client.V1ObjectMeta(name=pod_name, namespace=pod_namespace),
                delete_options=client.V1DeleteOptions(grace_period_seconds=grace_period_seconds),
            )
            try:
                core.create_namespaced_pod_eviction(pod_name, pod_namespace, eviction)
                evicted.append(f"{pod_namespace}/{pod_name}")
            except ApiException as exc:
                result.add_error(f"Failed to evict pod {pod_namespace}/{pod_name}: {exc}")
                _log.warning(event("k8s_ir_response", "drain_node.evict_error", pod=f"{pod_namespace}/{pod_name}", error=str(exc)))

        result.details["pods_evicted"] = evicted
        result.details["daemonset_pods_skipped"] = skipped_daemonsets
        _log.info(event("k8s_ir_response", "drain_node.complete", target=result.target, evicted=len(evicted)))

        return result

    def delete_node(self, name: str) -> OperationResult:
        """
        Remove a Node object from the cluster.

        NOTE: This only removes the cluster's record of the node. It does
        NOT stop, terminate, or otherwise touch the underlying VM/instance --
        use the relevant cloud IR module (e.g. aws_ir.response.terminate_ec2_instances)
        for that.
        """
        result = OperationResult(
            operation="delete_node",
            target=f"node={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "delete_node.dry_run", target=result.target))
            return result

        core = self._services.core_v1

        try:
            prior = core.read_node(name)
            result.details["rollback_state"] = prior.to_dict()
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "delete_node.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            core.delete_node(name)
            result.details["status"] = "Node object deleted (underlying VM untouched)"
            _log.info(event("k8s_ir_response", "delete_node.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "delete_node.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Network: NetworkPolicy quarantine
    # --------------------

    def quarantine_pod(
        self,
        namespace: str,
        pod_name: str,
        *,
        policy_name: str = "dredge-forensic-isolation",
    ) -> OperationResult:
        """
        Isolate a single pod by:
          - Labeling it with a unique dredge.io/quarantine label
          - Creating a deny-all ingress+egress NetworkPolicy scoped to that label

        NOTE: Enforcement depends on the cluster's CNI supporting NetworkPolicy
        (e.g. Calico, Cilium). Some CNIs (e.g. plain flannel) do not enforce
        NetworkPolicy at all -- verify enforcement is active before relying
        on this for containment.
        """
        result = OperationResult(
            operation="quarantine_pod",
            target=f"namespace={namespace},pod={pod_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "quarantine_pod.dry_run", target=result.target))
            return result

        core = self._services.core_v1
        networking = self._services.networking_v1

        try:
            prior = core.read_namespaced_pod(pod_name, namespace)
            result.details["rollback_state"] = {"labels": dict(prior.metadata.labels or {})}
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "quarantine_pod.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            core.patch_namespaced_pod(
                pod_name, namespace,
                {"metadata": {"labels": {_QUARANTINE_LABEL_KEY: pod_name}}},
            )
            result.details["label_added"] = {_QUARANTINE_LABEL_KEY: pod_name}
        except ApiException as exc:
            result.add_error(f"Failed to label pod: {exc}")
            _log.error(event("k8s_ir_response", "quarantine_pod.label_fatal", target=result.target, error=str(exc)))
            return result

        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=policy_name),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(
                    match_labels={_QUARANTINE_LABEL_KEY: pod_name},
                ),
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            ),
        )

        try:
            networking.create_namespaced_network_policy(namespace, policy)
            result.details["network_policy_created"] = policy_name
            _log.info(event("k8s_ir_response", "quarantine_pod.success", target=result.target))
        except ApiException as exc:
            result.add_error(f"Failed to create isolation NetworkPolicy: {exc}")
            _log.warning(event("k8s_ir_response", "quarantine_pod.policy_error", target=result.target, error=str(exc)))

        return result

    def quarantine_namespace(
        self,
        namespace: str,
        *,
        policy_name: str = "dredge-forensic-isolation",
    ) -> OperationResult:
        """
        Apply a deny-all ingress+egress NetworkPolicy across an entire namespace.

        Same CNI-enforcement caveat as quarantine_pod applies.
        """
        result = OperationResult(
            operation="quarantine_namespace",
            target=f"namespace={namespace}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "quarantine_namespace.dry_run", target=result.target))
            return result

        networking = self._services.networking_v1

        try:
            prior = networking.read_namespaced_network_policy(policy_name, namespace)
            result.details["rollback_state"] = prior.to_dict()
        except ApiException:
            result.details["rollback_state"] = None

        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=policy_name),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(),
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            ),
        )

        try:
            networking.create_namespaced_network_policy(namespace, policy)
            result.details["network_policy_created"] = policy_name
            _log.info(event("k8s_ir_response", "quarantine_namespace.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "quarantine_namespace.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Secrets
    # --------------------

    def delete_secret(self, namespace: str, name: str) -> OperationResult:
        """
        Delete a Secret.

        NOTE: rollback_state captures the full Secret object, INCLUDING its
        data, so it can be restored -- callers are responsible for handling
        the returned OperationResult with the same care as the secret itself.
        """
        result = OperationResult(
            operation="delete_secret",
            target=f"namespace={namespace},secret={name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "delete_secret.dry_run", target=result.target))
            return result

        core = self._services.core_v1

        try:
            prior = core.read_namespaced_secret(name, namespace)
            result.details["rollback_state"] = prior.to_dict()
        except ApiException as exc:
            _log.warning(event("k8s_ir_response", "delete_secret.rollback_capture_error", target=result.target, error=str(exc)))

        try:
            core.delete_namespaced_secret(name, namespace)
            result.details["status"] = "Secret deleted"
            _log.info(event("k8s_ir_response", "delete_secret.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "delete_secret.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Labeling
    # --------------------

    def label_resource(
        self,
        kind: str,
        namespace: Optional[str],
        name: str,
        labels: Dict[str, str],
    ) -> OperationResult:
        """
        Apply labels to a resource identified by kind + name.

        kind must be one of: "pod", "node", "namespace", "deployment".
        namespace is required for "pod" and "deployment", ignored for
        "node" and "namespace" (cluster-scoped / self-named).
        """
        target = f"kind={kind},name={name}"
        if namespace:
            target += f",namespace={namespace}"

        result = OperationResult(operation="label_resource", target=target, success=True)

        if kind not in ("pod", "node", "namespace", "deployment"):
            result.add_error(f"Unsupported kind for label_resource: {kind!r}")
            return result

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("k8s_ir_response", "label_resource.dry_run", target=result.target))
            return result

        body = {"metadata": {"labels": labels}}
        core = self._services.core_v1
        apps = self._services.apps_v1

        try:
            if kind == "pod":
                core.patch_namespaced_pod(name, namespace, body)
            elif kind == "node":
                core.patch_node(name, body)
            elif kind == "namespace":
                core.patch_namespace(name, body)
            elif kind == "deployment":
                apps.patch_namespaced_deployment(name, namespace, body)

            result.details["labels_applied"] = labels
            _log.info(event("k8s_ir_response", "label_resource.success", target=result.target))
        except ApiException as exc:
            result.add_error(str(exc))
            _log.warning(event("k8s_ir_response", "label_resource.error", target=result.target, error=str(exc)))

        return result
