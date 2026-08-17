from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client.exceptions import ApiException

from dredge.k8s_ir.response import K8sIRResponse
from dredge.config import DredgeConfig


def make_services():
    return MagicMock()


def make_api_exception(status=403, reason="Forbidden"):
    return ApiException(status=status, reason=reason)


def obj(**kwargs):
    return SimpleNamespace(**kwargs)


class TestRevokeRoleBinding:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).revoke_role_binding("ns", "rb")
        assert result.details.get("dry_run") is True
        services.rbac_v1.delete_namespaced_role_binding.assert_not_called()

    def test_happy_path_captures_rollback_and_deletes(self):
        services = make_services()
        prior = MagicMock()
        prior.to_dict.return_value = {"metadata": {"name": "rb"}}
        services.rbac_v1.read_namespaced_role_binding.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).revoke_role_binding("ns", "rb")

        assert result.success is True
        assert result.details["rollback_state"] == {"metadata": {"name": "rb"}}
        services.rbac_v1.delete_namespaced_role_binding.assert_called_once_with("rb", "ns")

    def test_rollback_capture_error_does_not_block_delete(self):
        services = make_services()
        services.rbac_v1.read_namespaced_role_binding.side_effect = make_api_exception(404, "Not Found")

        result = K8sIRResponse(services, DredgeConfig()).revoke_role_binding("ns", "rb")

        assert result.success is True
        assert "rollback_state" not in result.details

    def test_delete_error_marks_failure(self):
        services = make_services()
        services.rbac_v1.delete_namespaced_role_binding.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).revoke_role_binding("ns", "rb")

        assert result.success is False
        assert result.errors


class TestRevokeClusterRoleBinding:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).revoke_cluster_role_binding("crb")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        prior = MagicMock()
        prior.to_dict.return_value = {"metadata": {"name": "crb"}}
        services.rbac_v1.read_cluster_role_binding.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).revoke_cluster_role_binding("crb")

        assert result.success is True
        services.rbac_v1.delete_cluster_role_binding.assert_called_once_with("crb")

    def test_delete_error(self):
        services = make_services()
        services.rbac_v1.delete_cluster_role_binding.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).revoke_cluster_role_binding("crb")
        assert result.success is False

    def test_rollback_capture_error_does_not_block_delete(self):
        services = make_services()
        services.rbac_v1.read_cluster_role_binding.side_effect = make_api_exception(404, "Not Found")

        result = K8sIRResponse(services, DredgeConfig()).revoke_cluster_role_binding("crb")

        assert result.success is True
        assert "rollback_state" not in result.details


def _sa_token_secret(name, sa_name, namespace="ns"):
    return obj(
        type="kubernetes.io/service-account-token",
        metadata=obj(name=name, namespace=namespace, annotations={"kubernetes.io/service-account.name": sa_name}),
    )


def _role_binding(name, subjects):
    return obj(metadata=obj(name=name, namespace="ns"), subjects=subjects, role_ref=obj(name="role"))


class TestDisableServiceAccount:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).disable_service_account("ns", "sa")
        assert result.details.get("dry_run") is True
        services.core_v1.list_namespaced_secret.assert_not_called()

    def test_deletes_bound_tokens_and_bindings(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[
            _sa_token_secret("sa-token-abc", "sa"),
            _sa_token_secret("sa-token-other", "other-sa"),
            obj(type="Opaque", metadata=obj(name="unrelated", namespace="ns", annotations={})),
        ])
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[
            _role_binding("rb-match", [obj(kind="ServiceAccount", name="sa", namespace=None)]),
            _role_binding("rb-nomatch", [obj(kind="ServiceAccount", name="other-sa", namespace="ns")]),
        ])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[
            obj(metadata=obj(name="crb-match"), subjects=[obj(kind="ServiceAccount", name="sa", namespace="ns")], role_ref=obj(name="r")),
            obj(metadata=obj(name="crb-nomatch"), subjects=[obj(kind="ServiceAccount", name="other-sa", namespace="ns")], role_ref=obj(name="r")),
        ])

        result = K8sIRResponse(services, DredgeConfig()).disable_service_account("ns", "sa")

        assert result.success is True
        assert result.details["token_secrets_deleted"] == ["sa-token-abc"]
        assert result.details["role_bindings_removed"] == ["rb-match"]
        assert result.details["cluster_role_bindings_removed"] == ["crb-match"]
        services.core_v1.delete_namespaced_secret.assert_called_once_with("sa-token-abc", "ns")
        services.rbac_v1.delete_namespaced_role_binding.assert_called_once_with("rb-match", "ns")
        services.rbac_v1.delete_cluster_role_binding.assert_called_once_with("crb-match")

    def test_per_item_error_recorded_but_others_continue(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[
            _sa_token_secret("sa-token-abc", "sa"),
        ])
        services.core_v1.delete_namespaced_secret.side_effect = make_api_exception()
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[])

        result = K8sIRResponse(services, DredgeConfig()).disable_service_account("ns", "sa")

        assert result.success is False
        assert result.details["token_secrets_deleted"] == []

    def test_role_binding_delete_error_recorded(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[])
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[
            _role_binding("rb-match", [obj(kind="ServiceAccount", name="sa", namespace=None)]),
        ])
        services.rbac_v1.delete_namespaced_role_binding.side_effect = make_api_exception()
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[])

        result = K8sIRResponse(services, DredgeConfig()).disable_service_account("ns", "sa")

        assert result.success is False
        assert result.details["role_bindings_removed"] == []

    def test_cluster_role_binding_delete_error_recorded(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[])
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[
            obj(metadata=obj(name="crb-match"), subjects=[obj(kind="ServiceAccount", name="sa", namespace="ns")], role_ref=obj(name="r")),
        ])
        services.rbac_v1.delete_cluster_role_binding.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).disable_service_account("ns", "sa")

        assert result.success is False
        assert result.details["cluster_role_bindings_removed"] == []

    def test_fatal_error_during_listing(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).disable_service_account("ns", "sa")
        assert result.success is False


class TestDeleteServiceAccount:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).delete_service_account("ns", "sa")
        assert result.details.get("dry_run") is True

    def test_happy_path_deletes_after_clean_disable(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[])
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[])

        result = K8sIRResponse(services, DredgeConfig()).delete_service_account("ns", "sa")

        assert result.success is True
        assert result.details["service_account_deleted"] is True
        services.core_v1.delete_namespaced_service_account.assert_called_once_with("sa", "ns")

    def test_aborts_when_disable_fails(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).delete_service_account("ns", "sa")

        assert result.success is False
        services.core_v1.delete_namespaced_service_account.assert_not_called()

    def test_delete_error_after_clean_disable(self):
        services = make_services()
        services.core_v1.list_namespaced_secret.return_value = obj(items=[])
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[])
        services.core_v1.delete_namespaced_service_account.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).delete_service_account("ns", "sa")

        assert result.success is False
        assert "service_account_deleted" not in result.details


class TestDeletePod:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).delete_pod("ns", "p")
        assert result.details.get("dry_run") is True
        services.core_v1.delete_namespaced_pod.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).delete_pod("ns", "p", grace_period_seconds=5)
        assert result.success is True
        services.core_v1.delete_namespaced_pod.assert_called_once_with("p", "ns", grace_period_seconds=5)

    def test_error(self):
        services = make_services()
        services.core_v1.delete_namespaced_pod.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).delete_pod("ns", "p")
        assert result.success is False


class TestScaleDeployment:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).scale_deployment("ns", "d", 0)
        assert result.details.get("dry_run") is True

    def test_happy_path_captures_rollback(self):
        services = make_services()
        prior = MagicMock()
        prior.spec.replicas = 3
        services.apps_v1.read_namespaced_deployment_scale.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).scale_deployment("ns", "d", 0)

        assert result.success is True
        assert result.details["rollback_state"] == {"replicas": 3}
        services.apps_v1.patch_namespaced_deployment_scale.assert_called_once_with(
            "d", "ns", {"spec": {"replicas": 0}}
        )

    def test_error(self):
        services = make_services()
        services.apps_v1.patch_namespaced_deployment_scale.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).scale_deployment("ns", "d", 0)
        assert result.success is False

    def test_rollback_capture_error_does_not_block_patch(self):
        services = make_services()
        services.apps_v1.read_namespaced_deployment_scale.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).scale_deployment("ns", "d", 0)

        assert result.success is True
        assert "rollback_state" not in result.details


class TestCordonNode:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).cordon_node("n")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        prior = MagicMock()
        prior.spec.unschedulable = False
        services.core_v1.read_node.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).cordon_node("n")

        assert result.success is True
        assert result.details["rollback_state"] == {"unschedulable": False}
        services.core_v1.patch_node.assert_called_once_with("n", {"spec": {"unschedulable": True}})

    def test_error(self):
        services = make_services()
        services.core_v1.patch_node.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).cordon_node("n")
        assert result.success is False

    def test_rollback_capture_error_does_not_block_patch(self):
        services = make_services()
        services.core_v1.read_node.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).cordon_node("n")

        assert result.success is True
        assert "rollback_state" not in result.details


def _pod(name, namespace="ns", owner_kind=None):
    owners = [obj(kind=owner_kind)] if owner_kind else []
    return obj(metadata=obj(name=name, namespace=namespace, owner_references=owners))


class TestDrainNode:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).drain_node("n")
        assert result.details.get("dry_run") is True
        services.core_v1.patch_node.assert_not_called()

    def test_evicts_pods_and_skips_daemonsets(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.return_value = obj(items=[
            _pod("regular-pod"),
            _pod("ds-pod", owner_kind="DaemonSet"),
        ])

        result = K8sIRResponse(services, DredgeConfig()).drain_node("n")

        assert result.success is True
        assert result.details["cordoned"] is True
        assert result.details["pods_evicted"] == ["ns/regular-pod"]
        assert result.details["daemonset_pods_skipped"] == ["ns/ds-pod"]
        services.core_v1.create_namespaced_pod_eviction.assert_called_once()

    def test_includes_daemonsets_when_ignore_daemonsets_false(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.return_value = obj(items=[
            _pod("ds-pod", owner_kind="DaemonSet"),
        ])

        result = K8sIRResponse(services, DredgeConfig()).drain_node("n", ignore_daemonsets=False)

        assert result.details["pods_evicted"] == ["ns/ds-pod"]

    def test_cordon_fatal_error_aborts(self):
        services = make_services()
        services.core_v1.patch_node.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).drain_node("n")

        assert result.success is False
        services.core_v1.list_pod_for_all_namespaces.assert_not_called()

    def test_list_fatal_error_aborts(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).drain_node("n")

        assert result.success is False

    def test_eviction_error_recorded_but_continues(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.return_value = obj(items=[
            _pod("pod-a"), _pod("pod-b"),
        ])
        services.core_v1.create_namespaced_pod_eviction.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).drain_node("n")

        assert result.success is False
        assert result.details["pods_evicted"] == []


class TestDeleteNode:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).delete_node("n")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        prior = MagicMock()
        prior.to_dict.return_value = {"metadata": {"name": "n"}}
        services.core_v1.read_node.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).delete_node("n")

        assert result.success is True
        assert "underlying VM" in result.details["status"]
        services.core_v1.delete_node.assert_called_once_with("n")

    def test_error(self):
        services = make_services()
        services.core_v1.delete_node.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).delete_node("n")
        assert result.success is False

    def test_rollback_capture_error_does_not_block_delete(self):
        services = make_services()
        services.core_v1.read_node.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).delete_node("n")

        assert result.success is True
        assert "rollback_state" not in result.details


class TestQuarantinePod:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).quarantine_pod("ns", "p")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        prior = MagicMock()
        prior.metadata.labels = {"app": "web"}
        services.core_v1.read_namespaced_pod.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).quarantine_pod("ns", "p")

        assert result.success is True
        assert result.details["rollback_state"] == {"labels": {"app": "web"}}
        assert result.details["label_added"] == {"dredge.io/quarantine": "p"}
        assert result.details["network_policy_created"] == "dredge-forensic-isolation"
        services.core_v1.patch_namespaced_pod.assert_called_once()
        services.networking_v1.create_namespaced_network_policy.assert_called_once()

    def test_label_fatal_error_aborts_before_policy(self):
        services = make_services()
        services.core_v1.patch_namespaced_pod.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).quarantine_pod("ns", "p")

        assert result.success is False
        services.networking_v1.create_namespaced_network_policy.assert_not_called()

    def test_policy_error_recorded(self):
        services = make_services()
        services.networking_v1.create_namespaced_network_policy.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).quarantine_pod("ns", "p")

        assert result.success is False
        assert result.details["label_added"] == {"dredge.io/quarantine": "p"}

    def test_rollback_capture_error_does_not_block_label(self):
        services = make_services()
        services.core_v1.read_namespaced_pod.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).quarantine_pod("ns", "p")

        assert result.success is True
        assert "rollback_state" not in result.details


class TestQuarantineNamespace:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).quarantine_namespace("ns")
        assert result.details.get("dry_run") is True

    def test_happy_path_no_prior_policy(self):
        services = make_services()
        services.networking_v1.read_namespaced_network_policy.side_effect = make_api_exception(404, "Not Found")

        result = K8sIRResponse(services, DredgeConfig()).quarantine_namespace("ns")

        assert result.success is True
        assert result.details["rollback_state"] is None
        assert result.details["network_policy_created"] == "dredge-forensic-isolation"

    def test_happy_path_with_prior_policy(self):
        services = make_services()
        prior = MagicMock()
        prior.to_dict.return_value = {"metadata": {"name": "dredge-forensic-isolation"}}
        services.networking_v1.read_namespaced_network_policy.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).quarantine_namespace("ns")

        assert result.success is True
        assert result.details["rollback_state"] == {"metadata": {"name": "dredge-forensic-isolation"}}

    def test_error(self):
        services = make_services()
        services.networking_v1.read_namespaced_network_policy.side_effect = make_api_exception(404, "Not Found")
        services.networking_v1.create_namespaced_network_policy.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).quarantine_namespace("ns")
        assert result.success is False


class TestDeleteSecret:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).delete_secret("ns", "s")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        prior = MagicMock()
        prior.to_dict.return_value = {"data": {"key": "dmFsdWU="}}
        services.core_v1.read_namespaced_secret.return_value = prior

        result = K8sIRResponse(services, DredgeConfig()).delete_secret("ns", "s")

        assert result.success is True
        assert result.details["rollback_state"] == {"data": {"key": "dmFsdWU="}}
        services.core_v1.delete_namespaced_secret.assert_called_once_with("s", "ns")

    def test_error(self):
        services = make_services()
        services.core_v1.delete_namespaced_secret.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).delete_secret("ns", "s")
        assert result.success is False

    def test_rollback_capture_error_does_not_block_delete(self):
        services = make_services()
        services.core_v1.read_namespaced_secret.side_effect = make_api_exception()

        result = K8sIRResponse(services, DredgeConfig()).delete_secret("ns", "s")

        assert result.success is True
        assert "rollback_state" not in result.details


class TestLabelResource:
    def test_dry_run(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig(dry_run=True)).label_resource("pod", "ns", "p", {"a": "b"})
        assert result.details.get("dry_run") is True

    def test_pod(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("pod", "ns", "p", {"a": "b"})
        assert result.success is True
        services.core_v1.patch_namespaced_pod.assert_called_once_with("p", "ns", {"metadata": {"labels": {"a": "b"}}})

    def test_node(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("node", None, "n", {"a": "b"})
        assert result.success is True
        services.core_v1.patch_node.assert_called_once_with("n", {"metadata": {"labels": {"a": "b"}}})

    def test_namespace(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("namespace", None, "ns", {"a": "b"})
        assert result.success is True
        services.core_v1.patch_namespace.assert_called_once_with("ns", {"metadata": {"labels": {"a": "b"}}})

    def test_deployment(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("deployment", "ns", "d", {"a": "b"})
        assert result.success is True
        services.apps_v1.patch_namespaced_deployment.assert_called_once_with("d", "ns", {"metadata": {"labels": {"a": "b"}}})

    def test_unsupported_kind(self):
        services = make_services()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("bogus", "ns", "x", {"a": "b"})
        assert result.success is False
        assert "Unsupported kind" in result.errors[0]

    def test_api_error(self):
        services = make_services()
        services.core_v1.patch_namespaced_pod.side_effect = make_api_exception()
        result = K8sIRResponse(services, DredgeConfig()).label_resource("pod", "ns", "p", {"a": "b"})
        assert result.success is False


class TestSubjectsReferenceSaHelper:
    def test_none_subjects_returns_false(self):
        assert K8sIRResponse._subjects_reference_sa(None, "ns", "sa") is False

    def test_empty_subjects_returns_false(self):
        assert K8sIRResponse._subjects_reference_sa([], "ns", "sa") is False

    def test_non_service_account_kind_skipped(self):
        subjects = [obj(kind="User", name="sa", namespace="ns")]
        assert K8sIRResponse._subjects_reference_sa(subjects, "ns", "sa") is False

    def test_namespace_mismatch_skipped(self):
        subjects = [obj(kind="ServiceAccount", name="sa", namespace="other-ns")]
        assert K8sIRResponse._subjects_reference_sa(subjects, "ns", "sa") is False

    def test_matches_when_namespace_omitted_defaults_to_binding_namespace(self):
        subjects = [obj(kind="ServiceAccount", name="sa", namespace=None)]
        assert K8sIRResponse._subjects_reference_sa(subjects, "ns", "sa") is True

    def test_matches_when_namespace_explicit_and_equal(self):
        subjects = [obj(kind="ServiceAccount", name="sa", namespace="ns")]
        assert K8sIRResponse._subjects_reference_sa(subjects, "ns", "sa") is True
