from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client.exceptions import ApiException

from dredge.k8s_ir.hunt import K8sIRHunt
from dredge.config import DredgeConfig


def make_services():
    return MagicMock()


def make_api_exception(status=403, reason="Forbidden"):
    return ApiException(status=status, reason=reason)


def obj(**kwargs):
    return SimpleNamespace(**kwargs)


def _event(name="e1", namespace="ns", reason="Killing", event_type="Normal", ts=None, count=1):
    ts = ts or datetime.now(timezone.utc)
    return obj(
        metadata=obj(name=name, namespace=namespace),
        reason=reason,
        message="msg",
        type=event_type,
        involved_object=obj(kind="Pod", name="p", namespace=namespace),
        source=obj(component="kubelet"),
        first_timestamp=ts,
        last_timestamp=ts,
        event_time=None,
        count=count,
    )


class TestListEvents:
    def test_namespaced_happy_path(self):
        services = make_services()
        page = obj(items=[_event()], metadata=obj(_continue=None))
        services.core_v1.list_namespaced_event.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events(namespace="ns")

        assert result.success is True
        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["reason"] == "Killing"
        assert result.details["statistics"]["total_events_returned"] == 1
        services.core_v1.list_namespaced_event.assert_called_once()
        services.core_v1.list_event_for_all_namespaces.assert_not_called()

    def test_cluster_wide_when_no_namespace(self):
        services = make_services()
        page = obj(items=[_event()], metadata=obj(_continue=None))
        services.core_v1.list_event_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events()

        assert result.success is True
        services.core_v1.list_event_for_all_namespaces.assert_called_once()

    def test_field_selector_built_from_involved_object(self):
        services = make_services()
        services.core_v1.list_event_for_all_namespaces.return_value = obj(items=[], metadata=obj(_continue=None))

        K8sIRHunt(services, DredgeConfig()).list_events(
            involved_object_kind="Pod", involved_object_name="p",
        )

        kwargs = services.core_v1.list_event_for_all_namespaces.call_args.kwargs
        assert kwargs["field_selector"] == "involvedObject.kind=Pod,involvedObject.name=p"

    def test_reason_filtered_client_side(self):
        services = make_services()
        page = obj(items=[_event(reason="Killing"), _event(reason="Scheduled")], metadata=obj(_continue=None))
        services.core_v1.list_event_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events(reason="Killing")

        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["reason"] == "Killing"

    def test_event_type_filtered_client_side(self):
        services = make_services()
        page = obj(items=[_event(event_type="Normal"), _event(event_type="Warning")], metadata=obj(_continue=None))
        services.core_v1.list_event_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events(event_type="Warning")

        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["type"] == "Warning"

    def test_events_outside_time_window_excluded(self):
        services = make_services()
        old_ts = datetime.now(timezone.utc) - timedelta(days=10)
        page = obj(items=[_event(ts=old_ts)], metadata=obj(_continue=None))
        services.core_v1.list_event_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events()

        assert result.details["events"] == []

    def test_pagination_follows_continue_token(self):
        services = make_services()
        page1 = obj(items=[_event(name="e1")], metadata=obj(_continue="tok"))
        page2 = obj(items=[_event(name="e2")], metadata=obj(_continue=None))
        services.core_v1.list_event_for_all_namespaces.side_effect = [page1, page2]

        result = K8sIRHunt(services, DredgeConfig()).list_events(max_events=10)

        assert result.details["statistics"]["api_calls"] == 2
        assert len(result.details["events"]) == 2
        second_call_kwargs = services.core_v1.list_event_for_all_namespaces.call_args_list[1].kwargs
        assert second_call_kwargs["_continue"] == "tok"

    def test_stops_at_max_events(self):
        services = make_services()
        many = [_event(name=f"e{i}") for i in range(5)]
        page = obj(items=many, metadata=obj(_continue="tok"))
        services.core_v1.list_event_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_events(max_events=3, page_size=5)

        assert len(result.details["events"]) == 3

    def test_api_error(self):
        services = make_services()
        services.core_v1.list_event_for_all_namespaces.side_effect = make_api_exception()

        result = K8sIRHunt(services, DredgeConfig()).list_events()

        assert result.success is False
        assert result.details["events"] == []


class TestListRoleBindingsForSubject:
    def test_finds_matching_role_bindings_and_cluster_role_bindings(self):
        services = make_services()
        services.rbac_v1.list_role_binding_for_all_namespaces.return_value = obj(items=[
            obj(metadata=obj(namespace="ns", name="rb-match"), subjects=[obj(kind="User", name="alice")], role_ref=obj(name="admin")),
            obj(metadata=obj(namespace="ns", name="rb-nomatch"), subjects=[obj(kind="User", name="bob")], role_ref=obj(name="viewer")),
        ])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[
            obj(metadata=obj(name="crb-match"), subjects=[obj(kind="User", name="alice")], role_ref=obj(name="cluster-admin")),
        ])

        result = K8sIRHunt(services, DredgeConfig()).list_role_bindings_for_subject(kind="User", name="alice")

        assert result.success is True
        assert result.details["role_bindings"] == [{"namespace": "ns", "name": "rb-match", "role_ref": "admin"}]
        assert result.details["cluster_role_bindings"] == [{"name": "crb-match", "role_ref": "cluster-admin"}]

    def test_scoped_to_namespace_when_given(self):
        services = make_services()
        services.rbac_v1.list_namespaced_role_binding.return_value = obj(items=[])
        services.rbac_v1.list_cluster_role_binding.return_value = obj(items=[])

        K8sIRHunt(services, DredgeConfig()).list_role_bindings_for_subject(kind="User", name="alice", namespace="ns")

        services.rbac_v1.list_namespaced_role_binding.assert_called_once_with("ns")
        services.rbac_v1.list_role_binding_for_all_namespaces.assert_not_called()

    def test_api_error(self):
        services = make_services()
        services.rbac_v1.list_role_binding_for_all_namespaces.side_effect = make_api_exception()

        result = K8sIRHunt(services, DredgeConfig()).list_role_bindings_for_subject(kind="User", name="alice")

        assert result.success is False


class TestSubjectsMatchHelper:
    def test_none_subjects_returns_false(self):
        assert K8sIRHunt._subjects_match(None, "User", "alice") is False

    def test_empty_subjects_returns_false(self):
        assert K8sIRHunt._subjects_match([], "User", "alice") is False


class TestListPodsByServiceAccount:
    def test_happy_path(self):
        services = make_services()
        services.core_v1.list_namespaced_pod.return_value = obj(items=[
            obj(metadata=obj(name="p1"), status=obj(phase="Running"), spec=obj(node_name="node-a")),
        ])

        result = K8sIRHunt(services, DredgeConfig()).list_pods_by_service_account("ns", "sa")

        assert result.success is True
        assert result.details["pods"] == [{"name": "p1", "phase": "Running", "node": "node-a"}]
        services.core_v1.list_namespaced_pod.assert_called_once_with("ns", field_selector="spec.serviceAccountName=sa")

    def test_api_error(self):
        services = make_services()
        services.core_v1.list_namespaced_pod.side_effect = make_api_exception()
        result = K8sIRHunt(services, DredgeConfig()).list_pods_by_service_account("ns", "sa")
        assert result.success is False


def _pod_spec(host_network=False, host_pid=False, host_ipc=False, privileged=False):
    container = obj(
        name="c1",
        security_context=obj(privileged=privileged) if privileged else None,
    )
    return obj(
        metadata=obj(namespace="ns", name="p"),
        spec=obj(host_network=host_network, host_pid=host_pid, host_ipc=host_ipc, containers=[container]),
    )


class TestListPrivilegedPods:
    def test_flags_privileged_container(self):
        services = make_services()
        page = obj(items=[_pod_spec(privileged=True)], metadata=obj(_continue=None))
        services.core_v1.list_pod_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods()

        assert result.success is True
        assert result.details["flagged_pods"][0]["reasons"] == ["privilegedContainer"]

    def test_flags_host_network_pid_ipc(self):
        services = make_services()
        page = obj(items=[_pod_spec(host_network=True, host_pid=True, host_ipc=True)], metadata=obj(_continue=None))
        services.core_v1.list_pod_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods()

        reasons = result.details["flagged_pods"][0]["reasons"]
        assert set(reasons) == {"hostNetwork", "hostPID", "hostIPC"}

    def test_unflagged_pod_not_included(self):
        services = make_services()
        page = obj(items=[_pod_spec()], metadata=obj(_continue=None))
        services.core_v1.list_pod_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods()

        assert result.details["flagged_pods"] == []
        assert result.details["statistics"]["pods_scanned"] == 1

    def test_pagination(self):
        services = make_services()
        page1 = obj(items=[_pod_spec()], metadata=obj(_continue="tok"))
        page2 = obj(items=[_pod_spec(privileged=True)], metadata=obj(_continue=None))
        services.core_v1.list_pod_for_all_namespaces.side_effect = [page1, page2]

        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods(max_pods=100)

        assert result.details["statistics"]["pods_scanned"] == 2
        assert len(result.details["flagged_pods"]) == 1

    def test_api_error(self):
        services = make_services()
        services.core_v1.list_pod_for_all_namespaces.side_effect = make_api_exception()
        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods()
        assert result.success is False

    def test_stops_mid_page_at_max_pods(self):
        services = make_services()
        page = obj(items=[_pod_spec(), _pod_spec()], metadata=obj(_continue=None))
        services.core_v1.list_pod_for_all_namespaces.return_value = page

        result = K8sIRHunt(services, DredgeConfig()).list_privileged_pods(max_pods=1)

        assert result.details["statistics"]["pods_scanned"] == 1
