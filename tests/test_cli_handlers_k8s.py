"""Tests for dredge/cli.py's Kubernetes subcommand dispatch.

Mirrors the shared-table pattern in tests/test_cli_handlers.py: every k8s_ir
handler shares the shape parse argv -> build a Dredge instance -> call
exactly one dredge.k8s_ir.<namespace>.<method>(...) -> print_result(...).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dredge import cli as dredge_cli
from dredge.aws_ir.models import OperationResult

K8S_ARGS = ["--k8s-kubeconfig", "/fake/kubeconfig"]


def _get_nested(obj, path: str):
    target = obj
    for part in path.split("."):
        target = getattr(target, part)
    return target


def _run_handler(monkeypatch, capsys, argv, attr_path):
    mock_dredge_class = MagicMock()
    mock_instance = mock_dredge_class.return_value
    monkeypatch.setattr(dredge_cli, "Dredge", mock_dredge_class)

    target = _get_nested(mock_instance, attr_path)
    target.return_value = OperationResult(operation="op", target="t", success=True, details={"ok": True})

    parser = dredge_cli.build_parser()
    args = parser.parse_args(argv)
    args.func(args)

    return target, capsys.readouterr().out


CLI_HANDLER_CASES = [
    # --- response ---
    (
        "k8s-revoke-role-binding",
        [*K8S_ARGS, "k8s-revoke-role-binding", "rb1", "--namespace", "ns1"],
        "k8s_ir.response.revoke_role_binding",
        ("ns1", "rb1"),
        {},
    ),
    (
        "k8s-revoke-cluster-role-binding",
        [*K8S_ARGS, "k8s-revoke-cluster-role-binding", "crb1"],
        "k8s_ir.response.revoke_cluster_role_binding",
        ("crb1",),
        {},
    ),
    (
        "k8s-disable-service-account",
        [*K8S_ARGS, "k8s-disable-service-account", "sa1", "--namespace", "ns1"],
        "k8s_ir.response.disable_service_account",
        ("ns1", "sa1"),
        {},
    ),
    (
        "k8s-delete-service-account",
        [*K8S_ARGS, "k8s-delete-service-account", "sa1", "--namespace", "ns1"],
        "k8s_ir.response.delete_service_account",
        ("ns1", "sa1"),
        {},
    ),
    (
        "k8s-delete-pod",
        [*K8S_ARGS, "k8s-delete-pod", "pod1", "--namespace", "ns1"],
        "k8s_ir.response.delete_pod",
        ("ns1", "pod1"),
        {"grace_period_seconds": 0},
    ),
    (
        "k8s-scale-deployment",
        [*K8S_ARGS, "k8s-scale-deployment", "dep1", "--namespace", "ns1", "--replicas", "2"],
        "k8s_ir.response.scale_deployment",
        ("ns1", "dep1", 2),
        {},
    ),
    (
        "k8s-cordon-node",
        [*K8S_ARGS, "k8s-cordon-node", "node1"],
        "k8s_ir.response.cordon_node",
        ("node1",),
        {},
    ),
    (
        "k8s-drain-node",
        [*K8S_ARGS, "k8s-drain-node", "node1"],
        "k8s_ir.response.drain_node",
        ("node1",),
        {"grace_period_seconds": 30, "ignore_daemonsets": True},
    ),
    (
        "k8s-delete-node",
        [*K8S_ARGS, "k8s-delete-node", "node1"],
        "k8s_ir.response.delete_node",
        ("node1",),
        {},
    ),
    (
        "k8s-quarantine-pod",
        [*K8S_ARGS, "k8s-quarantine-pod", "pod1", "--namespace", "ns1"],
        "k8s_ir.response.quarantine_pod",
        ("ns1", "pod1"),
        {"policy_name": "dredge-forensic-isolation"},
    ),
    (
        "k8s-quarantine-namespace",
        [*K8S_ARGS, "k8s-quarantine-namespace", "--namespace", "ns1"],
        "k8s_ir.response.quarantine_namespace",
        ("ns1",),
        {"policy_name": "dredge-forensic-isolation"},
    ),
    (
        "k8s-delete-secret",
        [*K8S_ARGS, "k8s-delete-secret", "sec1", "--namespace", "ns1"],
        "k8s_ir.response.delete_secret",
        ("ns1", "sec1"),
        {},
    ),
    (
        "k8s-label-resource-pod",
        [*K8S_ARGS, "k8s-label-resource", "pod", "pod1", "--namespace", "ns1", "--label", "a=b"],
        "k8s_ir.response.label_resource",
        ("pod", "ns1", "pod1", {"a": "b"}),
        {},
    ),
    (
        "k8s-label-resource-node",
        [*K8S_ARGS, "k8s-label-resource", "node", "node1", "--label", "a=b"],
        "k8s_ir.response.label_resource",
        ("node", None, "node1", {"a": "b"}),
        {},
    ),
    # --- forensics ---
    (
        "k8s-get-pod-manifest",
        [*K8S_ARGS, "k8s-get-pod-manifest", "pod1", "--namespace", "ns1"],
        "k8s_ir.forensics.get_pod_manifest",
        ("ns1", "pod1"),
        {},
    ),
    (
        "k8s-get-pod-logs",
        [*K8S_ARGS, "k8s-get-pod-logs", "pod1", "--namespace", "ns1"],
        "k8s_ir.forensics.get_pod_logs",
        ("ns1", "pod1"),
        {"container": None, "previous": False, "tail_lines": None},
    ),
    (
        "k8s-get-pod-events",
        [*K8S_ARGS, "k8s-get-pod-events", "pod1", "--namespace", "ns1"],
        "k8s_ir.forensics.get_pod_events",
        ("ns1", "pod1"),
        {},
    ),
    (
        "k8s-describe-node",
        [*K8S_ARGS, "k8s-describe-node", "node1"],
        "k8s_ir.forensics.describe_node",
        ("node1",),
        {},
    ),
    (
        "k8s-capture-workload-manifest",
        [*K8S_ARGS, "k8s-capture-workload-manifest", "deployment", "dep1", "--namespace", "ns1"],
        "k8s_ir.forensics.capture_workload_manifest",
        ("deployment", "ns1", "dep1"),
        {},
    ),
    (
        "k8s-list-pods-on-node",
        [*K8S_ARGS, "k8s-list-pods-on-node", "node1"],
        "k8s_ir.forensics.list_pods_on_node",
        ("node1",),
        {},
    ),
    (
        "k8s-exec-pod-command",
        [*K8S_ARGS, "k8s-exec-pod-command", "pod1", "ps", "aux", "--namespace", "ns1"],
        "k8s_ir.forensics.exec_pod_command",
        ("ns1", "pod1", ["ps", "aux"]),
        {"container": None},
    ),
    # --- hunt ---
    (
        "k8s-hunt-events",
        [*K8S_ARGS, "k8s-hunt-events", "--namespace", "ns1"],
        "k8s_ir.hunt.list_events",
        (),
        {
            "namespace": "ns1",
            "involved_object_kind": None,
            "involved_object_name": None,
            "reason": None,
            "event_type": None,
            "start_time": None,
            "end_time": None,
            "max_events": 500,
        },
    ),
    (
        "k8s-hunt-role-bindings-for-subject",
        [*K8S_ARGS, "k8s-hunt-role-bindings-for-subject", "--kind", "User", "--name", "alice", "--namespace", "ns1"],
        "k8s_ir.hunt.list_role_bindings_for_subject",
        (),
        {"kind": "User", "name": "alice", "namespace": "ns1"},
    ),
    (
        "k8s-hunt-pods-by-service-account",
        [*K8S_ARGS, "k8s-hunt-pods-by-service-account", "--service-account", "sa1", "--namespace", "ns1"],
        "k8s_ir.hunt.list_pods_by_service_account",
        ("ns1", "sa1"),
        {},
    ),
    (
        "k8s-hunt-privileged-pods",
        [*K8S_ARGS, "k8s-hunt-privileged-pods"],
        "k8s_ir.hunt.list_privileged_pods",
        (),
        {"max_pods": 500},
    ),
]


@pytest.mark.parametrize(
    "argv,attr_path,expected_args,expected_kwargs",
    [(c[1], c[2], c[3], c[4]) for c in CLI_HANDLER_CASES],
    ids=[c[0] for c in CLI_HANDLER_CASES],
)
def test_handler_dispatches_to_dredge(monkeypatch, capsys, argv, attr_path, expected_args, expected_kwargs):
    target, out = _run_handler(monkeypatch, capsys, argv, attr_path)
    target.assert_called_once_with(*expected_args, **expected_kwargs)
    assert '"success": true' in out


class TestBuildK8sConfigFromArgs:
    def _namespace(self, **overrides):
        import argparse
        base = dict(
            k8s_token=None,
            k8s_in_cluster=False,
            k8s_kubeconfig=None,
            k8s_context=None,
            k8s_token_env_var="K8S_TOKEN",
            k8s_api_server=None,
            k8s_ca_cert=None,
            k8s_insecure_skip_tls_verify=False,
            k8s_namespace=None,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_nothing_set_returns_none(self):
        assert dredge_cli.build_k8s_config_from_args(self._namespace()) is None

    def test_kubeconfig_set_returns_config(self):
        result = dredge_cli.build_k8s_config_from_args(self._namespace(k8s_kubeconfig="/path"))
        assert result.kubeconfig_path == "/path"

    def test_token_env_var_used_when_no_explicit_token(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN_VAR", "secret-token")
        result = dredge_cli.build_k8s_config_from_args(
            self._namespace(k8s_in_cluster=False, k8s_kubeconfig="/path", k8s_token_env_var="MY_TOKEN_VAR"),
        )
        assert result.token == "secret-token"

    def test_explicit_token_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("K8S_TOKEN", "from-env")
        result = dredge_cli.build_k8s_config_from_args(self._namespace(k8s_token="explicit-token"))
        assert result.token == "explicit-token"

    def test_insecure_flag_maps_to_verify_ssl_false(self):
        result = dredge_cli.build_k8s_config_from_args(
            self._namespace(k8s_token="t", k8s_insecure_skip_tls_verify=True),
        )
        assert result.verify_ssl is False


class TestK8sDredgeMissingConfig:
    def test_raises_system_exit_when_unconfigured(self):
        parser = dredge_cli.build_parser()
        args = parser.parse_args(["k8s-cordon-node", "node1"])
        with pytest.raises(SystemExit):
            dredge_cli._k8s_dredge(args)


class TestK8sNamespaceHelper:
    def test_uses_subcommand_namespace(self):
        parser = dredge_cli.build_parser()
        args = parser.parse_args([*K8S_ARGS, "k8s-delete-pod", "p1", "--namespace", "explicit-ns"])
        assert dredge_cli._k8s_namespace(args) == "explicit-ns"

    def test_falls_back_to_global_namespace(self):
        parser = dredge_cli.build_parser()
        args = parser.parse_args([*K8S_ARGS, "--k8s-namespace", "global-ns", "k8s-delete-pod", "p1"])
        assert dredge_cli._k8s_namespace(args) == "global-ns"

    def test_raises_when_neither_set(self):
        parser = dredge_cli.build_parser()
        args = parser.parse_args([*K8S_ARGS, "k8s-delete-pod", "p1"])
        with pytest.raises(SystemExit):
            dredge_cli._k8s_namespace(args)
