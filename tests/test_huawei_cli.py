import json
import os
from unittest.mock import MagicMock, patch

import pytest

from dredge import Dredge
from dredge.cli import build_parser
from dredge.huawei_ir import HuaweiAuthConfig, HuaweiIRNamespace
from dredge.huawei_ir.models import OperationResult


def args(*extra):
    return build_parser().parse_args(["--huawei-region", "cn-north-4", "--huawei-project-id", "project",
                                     "huawei", "hunt", "exposed-secrets", *extra])


def test_huawei_library_does_not_initialize_aws():
    config = HuaweiAuthConfig(region_name="cn-north-4", project_id="project")
    with patch("dredge.AwsSessionFactory") as factory:
        dredge = Dredge(huawei_config=config)
        factory.assert_not_called()
        assert isinstance(dredge.huawei_ir, HuaweiIRNamespace)
        dredge.huawei_ir.close()
        assert dredge.aws_ir is not None
        factory.assert_called_once()


def test_huawei_cli_passes_bounds_and_closes(capsys):
    parsed = args("--content-only", "--scan-lts", "group/stream", "--start-time", "2026-01-01T00:00:00Z",
                  "--end-time", "2026-01-01T01:00:00Z", "--content-max-api-calls", "5")
    with patch("dredge.huawei_ir.HuaweiIRNamespace") as namespace, patch("dredge.cli.Dredge") as aws:
        namespace.return_value.hunt.hunt_exposed_secrets.return_value = OperationResult("hunt", "test", True)
        parsed.func(parsed)
        kwargs = namespace.return_value.hunt.hunt_exposed_secrets.call_args.kwargs
        assert kwargs["include"] == []
        assert kwargs["content_max_api_calls"] == 5
        assert kwargs["start_time"].utcoffset().total_seconds() == 0
        namespace.return_value.close.assert_called_once()
        aws.assert_not_called()
        assert json.loads(capsys.readouterr().out)["success"]


@pytest.mark.parametrize("extra", [("--content-only",), ("--content-only", "--include", "cae"), ("--include", "cce")])
def test_cli_rejects_missing_or_conflicting_targets(extra):
    parsed = args(*extra)
    with pytest.raises(ValueError):
        parsed.func(parsed)


def test_raw_export_private_and_not_printed_or_overwritten(tmp_path, capsys):
    path = tmp_path / "raw.json"
    parsed = args("--unredacted", str(path))
    with patch("dredge.huawei_ir.HuaweiIRNamespace") as namespace:
        namespace.return_value.hunt.hunt_exposed_secrets.side_effect = [
            OperationResult("hunt", "test", True, {"raw_values": {"hash": "secret-value"}}),
            OperationResult("hunt", "test", True, {"raw_values": {"hash": "replacement"}}),
        ]
        parsed.func(parsed)
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert json.loads(path.read_text()) == {"hash": "secret-value"}
        assert "secret-value" not in capsys.readouterr().out
        with pytest.raises(ValueError, match="new writable file"):
            parsed.func(parsed)
        assert json.loads(path.read_text()) == {"hash": "secret-value"}


def test_cli_cce_uses_kubeconfig():
    parsed = build_parser().parse_args(["--huawei-region", "cn-north-4", "--k8s-context", "audit",
                                       "huawei", "hunt", "exposed-secrets", "--include", "cce"])
    with patch("dredge.k8s_ir.services.K8sClientFactory") as kube, patch("dredge.huawei_ir.HuaweiIRNamespace") as namespace:
        namespace.return_value.hunt.hunt_exposed_secrets.return_value = OperationResult("hunt", "test", True)
        parsed.func(parsed)
        assert kube.call_args.args[0].context == "audit"
        assert namespace.call_args.kwargs["k8s_services"] is not None


def test_cli_cce_accepts_token_environment(monkeypatch):
    from dredge.cli import build_k8s_config_from_args
    monkeypatch.setenv("CCE_TEST_TOKEN", "ephemeral-token")
    parsed = build_parser().parse_args(["--k8s-token-env-var", "CCE_TEST_TOKEN", "--k8s-api-server", "https://cluster.example",
                                       "huawei", "hunt", "exposed-secrets", "--include", "cce"])
    cfg = build_k8s_config_from_args(parsed)
    assert cfg.token == "ephemeral-token"


def test_batch_client_cache():
    from dredge.k8s_ir.services import K8sServiceRegistry
    with patch("dredge.k8s_ir.services.client.BatchV1Api") as batch:
        services = K8sServiceRegistry(MagicMock())
        assert services.batch_v1 is services.batch_v1
        batch.assert_called_once()


@pytest.mark.parametrize("position", ["root", "provider"])
def test_huawei_sweep_cli_both_flag_positions(position, capsys):
    flags = ["--huawei-profile", "all", "--huawei-region", "all", "--huawei-project-id", "all",
             "--huawei-profile-source", "koocli", "--huawei-timeout", "12"]
    argv = flags + ["huawei"] if position == "root" else ["huawei"] + flags
    parsed = build_parser().parse_args(argv + ["hunt", "exposed-secrets", "--sso-login", "--max-workers", "2"])
    with patch("dredge.huawei_ir.secret_sweep.hunt_exposed_secrets_multi_profile", return_value=OperationResult("sweep", "all", True)) as sweep, patch(
        "dredge.cli.Dredge") as aws, patch("dredge.huawei_ir.HuaweiIRNamespace") as single:
        parsed.func(parsed)
        assert sweep.call_args.kwargs["profiles"] == "all"
        assert sweep.call_args.kwargs["regions"] == "all"
        assert sweep.call_args.kwargs["project_id"] == "all"
        assert sweep.call_args.kwargs["profile_source"] == "koocli"
        assert sweep.call_args.kwargs["sso_login"] is True
        assert sweep.call_args.kwargs["max_workers"] == 2
        assert sweep.call_args.kwargs["timeout"] == 12
        aws.assert_not_called()
        single.assert_not_called()
    assert json.loads(capsys.readouterr().out)["success"]


def test_named_sso_profile_uses_cached_sweep_without_login(tmp_path, monkeypatch, capsys):
    path = tmp_path / "credentials"
    path.write_text("[sso.audit]\nsso_region=ap-southeast-1\n")
    monkeypatch.setenv("HUAWEICLOUD_SDK_CREDENTIALS_FILE", str(path))
    parsed = build_parser().parse_args(["huawei", "--huawei-profile", "audit", "hunt", "exposed-secrets"])
    with patch("dredge.huawei_ir.secret_sweep.hunt_exposed_secrets_multi_profile", return_value=OperationResult("sweep", "audit", True)) as sweep:
        parsed.func(parsed)
        assert sweep.call_args.kwargs["profiles"] == "audit"
        assert sweep.call_args.kwargs["sso_login"] is False


def test_sweep_raw_export_and_cce_guard(tmp_path, capsys):
    path = tmp_path / "raw.json"
    parsed = build_parser().parse_args(["huawei", "--huawei-profile", "all", "--huawei-region", "all", "hunt", "exposed-secrets",
                                        "--unredacted", str(path)])
    with patch("dredge.huawei_ir.secret_sweep.hunt_exposed_secrets_multi_profile", return_value=OperationResult(
        "sweep", "all", True, {"raw_values": {"hash": "raw-secret"}})):
        parsed.func(parsed)
    assert json.loads(path.read_text()) == {"hash": "raw-secret"}
    assert "raw-secret" not in capsys.readouterr().out
    assert path.stat().st_mode & 0o777 == 0o600
    parsed.include = ["cce"]
    with patch("dredge.k8s_ir.services.K8sClientFactory") as kube:
        with pytest.raises(ValueError, match="separate single-cluster"):
            parsed.func(parsed)
        kube.assert_not_called()
