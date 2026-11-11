import base64
import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from dredge.huawei_ir.config import HuaweiAuthConfig
from dredge.huawei_ir.hunt import HuaweiIRHunt
from dredge.huawei_ir.services import HuaweiServiceError

TOKEN = "ghp_" + "aB3cD4" * 6
PAIR = {"HUAWEICLOUD_SDK_AK": "ABCDEFGHIJKLMNOPQRST", "HUAWEICLOUD_SDK_SK": "aB7/" * 10}
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def services():
    services = MagicMock()
    services.config = HuaweiAuthConfig(region_name="cn-north-4", project_id="project")
    return services


def payload(result):
    return json.dumps(result.details)


def test_functiongraph_masking_pagination_and_dedup(services):
    services.call.side_effect = [
        {"functions": [{"func_urn": "one"}], "next_marker": 1},
        {"user_data": json.dumps({**PAIR, "_encrypt_PASSWORD": TOKEN}), "encrypted_user_data": "hidden"},
        {"functions": [{"func_urn": "two"}]},
        {"user_data": json.dumps(PAIR)},
    ]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["functiongraph"])
    assert result.success
    assert len(result.details["findings"]) == 2
    assert all(f["severity"] == "CRITICAL" for f in result.details["findings"])
    assert TOKEN not in payload(result)
    assert PAIR["HUAWEICLOUD_SDK_SK"] not in payload(result)
    assert result.details["uninspected"][0]["reason"] == "encrypted_or_masked_environment"
    assert not result.details["complete"]
    assert services.call.call_args_list[2].kwargs["marker"] == "1"


def test_default_scanners_and_partial_failures(services):
    services.call.side_effect = [HuaweiServiceError("functiongraph failed (HTTP 403)"), {"servers": []}, {"items": []}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets()
    assert not result.success
    assert set(result.details["scanners"]) == {"functiongraph", "ecs_user_data", "cae"}
    services.obs_call.assert_not_called()


def test_ecs_user_data_and_missing_visibility(services):
    services.call.side_effect = [{"servers": [{"id": "one"}, {"id": "two"}]},
                                {"server": {"os_ext_srv_att_ruser_data": base64.b64encode(f"TOKEN={TOKEN}".encode()).decode()}},
                                {"server": {}}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["ecs_user_data"])
    assert len(result.details["findings"]) == 1
    assert result.details["uninspected"][0]["reason"] == "user_data_not_returned"
    assert TOKEN not in payload(result)


def test_cae_environment_and_references(services):
    services.call.side_effect = [{"items": [{"id": "env"}]}, {"items": [{"id": "app"}]},
                                {"items": [{"id": "component"}], "total_count": 1},
                                {"items": [{"type": "env", "data": {"spec": {"envs": {"TOKEN": TOKEN},
                                                                                 "env_references": [{"name": "csms"}]}}}]}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["cae"])
    assert len(result.details["findings"]) == 1
    assert result.details["uninspected"][0]["reason"] == "secret_references_not_resolved"
    assert services.call.call_args.kwargs["x_environment_id"] == "env"
    assert services.call.call_args.kwargs["display_mode"] == "latestEffective"


def test_configuration_resource_limit(services):
    services.call.side_effect = [{"functions": [{"func_urn": "one"}, {"func_urn": "two"}]}, {"user_data": "{}"}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["functiongraph"], max_resources=1)
    assert result.details["scanners"]["functiongraph"]["stop_reasons"] == ["max_resources"]
    assert services.call.call_count == 2


@pytest.mark.parametrize("kwargs", [
    {"scan_obs": ["obs://bucket/"]}, {"scan_obs": ["obs://bucket/*"]},
    {"scan_obs": "obs://bucket/path"}, {"scan_lts": ["group/*"]},
    {"scan_lts": ["group/stream"]}, {"scan_lts": ["group/stream"], "start_time": START, "end_time": START + timedelta(days=2)},
    {"start_time": START}, {"include": ["unknown"]}, {"include": ["cce"]},
    {"scan_k8s_secrets": True}, {"content_max_api_calls": 0}, {"max_resources": True},
])
def test_validation_before_api(services, kwargs):
    with pytest.raises(ValueError):
        HuaweiIRHunt(services).hunt_exposed_secrets(**kwargs)
    services.call.assert_not_called()
    services.obs_call.assert_not_called()


def obs_response(body):
    return SimpleNamespace(status=200, body=body)


def test_obs_range_dedup_and_closed_stream(services):
    content = f"TOKEN={TOKEN}".encode()
    body = io.BytesIO(content)
    item = {"key": "target/.env", "size": len(content), "etag": "version"}
    services.obs_call.side_effect = [obs_response({"contents": [item]}), obs_response({"response": body}),
                                   obs_response({"contents": [item]})]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/", "obs://bucket/target/.env"])
    assert body.closed
    assert result.details["scanners"]["obs"]["scanned"] == 1
    assert result.details["scanners"]["obs"]["skipped"] == 1
    assert services.obs_call.call_args_list[1].kwargs["headers"] == {"range": f"0-{len(content)-1}", "if_match": "version"}
    assert TOKEN not in payload(result)


def test_obs_budget_counts_failed_calls(services):
    services.obs_call.side_effect = HuaweiServiceError("denied")
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/path", "obs://other/path"], content_max_api_calls=1)
    assert not result.success
    assert services.obs_call.call_count == 1
    assert "max_api_calls" in result.details["scanners"]["obs"]["stop_reasons"]


def test_obs_skips_archives_large_and_outside_prefix(services):
    services.obs_call.return_value = obs_response({"contents": [
        {"key": "target/archive", "size": 20, "storageClass": "COLD"},
        {"key": "target/large", "size": 2000}, {"key": "outside", "size": 20}]})
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"], obs_max_object_bytes=100)
    assert not result.success
    assert services.obs_call.call_count == 1
    assert result.details["scanners"]["obs"]["skipped"] == 2


def test_obs_byte_budget_before_download(services):
    services.obs_call.return_value = obs_response({"contents": [{"key": "target/.env", "size": 200}]})
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"], content_max_bytes=100)
    assert services.obs_call.call_count == 1
    assert result.details["scanners"]["obs"]["stop_reasons"] == ["max_bytes"]


def test_lts_cursor_and_line_pagination_does_not_stop_at_complete_page(services):
    services.call.side_effect = [
        {"logs": [{"content": TOKEN, "line_num": "123", "labels": {"__time__": "456"}}], "is_query_complete": True, "scroll_id": "cursor"},
        {"logs": [{"content": "nothing", "line_num": "124"}], "is_query_complete": True},
    ]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_lts=["group/stream"], start_time=START, end_time=START+timedelta(hours=1))
    assert result.details["scanners"]["lts"]["scanned"] == 2
    body = services.call.call_args.kwargs["body"]
    assert body["scroll_id"] == "cursor"
    assert body["line_num"] == "123"
    assert body["time__"] == "456"
    assert body["search_type"] == "forwards"
    assert body["highlight"] is False
    assert TOKEN not in payload(result)


def test_lts_event_limit_and_raw_opt_in(services):
    services.call.return_value = {"logs": [{"content": TOKEN, "line_num": "123"}], "is_query_complete": True}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_lts=["g/s"], start_time=START, end_time=START+timedelta(hours=1), lts_max_events=1, keep_raw=True)
    assert services.call.call_count == 1
    assert result.details["scanners"]["lts"]["stop_reasons"] == ["max_events"]
    assert TOKEN in result.details["raw_values"].values()


def test_lts_stalled_incomplete_page_reported(services):
    services.call.return_value = {"logs": [], "is_query_complete": False}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_lts=["g/s"], start_time=START, end_time=START+timedelta(hours=1))
    assert result.details["scanners"]["lts"]["stop_reasons"] == ["pagination_stalled"]
    assert not result.details["complete"]


def test_csms_is_inventory_and_never_raw(services):
    services.call.return_value = {"version": {"secret_string": TOKEN}}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_csms=["named-secret"], keep_raw=True)
    assert result.details["findings"] == []
    assert result.details["raw_values"] == {}
    assert result.details["inventory"][0]["assessment"] == "intended_secret_storage"
    assert TOKEN not in payload(result)
    assert services.call.call_args.kwargs == {"secret_name": "named-secret", "version_id": "latest"}


def test_cce_scans_cluster_and_secrets_only_when_requested(services):
    k8s = MagicMock()
    for api in ("core_v1", "apps_v1", "batch_v1"):
        getattr(k8s, api).configure_mock(**{})
    empty = MagicMock()
    empty.to_dict.return_value = {"items": []}
    for api, kinds in (("core_v1", ("pod", "config_map", "secret")),
                       ("apps_v1", ("deployment", "stateful_set", "daemon_set", "replica_set")),
                       ("batch_v1", ("job", "cron_job"))):
        for kind in kinds:
            getattr(getattr(k8s, api), f"list_namespaced_{kind}").return_value = empty
    pod = MagicMock()
    pod.to_dict.return_value = {"items": [{"metadata": {"name": "pod", "namespace": "test"}, "spec": {"containers": [{"name": "app", "env": [{"name": "TOKEN", "value": TOKEN}]}]}}]}
    k8s.core_v1.list_namespaced_pod.return_value = pod
    secret = MagicMock()
    secret.to_dict.return_value = {"items": [{"metadata": {"name": "intended", "namespace": "test"}, "data": {"token": base64.b64encode(TOKEN.encode()).decode()}}]}
    k8s.core_v1.list_namespaced_secret.return_value = secret
    hunt = HuaweiIRHunt(services, k8s_services=k8s)
    result = hunt.hunt_exposed_secrets(include=["cce"], k8s_namespace="test")
    k8s.core_v1.list_namespaced_secret.assert_not_called()
    assert len(result.details["findings"]) == 1
    assert TOKEN not in payload(result)
    result = hunt.hunt_exposed_secrets(include=["cce"], k8s_namespace="test", scan_k8s_secrets=True)
    assert len(result.details["inventory"]) == 1
    assert len(result.details["findings"]) == 1
    assert TOKEN not in payload(result)
    services.call.assert_not_called()


@pytest.mark.parametrize("env", ["not-json", "[]"])
def test_invalid_environment_is_visible_gap(services, env):
    services.call.side_effect = [{"functions": [{"func_urn": "one"}]}, {"user_data": env}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["functiongraph"])
    assert result.details["uninspected"][0]["reason"] == "unparseable_environment"


def test_functiongraph_repeated_page_bounded(services):
    services.call.side_effect = [{"functions": [{"func_urn": "one"}], "next_marker": 1}, {"user_data": "{}"},
                                {"functions": [{"func_urn": "one"}], "next_marker": 1}, {"user_data": "{}"}]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["functiongraph"])
    assert result.details["scanners"]["functiongraph"]["stop_reasons"] == ["pagination_stalled"]


def test_ecs_pagination_and_invalid_data(services):
    items = [{"id": str(i)} for i in range(100)]
    def call(service, operation, **kwargs):
        if operation == "list_servers_details":
            return {"servers": items if not kwargs.get("marker") else []}
        return {"server": {"os_ext_srv_att_ruser_data": "not base64"}}
    services.call.side_effect = call
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=["ecs_user_data"])
    assert len(result.details["uninspected"]) == 100
    assert services.call.call_args.kwargs["marker"] == "99"


@pytest.mark.parametrize("content,reason", [(b"binary\x00data", "binary_or_compressed_object"), (b"\xff\xfe", "non_utf8_object")])
def test_obs_binary_contents_are_reported_and_closed(services, content, reason):
    body = io.BytesIO(content)
    services.obs_call.side_effect = [obs_response({"contents": [{"key": "target/data", "size": len(content)}]}),
                                   obs_response({"response": body})]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"])
    assert body.closed
    assert result.details["uninspected"][0]["reason"] == reason


def test_obs_partial_body_and_request_failure(services):
    body = io.BytesIO(b"short")
    services.obs_call.side_effect = [obs_response({"contents": [{"key": "target/a", "size": 20}, {"key": "target/b", "size": 20}]}),
                                   obs_response({"response": body}), HuaweiServiceError("denied")]
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"])
    assert not result.success
    assert len(result.errors) == 2
    assert body.closed


def test_obs_object_cap_and_stalled_listing(services):
    page = obs_response({"contents": [], "is_truncated": True, "next_marker": "repeat"})
    services.obs_call.return_value = page
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"])
    assert services.obs_call.call_count == 2
    assert result.details["scanners"]["obs"]["stop_reasons"] == ["pagination_stalled"]
    services.obs_call.return_value = obs_response({"contents": [{"key": "target/archive", "size": 20, "storageClass": "COLD"}], "is_truncated": True, "next_marker": "next"})
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_obs=["obs://bucket/target/"], obs_max_objects=1)
    assert result.details["scanners"]["obs"]["stop_reasons"] == ["max_objects"]


def test_lts_processing_bytes_cap_and_time_limit(services, monkeypatch):
    services.call.return_value = {"logs": [{"content": TOKEN}]}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_lts=["g/s"], start_time=START,
                                                      end_time=START+timedelta(hours=1), content_max_bytes=5)
    assert result.details["scanners"]["lts"]["stop_reasons"] == ["max_bytes"]
    assert result.details["findings"] == []
    monkeypatch.setattr("dredge.secret_scanning.time.monotonic", lambda: float("inf"))
    services.call.reset_mock()
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_lts=["g/s"], start_time=START,
                                                      end_time=START+timedelta(hours=1))
    services.call.assert_not_called()
    assert "max_seconds" in result.details["scanners"]["lts"]["stop_reasons"]


def test_csms_limit_and_missing_value(services):
    services.call.return_value = {"version": {}}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_csms=["one", "two"], max_resources=1)
    assert result.details["uninspected"][0]["reason"] == "secret_value_not_returned"
    assert result.details["scanners"]["csms"]["stop_reasons"] == ["max_resources"]
    services.call.return_value = {"version": {"secret_string": TOKEN}}
    result = HuaweiIRHunt(services).hunt_exposed_secrets(include=[], scan_csms=["one"], content_max_bytes=1)
    assert result.details["scanners"]["csms"]["stop_reasons"] == ["max_bytes"]


def test_cce_configmaps_workload_templates_and_rbac_failure(services):
    from kubernetes.client.exceptions import ApiException
    k8s = MagicMock()
    def response(data):
        return SimpleNamespace(to_dict=lambda: data)
    for api, kinds in (("core_v1", ("pod", "config_map")),
                       ("apps_v1", ("deployment", "stateful_set", "daemon_set", "replica_set")),
                       ("batch_v1", ("job", "cron_job"))):
        for kind in kinds:
            getattr(getattr(k8s, api), f"list_{kind}_for_all_namespaces").return_value = response({"items": []})
    k8s.core_v1.list_pod_for_all_namespaces.side_effect = ApiException(status=403, reason=TOKEN)
    k8s.core_v1.list_config_map_for_all_namespaces.side_effect = [
        response({"items": [{"metadata": {"namespace": "ns", "name": "cfg"},
                             "binary_data": {"script": base64.b64encode(f"TOKEN={TOKEN}".encode()).decode(), "bad": "!"}}],
                  "metadata": {"_continue": "next"}}), response({"items": []}),
    ]
    k8s.batch_v1.list_cron_job_for_all_namespaces.return_value = response({"items": [{
        "metadata": {"namespace": "ns", "name": "cron"},
        "spec": {"job_template": {"spec": {"template": {"spec": {
            "init_containers": [{"name": "setup", "command": [f"TOKEN={TOKEN}"]}]
        }}}}}
    }]})
    result = HuaweiIRHunt(services, k8s_services=k8s).hunt_exposed_secrets(include=["cce"])
    assert not result.success
    assert TOKEN not in json.dumps(result.errors)
    assert TOKEN not in payload(result)
    assert len(result.details["findings"]) >= 1
    assert result.details["uninspected"][0]["reason"] == "non_text_or_invalid_base64"
    assert k8s.core_v1.list_config_map_for_all_namespaces.call_args.kwargs["_continue"] == "next"
    sources = [source for finding in result.details["findings"] for source in finding["sources"]]
    assert any(source["location_type"] == "kubernetes_config_map_content" for source in sources)
    assert any(source["location_type"] == "kubernetes_command" for source in sources)
