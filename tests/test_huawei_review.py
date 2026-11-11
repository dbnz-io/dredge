import csv
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dredge.huawei_ir import HuaweiAuthConfig, HuaweiIRNamespace
from dredge.huawei_ir.review import CHECKS, HuaweiIRReview
from dredge.huawei_ir.services import HuaweiServiceError, HuaweiServiceRegistry, _plain


class Metadata:
    def __init__(self, responses=None):
        self.config = HuaweiAuthConfig(region_name="cn-north-4", project_id="project")
        self.auth = SimpleNamespace(get_credentials=lambda **kw: SimpleNamespace(project_id="project"))
        self.responses = responses or {}
        self.calls = []
        self.obs_regions = []

    def call(self, service, operation, **params):
        self.calls.append((service, operation, params))
        value = self.responses[(service, operation)]
        if isinstance(value, Exception):
            raise value
        return _plain(value(params) if callable(value) else value)

    def iam_call(self, operation, **params):
        return self.call("iam", operation, **params)

    def obs_call(self, operation, **params):
        return SimpleNamespace(body=self.call("obs", operation, **params))

    def obs_for_region(self, region):
        self.obs_regions.append(region)
        return self


def review(responses, **options):
    registry = Metadata(responses)
    result = HuaweiIRReview(registry, account_id="account").review(**options)
    return result, registry


def rule(**changes):
    return dict(id="rule", security_group_id="sg", direction="ingress", action="allow", enabled=True,
                ethertype="IPv4", remote_ip_prefix="0.0.0.0/0", protocol="tcp", multiport="22,3306:3389", **changes)


def test_iam_checks_metadata_only_and_shared_inventory():
    old = "2020-01-01T00:00:00Z"
    responses = {
        ("iam", "keystone_list_users"): {"users": [dict(id="u", enabled=True, access_mode="console")]},
        ("iam", "show_user_login_protect"): {"login_protect": {"enabled": False}},
        ("iam", "keystone_list_groups"): {"groups": [{"id": "g"}]},
        ("iam", "keystone_list_domain_permissions_for_group"): {"roles": [{"id": "r", "name": "te_admin"}]},
        ("iam", "list_permanent_access_keys"): {"credentials": [{"access": "DO-NOT-EXPORT-ABCD", "status": "active", "create_time": old}]},
        ("iam", "list_agencies"): {"agencies": [{"id": "a", "trust_domain_id": "outside", "create_time": old}]},
        ("iam", "show_domain_password_policy"): {"password_policy": {"minimum_password_length": 6}},
        ("iam", "show_user"): {"user": {"create_time": old}},
    }
    result, registry = review(responses, services=["iam", "recent"], scopes=["global"],
                              incident_start=datetime(2019, 1, 1, tzinfo=timezone.utc))
    assert result.success and result.details["complete"], result.details
    assert result.details["total_findings"] == 7
    assert len([c for c in registry.calls if c[1] == "keystone_list_users"]) == 1
    assert "DO-NOT-EXPORT" not in json.dumps(result.details)
    assert "ABCD" in json.dumps(result.details)
    assert all(f["account_id"] == "account" and f["region"] is None for f in result.details["findings"])


def test_iam_wire_policy_statement_keys():
    result, _ = review({
        ("iam", "keystone_list_groups"): {"groups": [{"id": "group"}]},
        ("iam", "keystone_list_domain_permissions_for_group"): {"roles": [
            {"id": "admin", "policy": {"Statement": [{"Effect": "Allow", "Action": "iam:*:*"}]}},
            {"id": "deny", "policy": {"Statement": [{"Effect": "Deny", "Action": ["*:*:*"]}]}},
            {"id": "reader", "policy": {"Statement": [{"Effect": "Allow", "Action": ["iam:users:listUsers"]}]}},
        ]},
    }, include=["iam-admin-groups"])
    assert result.success and result.details["complete"]
    assert result.details["total_findings"] == 1
    assert result.details["findings"][0]["detail"]["role_id"] == "admin"


@pytest.mark.parametrize("error,expected,complete", [
    (HuaweiServiceError("not configured", status=404, code="IAM.0004"), 1, True),
    (HuaweiServiceError("not found", status=404, code="OTHER"), 0, False),
    (HuaweiServiceError("denied", status=403, code="IAM.0004"), 0, False),
])
def test_only_documented_login_absence_is_a_finding(error, expected, complete):
    result, _ = review({("iam", "keystone_list_users"): {"users": [dict(id="u", enabled=True, access_mode="console")]},
                       ("iam", "show_user_login_protect"): error}, include=["iam-login-protection"])
    assert result.details["total_findings"] == expected
    assert result.details["complete"] is complete


@pytest.mark.parametrize("enabled,mode,protection,expected,complete", [
    (True, "default", {"enabled": True, "verification_method": "vmfa"}, 0, True),
    (True, "console", {"enabled": True, "verification_method": "sms"}, 1, True),
    (True, "console", {"enabled": True, "verification_method": "email"}, 1, True),
    (True, "programmatic", {}, 0, True),
    (False, "console", {}, 0, True),
    (True, None, {}, 0, False),
    (True, "console", {"enabled": "false"}, 0, False),
    (True, "console", {"enabled": True, "verification_method": "future"}, 0, False),
])
def test_login_modes(enabled, mode, protection, expected, complete):
    result, _ = review({("iam", "keystone_list_users"): {"users": [dict(id="u", enabled=enabled, access_mode=mode)]},
        ("iam", "show_user_login_protect"): {"login_protect": protection}}, include=["iam-login-protection"])
    assert result.details["total_findings"] == expected
    assert result.details["complete"] is complete


def test_obs_all_checks_use_bucket_region_and_no_object_reads():
    pytest.importorskip("obs")
    from obs.model import Bucket, GetBPSModel, GetBPAModel, Logging, ListBucketsResponse
    result, registry = review({
        ("obs", "listBuckets"): ListBucketsResponse(buckets=[Bucket(name="bucket", location="ap-southeast-1")], isTruncated=False),
        ("obs", "getBucketPublicStatus"): GetBPSModel(status=True),
        ("obs", "getBucketPublicAccessBlock"): GetBPAModel(blockPublicAcls=False, ignorePublicAcls=False, blockPublicPolicy=False, restrictPublicBuckets=False),
        ("obs", "getBucketEncryption"): HuaweiServiceError("absent", status=404, code="ServerSideEncryptionConfigurationNotFoundError"),
        ("obs", "getBucketLogging"): Logging(),
    }, services=["obs"])
    assert result.success and result.details["complete"], result.details
    assert result.details["total_findings"] == 4
    assert len(registry.calls) == 5
    assert registry.obs_regions == ["ap-southeast-1"] * 4
    assert all(f["region"] == "ap-southeast-1" for f in result.details["findings"])


def test_obs_missing_location_and_denied_configuration_are_incomplete():
    result, registry = review({("obs", "listBuckets"): {"buckets": [{"name": "unlocated"}, {"name": "known", "location": "cn-north-4"}]},
        ("obs", "getBucketEncryption"): HuaweiServiceError("denied", status=403)}, include=["obs-default-encryption"])
    assert not result.success and not result.details["complete"]
    assert not result.details["findings"]
    assert len(registry.calls) == 2


@pytest.mark.parametrize("changes,expected,complete", [
    ({}, 1, True), ({"action": "deny"}, 0, True), ({"enabled": False}, 0, True),
    ({"direction": "egress"}, 0, True), ({"remote_ip_prefix": "10.0.0.0/8"}, 0, True),
    ({"remote_ip_prefix": None, "remote_group_id": "other"}, 0, True),
    ({"remote_ip_prefix": None, "remote_address_group_id": "address-group"}, 0, True),
    ({"remote_ip_prefix": None, "ethertype": "IPv6", "multiport": None}, 1, True),
    ({"remote_ip_prefix": "::/0", "protocol": "udp"}, 1, True),
    ({"protocol": "icmp"}, 0, True), ({"multiport": "443"}, 0, True),
    ({"multiport": "33:22"}, 0, False), ({"remote_ip_prefix": "bad"}, 0, False),
    ({"enabled": None}, 0, False),
])
def test_security_group_rule_semantics(changes, expected, complete):
    data = {**rule(), **changes}
    result, _ = review({("vpc", "list_security_group_rules"): {"security_group_rules": [data], "page_info": {"next_marker": None}}},
                       include=["vpc-open-critical-ports"])
    assert result.success
    assert result.details["total_findings"] == expected
    assert result.details["complete"] is complete


def test_ip_match_and_flow_logs_share_rules_inventory():
    result, registry = review({
        ("vpc", "list_security_group_rules"): {"security_group_rules": [rule()], "page_info": {}},
        ("vpc", "list_vpcs"): {"vpcs": [{"id": "vpc"}], "page_info": {}},
        ("vpc_flow", "list_flow_logs"): {"flow_logs": []},
    }, services=["vpc"], ips=["203.0.113.1", "::1"])
    assert result.success and result.details["complete"]
    assert result.details["total_findings"] == 3
    assert len(registry.calls) == 3
    assert next(f for f in result.details["findings"] if f["check_id"] == "vpc-sg-references-ip")["detail"]["matches"] == ["203.0.113.1/32"]


def test_regional_compute_database_cluster_checks_and_cache():
    pytest.importorskip("huaweicloudsdkcce")
    from huaweicloudsdkecs.v2 import ServerDetail, ServerAddress
    from huaweicloudsdkrds.v3 import InstanceResponse
    from huaweicloudsdkcce.v3 import Cluster, ClusterMetadata, ClusterSpec, ClusterStatus, ClusterEndpoints, Authentication
    server = ServerDetail(id="s", status="ACTIVE", created="2025-01-01T00:00:00Z", addresses={"network": [ServerAddress(addr="203.0.113.2", os_ext_ip_stype="floating")]})
    db = InstanceResponse(id="db", public_ips=["203.0.113.3"], enable_ssl=False, disk_encryption_id="", type="Single", created="2025-01-01T00:00:00Z")
    cluster = Cluster(metadata=ClusterMetadata(uid="cluster", creation_timestamp="2025-01-01T00:00:00Z"),
        spec=ClusterSpec(authentication=Authentication(mode="x509"), enable_master_volume_encryption=False),
        status=ClusterStatus(endpoints=[ClusterEndpoints(type="External", url="https://example.invalid")]))
    result, registry = review({
        ("ecs", "list_servers_details"): {"servers": [server.to_dict()], "count": 1},
        ("evs", "list_volumes"): {"volumes": [{"id": "v", "encrypted": False}], "count": 1},
        ("rds", "list_instances"): {"instances": [db.to_dict()], "total_count": 1},
        ("rds", "show_backup_policy"): {"backup_policy": {"keep_days": 1}},
        ("cce", "list_clusters"): {"items": [cluster.to_dict()]},
    }, services=["ecs", "evs", "rds", "cce", "recent"], scopes=["regional"],
       incident_start=datetime(2024, 1, 1, tzinfo=timezone.utc))
    assert result.success and result.details["complete"], result.details
    assert result.details["total_findings"] == 12
    assert len(registry.calls) == 5
    assert all(f["project_id"] == "project" and f["region"] == "cn-north-4" for f in result.details["findings"])


def test_security_services_and_function_triggers():
    result, _ = review({
        ("functiongraph", "list_functions"): {"functions": [{"func_urn": "urn:function"}], "next_marker": "0"},
        ("functiongraph", "list_function_triggers"): {"body": [dict(trigger_id="t", trigger_type_code="APIG", trigger_status="ACTIVE", event_data={"auth": "NONE", "SECRET": "never-export"})]},
        ("cts", "list_trackers"): {"trackers": [{"id": "t1", "status": "disabled", "obs_info": {}, "lts": {"is_lts_enabled": False}},
            {"id": "t2", "status": "disabled", "obs_info": {"bucket_name": "archive"}, "is_support_validate": False}]},
        ("lts", "list_log_groups"): {"log_groups": [{"log_group_id": "log", "ttl_in_days": 7}]},
        ("hss", "list_host_status"): {"data_list": [{"host_id": "s1", "protect_status": "closed", "agent_status": "offline"}], "total_num": 1},
        ("ecs", "list_servers_details"): {"servers": [{"id": "s1", "status": "ACTIVE"}, {"id": "s2", "status": "ACTIVE"}], "count": 2},
        ("secmaster", "list_workspaces"): {"workspaces": [], "count": 0},
    }, services=["functiongraph", "cts", "lts", "hss", "secmaster"])
    assert result.success and result.details["complete"], result.details
    assert result.details["total_findings"] == 8
    assert "never-export" not in json.dumps(result.details)


@pytest.mark.parametrize("service,operation,key,check", [
    ("cts", "list_trackers", "trackers", "cts-system-tracker"),
    ("secmaster", "list_workspaces", "workspaces", "secmaster-workspaces"),
    ("hss", "list_host_status", "data_list", "hss-host-protection"),
])
@pytest.mark.parametrize("response", [RuntimeError("RAW-SECRET"), {}, None])
def test_missing_inventory_never_means_missing_security_control(service, operation, key, check, response):
    result, _ = review({(service, operation): response}, include=[check])
    assert not result.details["complete"]
    assert not result.details["findings"]
    assert "RAW-SECRET" not in json.dumps(result.details)


def test_permission_failure_preserves_findings_and_runs_remaining_checks():
    result, _ = review({
        ("rds", "list_instances"): {"instances": [{"id": "one", "enable_ssl": False}, {"id": "two", "enable_ssl": False}], "total_count": 2},
        ("rds", "show_backup_policy"): lambda p: (_ for _ in ()).throw(RuntimeError("RAW-SECRET")) if p["instance_id"] == "one" else {"backup_policy": {"keep_days": 0}},
    }, include=["rds-ssl-disabled", "rds-backup-retention"])
    assert not result.success and not result.details["complete"]
    assert result.details["total_findings"] == 3
    assert result.details["checks"]["rds-backup-retention"]["status"] == "partial"
    assert "RAW-SECRET" not in json.dumps(result.details)


@pytest.mark.parametrize("options,reason,count", [({"max_resources": 1}, "max_resources", 1), ({"max_api_calls": 1}, "max_api_calls", 0)])
def test_limits_preserve_evidence(options, reason, count):
    responses = {("rds", "list_instances"): {"instances": [{"id": "a"}, {"id": "b"}], "total_count": 2},
                 ("rds", "show_backup_policy"): {"backup_policy": {"keep_days": 0}}}
    result, _ = review(responses, include=["rds-backup-retention"], **options)
    assert result.success and not result.details["complete"]
    assert result.details["total_findings"] == count
    assert reason in result.details["checks"]["rds-backup-retention"]["stop_reasons"]


def test_time_budget_and_stalled_pagination():
    with patch("dredge.huawei_ir.review.time.monotonic", side_effect=[0, 200]):
        result, registry = review({}, include=["rds-public-instances"], max_seconds=1)
    assert not registry.calls and not result.details["complete"]
    assert result.details["checks"]["rds-public-instances"]["stop_reasons"] == ["max_seconds"]
    result, registry = review({("rds", "list_instances"): {"instances": [{"id": "a", "public_ips": ["203.0.113.1"]}], "total_count": 3}}, include=["rds-public-instances"])
    assert not result.details["complete"] and result.details["total_findings"] == 1
    assert len(registry.calls) == 2
    assert result.details["checks"]["rds-public-instances"]["stop_reasons"] == ["pagination_stalled"]


def test_page_info_and_obs_markers():
    responses = {("vpc", "list_security_group_rules"): lambda p: {"security_group_rules": [{**rule(), "id": p.get("marker", "first")}],
        "page_info": {"next_marker": None if p.get("marker") else "last"}}}
    result, registry = review(responses, include=["vpc-open-critical-ports"])
    assert result.details["complete"] and result.details["total_findings"] == 2
    assert registry.calls[-1][2]["marker"] == "last"
    result, _ = review({("obs", "listBuckets"): {"buckets": [], "isTruncated": True}}, services=["obs"])
    assert not result.details["complete"] and not result.details["findings"]


@pytest.mark.parametrize("options", [
    {"services": ["aws"]}, {"tiers": [True]}, {"scopes": []}, {"max_resources": 0}, {"max_api_calls": True},
    {"include": ["invented"]}, {"exclude": ["invented"]}, {"include": []}, {"tiers": []},
    {"ips": "1.2.3.4"}, {"ips": ["broken"]}, {"incident_start": datetime(2020, 1, 1)},
])
def test_validation_precedes_io(options):
    registry = Metadata()
    with pytest.raises(ValueError):
        HuaweiIRReview(registry).review(**options)
    assert not registry.calls


def test_selection_skips_conditional_checks_and_namespace_has_review():
    result, registry = review({}, services=["recent"])
    assert result.success and result.details["complete"] and not registry.calls
    assert all(c["status"] == "skipped" for c in result.details["checks"].values())
    namespace = HuaweiIRNamespace(HuaweiAuthConfig(region_name="cn-north-4", project_id="project"))
    assert isinstance(namespace.review, HuaweiIRReview)
    assert len(CHECKS) == 30


def test_csv_html_escape_untrusted_metadata_and_show_incomplete(tmp_path):
    result, _ = review({("rds", "list_instances"): {"instances": [{"id": '=HYPERLINK("bad")', "public_ips": ["</script><script>alert(1)</script>"]}, {"id": "unknown"}], "total_count": 2}}, include=["rds-public-instances"])
    csv_path, html_path = tmp_path / "review.csv", tmp_path / "review.html"
    HuaweiIRReview.to_csv(result, csv_path)
    HuaweiIRReview.to_html(result, html_path)
    row = next(csv.DictReader(csv_path.open()))
    assert row["resource_id"].startswith("'=")
    content = html_path.read_text()
    assert "INCOMPLETE" in content and "&lt;/script&gt;" in content
    assert "<script>alert" not in content
    assert 'src="http' not in content and 'href="http' not in content


@pytest.mark.parametrize("service,operation,params", [
    ("vpc", "list_security_group_rules", {"limit": 100, "marker": "m"}),
    ("vpc", "list_vpcs", {"limit": 100}), ("vpc_flow", "list_flow_logs", {"limit": 100, "marker": "m"}),
    ("rds", "list_instances", {"offset": 0, "limit": 100}), ("rds", "show_backup_policy", {"instance_id": "db"}),
    ("evs", "list_volumes", {"offset": 0, "limit": 100}), ("cce", "list_clusters", {"detail": "true"}),
    ("cts", "list_trackers", {"tracker_type": "system"}), ("lts", "list_log_groups", {}),
    ("hss", "list_host_status", {"offset": 0, "limit": 100, "region": "cn-north-4", "enterprise_project_id": "all_granted_eps"}),
    ("secmaster", "list_workspaces", {"project_id": "project", "offset": 0, "limit": 100}),
    ("functiongraph", "list_function_triggers", {"function_urn": "urn"}),
])
def test_new_sdk_request_contracts(service, operation, params):
    pytest.importorskip("huaweicloudsdksecmaster")
    registry = HuaweiServiceRegistry(HuaweiAuthConfig(region_name="cn-north-4", project_id="project", access_key_id="ak", secret_access_key="sk"))
    with patch("huaweicloudsdkcore.client.Client.do_http_request", return_value=SimpleNamespace(to_dict=lambda: {"ok": True})) as request:
        assert registry.call(service, operation, **params) == {"ok": True}
        assert request.call_count == 1
        assert registry._clients[service].get_credentials().project_id == "project"


def test_sdk_nested_models_and_error_codes_survive_boundary():
    pytest.importorskip("huaweicloudsdkecs")
    from huaweicloudsdkecs.v2 import ListServersDetailsResponse, ServerDetail, ServerAddress
    from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException
    registry = HuaweiServiceRegistry(HuaweiAuthConfig(region_name="cn-north-4", project_id="project", access_key_id="ak", secret_access_key="sk"))
    response = ListServersDetailsResponse(servers=[ServerDetail(id="s", addresses={"net": [ServerAddress(addr="203.0.113.1", os_ext_ip_stype="floating")]})])
    with patch("huaweicloudsdkcore.client.Client.do_http_request", return_value=response):
        data = registry.call("ecs", "list_servers_details")
    assert data["servers"][0]["addresses"]["net"][0]["os_ext_ip_stype"] == "floating"
    json.dumps(data)  # No SDK objects may remain in nested dict/list values.
    error = ClientRequestException(404, SimpleNamespace(error_code="IAM.0004", error_msg="DO-NOT-EXPORT", request_id="id", encoded_auth_msg=None))
    with patch("huaweicloudsdkcore.client.Client.do_http_request", side_effect=error):
        with pytest.raises(Exception) as caught:
            registry.iam_call("show_user_login_protect", user_id="u")
        assert caught.value.status == 404 and caught.value.code == "IAM.0004"
        assert "DO-NOT-EXPORT" not in str(caught.value)
