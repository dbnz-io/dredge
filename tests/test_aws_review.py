import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from datetime import datetime, timezone
from unittest.mock import MagicMock

import botocore.exceptions
import pytest

from dredge.aws_ir.review import AwsIRReview, SERVICES
from dredge.aws_ir.models import OperationResult
from dredge.config import DredgeConfig


def _result(**details):
    r = OperationResult(operation="op", target="t", success=True)
    r.details.update(details)
    return r


def make_hunt():
    h = MagicMock()
    h.list_iam_admin_principals.return_value = _result(admin_users=[], admin_roles=[])
    h.get_iam_credential_report.return_value = _result(users=[])
    h.hunt_exposed_s3_buckets.return_value = _result(buckets=[])
    h.list_open_security_groups.return_value = _result(open_groups=[])
    h.list_public_snapshots.return_value = _result(snapshots=[])
    h.hunt_security_groups_by_ip.return_value = _result(matches=[])
    return h


def make_services():
    s = MagicMock()
    s._session.region_name = "us-east-1"
    s.sts.get_caller_identity.return_value = {"Account": "111122223333"}
    # empty everywhere by default
    s.rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]
    s.lambda_.get_paginator.return_value.paginate.return_value = [{"Functions": []}]
    s.iam.get_paginator.return_value.paginate.return_value = [{"Roles": [], "Users": []}]
    s.s3.list_buckets.return_value = {"Buckets": []}
    s.ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": [], "Vpcs": [], "FlowLogs": []}
    ]
    s.ec2.describe_instance_connect_endpoints.return_value = {"InstanceConnectEndpoints": []}
    s.ecs.get_paginator.return_value.paginate.return_value = [{"clusterArns": []}]
    # org controls all present/healthy by default -> no findings
    s.guardduty.list_detectors.return_value = {"DetectorIds": ["d-1"]}
    s.cloudtrail.describe_trails.return_value = {"trailList": [{"Name": "t", "TrailARN": "arn:t"}]}
    s.cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    s.securityhub.describe_hub.return_value = {"HubArn": "arn"}
    s.accessanalyzer.list_analyzers.return_value = {"analyzers": [{"arn": "a"}]}
    return s


def make_review(services=None, hunt=None):
    return AwsIRReview(services or make_services(), DredgeConfig(), hunt=hunt or make_hunt())


class TestTargeting:
    def test_service_target_only_runs_that_service(self):
        hunt = make_hunt()
        hunt.list_iam_admin_principals.return_value = _result(admin_users=["adm"], admin_roles=[])
        res = make_review(hunt=hunt).review(services=["iam"])
        assert {c.split("-")[0] for c in res.details["checks"]} == {"iam"}
        assert {f["service"] for f in res.details["findings"]} == {"iam"}

    def test_service_target_includes_tier2(self):
        res = make_review().review(services=["iam"])
        # iam has a tier-2 check (stale-access-keys)
        assert "iam-stale-access-keys" in res.details["checks"]

    def test_full_tier1_excludes_tier2(self):
        res = make_review().review(services="all", tiers=(1,))
        assert "iam-stale-access-keys" not in res.details["checks"]  # tier-2
        assert "iam-admin-principals" in res.details["checks"]        # tier-1

    def test_full_deep_includes_tier2(self):
        res = make_review().review(services="all", tiers=(1, 2))
        assert "iam-stale-access-keys" in res.details["checks"]

    def test_meta_records_services_and_tiers(self):
        res = make_review().review(services=["iam", "s3"], tiers=(1, 2))
        assert res.details["meta"]["services"] == ["iam", "s3"]
        assert res.details["meta"]["tiers"] == [1, 2]
        assert res.details["meta"]["account_id"] == "111122223333"


class TestOrchestration:
    def test_findings_sorted_by_severity(self):
        hunt = make_hunt()
        hunt.list_iam_admin_principals.return_value = _result(admin_users=["adm"], admin_roles=[])  # HIGH
        hunt.hunt_exposed_s3_buckets.return_value = _result(buckets=[{"bucket": "leaky", "exposed": True}])  # CRIT
        res = make_review(hunt=hunt).review(services="all", tiers=(1,))
        sevs = [f["severity"] for f in res.details["findings"]]
        assert sevs == sorted(sevs, key=lambda s: {"CRITICAL": 0, "HIGH": 1}.get(s, 9))
        assert sevs[0] == "CRITICAL"

    def test_check_error_isolated(self):
        svc = make_services()
        svc.guardduty.list_detectors.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListDetectors")
        res = make_review(services=svc).review(services=["org"], tiers=(1,))
        assert res.success is False
        assert res.details["checks"]["org-guardduty-enabled"]["status"] == "failed"
        assert res.details["checks"]["org-cloudtrail-logging"]["status"] == "ran"

    def test_recent_skipped_without_incident_start(self):
        res = make_review().review(services=["recent"])
        assert res.details["checks"]["recent-resources"]["status"] == "skipped"

    def test_sg_by_ip_skipped_without_ips(self):
        res = make_review().review(services=["ec2"])
        assert res.details["checks"]["ec2-sg-references-ip"]["status"] == "skipped"


class TestOrgControls:
    def test_guardduty_off_flagged(self):
        svc = make_services()
        svc.guardduty.list_detectors.return_value = {"DetectorIds": []}
        res = make_review(services=svc).review(services=["org"], tiers=(1,))
        ids = [f["check_id"] for f in res.details["findings"]]
        assert "org-guardduty-enabled" in ids

    def test_cloudtrail_not_logging_flagged(self):
        svc = make_services()
        svc.cloudtrail.get_trail_status.return_value = {"IsLogging": False}
        res = make_review(services=svc).review(services=["org"], tiers=(1,))
        assert any(f["check_id"] == "org-cloudtrail-logging" for f in res.details["findings"])

    def test_vpc_without_flow_logs_flagged(self):
        svc = make_services()
        # flow-logs paginator: first call (describe_flow_logs) empty, then describe_vpcs has one vpc
        svc.ec2.get_paginator.return_value.paginate.side_effect = [
            [{"FlowLogs": []}],
            [{"Vpcs": [{"VpcId": "vpc-abc"}]}],
        ]
        res = make_review(services=svc).review(services=["org"], tiers=(1,), include=["org-vpc-flow-logs"])
        f = res.details["findings"][0]
        assert f["check_id"] == "org-vpc-flow-logs" and f["resource_id"] == "vpc-abc"

    def test_security_hub_disabled_flagged(self):
        svc = make_services()
        svc.securityhub.describe_hub.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "InvalidAccessException", "Message": "not subscribed"}}, "DescribeHub")
        res = make_review(services=svc).review(services=["org"], tiers=(2,))
        assert any(f["check_id"] == "org-security-hub-enabled" for f in res.details["findings"])

    def test_healthy_org_no_findings(self):
        res = make_review().review(services=["org"], tiers=(1, 2))
        assert res.details["total_findings"] == 0


class TestServiceChecks:
    def test_console_without_mfa(self):
        hunt = make_hunt()
        hunt.get_iam_credential_report.return_value = _result(users=[
            {"user": "bob", "password_enabled": "true", "mfa_active": "false"},
            {"user": "carol", "password_enabled": "true", "mfa_active": "true"},
        ])
        res = make_review(hunt=hunt).review(services=["iam"], include=["iam-console-without-mfa"])
        assert [f["resource_id"] for f in res.details["findings"]] == ["bob"]
        assert res.details["findings"][0]["severity"] == "CRITICAL"

    def test_stale_access_keys(self):
        hunt = make_hunt()
        hunt.get_iam_credential_report.return_value = _result(users=[
            {"user": "old", "access_key_1_active": "true", "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00"},
            {"user": "fresh", "access_key_1_active": "true",
             "access_key_1_last_rotated": datetime.now(timezone.utc).isoformat()},
        ])
        res = make_review(hunt=hunt).review(services=["iam"], include=["iam-stale-access-keys"])
        assert [f["resource_id"] for f in res.details["findings"]] == ["old#key1"]

    def test_weak_role_trust(self):
        svc = make_services()
        svc.iam.get_paginator.return_value.paginate.return_value = [{"Roles": [
            {"RoleName": "Wild", "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]}},
            {"RoleName": "X", "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}}]}},
            {"RoleName": "Svc", "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]}},
        ]}]
        res = make_review(services=svc).review(services=["iam"], include=["iam-weak-role-trust"])
        by = {f["resource_id"]: f["severity"] for f in res.details["findings"]}
        assert by == {"Wild": "CRITICAL", "X": "HIGH"}

    def test_public_rds_and_encryption(self):
        svc = make_services()
        svc.rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": [
            {"DBInstanceIdentifier": "pub", "PubliclyAccessible": True, "StorageEncrypted": True},
            {"DBInstanceIdentifier": "unenc", "PubliclyAccessible": False, "StorageEncrypted": False},
        ]}]
        res = make_review(services=svc).review(services=["rds"])
        by = {(f["check_id"], f["resource_id"]) for f in res.details["findings"]}
        assert ("rds-public-instances", "pub") in by
        assert ("rds-unencrypted", "unenc") in by

    def test_imdsv1(self):
        svc = make_services()
        svc.ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": [
            {"Instances": [
                {"InstanceId": "i-v1", "MetadataOptions": {"HttpTokens": "optional"}},
                {"InstanceId": "i-v2", "MetadataOptions": {"HttpTokens": "required"}},
            ]}
        ]}]
        res = make_review(services=svc).review(services=["ec2"], include=["ec2-imdsv1-allowed"])
        assert [f["resource_id"] for f in res.details["findings"]] == ["i-v1"]

    def test_sg_references_ip(self):
        hunt = make_hunt()
        hunt.hunt_security_groups_by_ip.return_value = _result(matches=[{"group_id": "sg-1"}])
        res = make_review(hunt=hunt).review(services=["ec2"], ips=["1.2.3.4"], include=["ec2-sg-references-ip"])
        assert res.details["findings"][0]["resource_id"] == "sg-1"
        _, kwargs = hunt.hunt_security_groups_by_ip.call_args
        assert kwargs["direction"] == "both"

    def test_lambda_public_url(self):
        svc = make_services()
        svc.lambda_.get_paginator.return_value.paginate.return_value = [{"Functions": [
            {"FunctionName": "pub"}, {"FunctionName": "none"}]}]
        def cfg(FunctionName):
            if FunctionName == "pub":
                return {"AuthType": "NONE", "FunctionUrl": "https://x"}
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "no"}}, "GetFunctionUrlConfig")
        svc.lambda_.get_function_url_config.side_effect = cfg
        res = make_review(services=svc).review(services=["lambda"])
        assert [f["resource_id"] for f in res.details["findings"]] == ["pub"]
        assert res.details["findings"][0]["severity"] == "CRITICAL"

    def test_s3_public_and_no_encryption(self):
        hunt = make_hunt()
        hunt.hunt_exposed_s3_buckets.return_value = _result(buckets=[{"bucket": "leaky", "exposed": True}])
        svc = make_services()
        svc.s3.list_buckets.return_value = {"Buckets": [{"Name": "unenc"}, {"Name": "ok"}]}
        def enc(Bucket):
            if Bucket == "unenc":
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "no"}},
                    "GetBucketEncryption")
            return {"ServerSideEncryptionConfiguration": {}}
        svc.s3.get_bucket_encryption.side_effect = enc
        res = AwsIRReview(svc, DredgeConfig(), hunt=hunt).review(services=["s3"])
        by = {(f["check_id"], f["resource_id"]) for f in res.details["findings"]}
        assert ("s3-public-buckets", "leaky") in by
        assert ("s3-no-default-encryption", "unenc") in by
        assert ("s3-no-default-encryption", "ok") not in by

    def test_open_critical_ports_and_snapshots(self):
        hunt = make_hunt()
        hunt.list_open_security_groups.return_value = _result(open_groups=[{"group_id": "sg-1"}])
        hunt.list_public_snapshots.return_value = _result(snapshots=[{"snapshot_id": "snap-1"}])
        res = make_review(hunt=hunt).review(services=["ec2"],
                                            include=["ec2-open-critical-ports", "ec2-public-snapshots"])
        by = {(f["check_id"], f["severity"]) for f in res.details["findings"]}
        assert ("ec2-open-critical-ports", "CRITICAL") in by
        assert ("ec2-public-snapshots", "HIGH") in by
        # composed hunt asked for the critical port set
        _, kwargs = hunt.list_open_security_groups.call_args
        assert 22 in kwargs["ports"]

    def test_access_analyzer_missing_flagged(self):
        svc = make_services()
        svc.accessanalyzer.list_analyzers.return_value = {"analyzers": []}
        res = make_review(services=svc).review(services=["org"], tiers=(2,), include=["org-access-analyzer"])
        assert res.details["findings"][0]["check_id"] == "org-access-analyzer"

    def test_cloudtrail_no_trails_flagged(self):
        svc = make_services()
        svc.cloudtrail.describe_trails.return_value = {"trailList": []}
        res = make_review(services=svc).review(services=["org"], tiers=(1,), include=["org-cloudtrail-logging"])
        assert res.details["findings"][0]["check_id"] == "org-cloudtrail-logging"

    def test_weak_role_trust_decodes_url_encoded(self):
        import json, urllib.parse
        doc = urllib.parse.quote(json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]}))
        svc = make_services()
        svc.iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [{"RoleName": "Enc", "AssumeRolePolicyDocument": doc}]}]
        res = make_review(services=svc).review(services=["iam"], include=["iam-weak-role-trust"])
        assert res.details["findings"][0]["resource_id"] == "Enc"

    def test_recently_created(self):
        start = datetime(2026, 8, 30, tzinfo=timezone.utc)
        svc = make_services()
        svc.iam.get_paginator.return_value.paginate.side_effect = [
            [{"Users": [{"UserName": "newu", "CreateDate": datetime(2026, 8, 31, tzinfo=timezone.utc)}]}],
            [{"Roles": []}],
        ]
        svc.s3.list_buckets.return_value = {"Buckets": [
            {"Name": "newb", "CreationDate": datetime(2026, 8, 31, tzinfo=timezone.utc)},
            {"Name": "oldb", "CreationDate": datetime(2020, 1, 1, tzinfo=timezone.utc)},
        ]}
        res = make_review(services=svc).review(services=["recent"], incident_start=start)
        ids = sorted(f["resource_id"] for f in res.details["findings"])
        assert ids == ["newb", "newu"]


class TestReports:
    def _sample(self):
        return _result(
            findings=[{
                "severity": "CRITICAL", "service": "s3", "tier": 1, "check_id": "s3-public-buckets",
                "resource_type": "AWS::S3::Bucket", "resource_id": "leaky", "region": None,
                "created_time": None, "title": "Publicly exposed S3 bucket",
                "recommendation": "Enable BPA", "detail": {"reason": "ACL public"},
            }],
            summary={"CRITICAL": 1},
            checks={"s3-public-buckets": {"status": "ran", "count": 1}},
            meta={"account_id": "111122223333", "region": "us-east-1", "services": ["s3"],
                  "tiers": [1], "generated_at": "2026-08-31T00:00:00+00:00", "incident_start": None},
        )

    def test_csv(self, tmp_path):
        p = tmp_path / "r.csv"
        AwsIRReview.to_csv(self._sample(), str(p))
        text = p.read_text()
        assert text.splitlines()[0].startswith("severity,service,tier,check_id,")
        assert "leaky" in text and "s3" in text

    def test_html_self_contained_with_service_filter(self, tmp_path):
        p = tmp_path / "r.html"
        AwsIRReview.to_html(self._sample(), str(p))
        html = p.read_text()
        assert "<!doctype html>" in html
        assert "CRITICAL: 1" in html
        assert 'data-svc="s3"' in html            # per-service filtering
        assert "111122223333" in html
        assert "src=" not in html and "https://" not in html

    def test_html_escapes(self, tmp_path):
        res = self._sample()
        res.details["findings"][0]["resource_id"] = "<script>alert(1)</script>"
        p = tmp_path / "r.html"
        AwsIRReview.to_html(res, str(p))
        assert "<script>alert(1)</script>" not in p.read_text()


class TestNewChecks:
    def test_ecs_execute_command_enabled(self):
        svc = make_services()
        svc.ecs.get_paginator.return_value.paginate.side_effect = [
            [{"clusterArns": ["arn:cluster/c1"]}],   # list_clusters
            [{"serviceArns": ["arn:svc/s1"]}],       # list_services
        ]
        svc.ecs.describe_services.return_value = {"services": [
            {"serviceName": "exec-svc", "enableExecuteCommand": True},
            {"serviceName": "normal", "enableExecuteCommand": False},
        ]}
        res = make_review(services=svc).review(services=["ecs"])
        assert [f["resource_id"] for f in res.details["findings"]] == ["exec-svc"]
        assert res.details["findings"][0]["severity"] == "HIGH"

    def test_instance_connect_endpoint_flagged(self):
        svc = make_services()
        svc.ec2.describe_instance_connect_endpoints.return_value = {
            "InstanceConnectEndpoints": [{"InstanceConnectEndpointId": "eice-1", "VpcId": "vpc-1", "State": "available"}]
        }
        res = make_review(services=svc).review(services=["ec2"], include=["ec2-instance-connect-endpoints"])
        assert res.details["findings"][0]["resource_id"] == "eice-1"
        assert res.details["findings"][0]["severity"] == "MEDIUM"

    def test_instance_connect_pagination_terminates(self):
        # a non-string NextToken (e.g. a stray mock) must not infinite-loop
        svc = make_services()
        svc.ec2.describe_instance_connect_endpoints.return_value = {
            "InstanceConnectEndpoints": [], "NextToken": object()}
        res = make_review(services=svc).review(services=["ec2"], include=["ec2-instance-connect-endpoints"])
        assert res.details["checks"]["ec2-instance-connect-endpoints"]["status"] == "ran"


class TestMultiRegion:
    def _regional_services(self, per_region_dbs):
        svc = make_services()
        svc.resolve_enabled_regions.return_value = sorted(per_region_dbs)

        def regional(region):
            m = MagicMock()
            m.rds.meta.region_name = region
            m.rds.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [{"DBInstanceIdentifier": d, "PubliclyAccessible": True} for d in per_region_dbs[region]]}
            ]
            return m
        svc.regional.side_effect = regional
        return svc

    def test_all_regions_fans_out_regional_check(self):
        svc = self._regional_services({"us-east-1": ["db-a"], "eu-west-1": ["db-b"]})
        res = make_review(services=svc).review(services=["rds"], tiers=(1,), regions="all")
        svc.resolve_enabled_regions.assert_called_once()
        by = {(f["resource_id"], f["region"]) for f in res.details["findings"]}
        assert by == {("db-a", "us-east-1"), ("db-b", "eu-west-1")}
        assert res.details["checks"]["rds-public-instances"]["count"] == 2
        assert set(res.details["checks"]["rds-public-instances"]["by_region"]) == {"us-east-1", "eu-west-1"}
        assert res.details["meta"]["regions"] == ["eu-west-1", "us-east-1"]

    def test_explicit_regions_list_no_resolve(self):
        svc = self._regional_services({"us-east-1": ["db-a"], "eu-west-1": []})
        res = make_review(services=svc).review(services=["rds"], tiers=(1,), regions=["us-east-1", "eu-west-1"])
        svc.resolve_enabled_regions.assert_not_called()
        assert [f["region"] for f in res.details["findings"]] == ["us-east-1"]

    def test_per_region_error_recorded_partial(self):
        svc = make_services()
        svc.resolve_enabled_regions.return_value = ["us-east-1", "bad-1"]
        def regional(region):
            m = MagicMock(); m.rds.meta.region_name = region
            if region == "bad-1":
                m.rds.get_paginator.return_value.paginate.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeDBInstances")
            else:
                m.rds.get_paginator.return_value.paginate.return_value = [
                    {"DBInstances": [{"DBInstanceIdentifier": "ok", "PubliclyAccessible": True}]}]
            return m
        svc.regional.side_effect = regional
        res = make_review(services=svc).review(services=["rds"], tiers=(1,), regions="all")
        st = res.details["checks"]["rds-public-instances"]
        assert st["status"] == "partial"          # one region failed, one succeeded
        assert "error" in st["by_region"]["bad-1"]
        assert st["by_region"]["us-east-1"]["count"] == 1

    def test_global_checks_run_once_regardless_of_regions(self):
        hunt = make_hunt()
        hunt.list_iam_admin_principals.return_value = _result(admin_users=["adm"], admin_roles=[])
        svc = make_services()
        svc.resolve_enabled_regions.return_value = ["us-east-1", "eu-west-1"]
        svc.regional.side_effect = lambda r: make_services()
        res = AwsIRReview(svc, DredgeConfig(), hunt=hunt).review(services=["iam"], regions="all")
        # global iam check produced exactly one finding, not one-per-region
        assert [f["check_id"] for f in res.details["findings"]].count("iam-admin-principals") == 1


def test_services_constant_matches_checks():
    review = make_review()
    check_services = {svc for _id, svc, *_ in review._CHECKS}
    assert check_services == set(SERVICES)
