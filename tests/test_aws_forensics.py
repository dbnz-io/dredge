import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
import gzip

from datetime import date, datetime, timezone
from unittest.mock import MagicMock
import pytest
from botocore.exceptions import ClientError

from dredge.aws_ir.forensics import AwsIRForensics
from dredge.config import DredgeConfig


def make_client_error(code="AccessDenied", op="Operation"):
    return ClientError({"Error": {"Code": code, "Message": "simulated"}}, op)


def make_services():
    return MagicMock()


class TestGetEbsSnapshot:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRForensics(services, DredgeConfig(dry_run=True)).get_ebs_snapshot("vol-123")
        assert result.details.get("dry_run") is True
        services.ec2.create_snapshot.assert_not_called()

    def test_happy_path_returns_snapshot_id(self):
        services = make_services()
        services.ec2.create_snapshot.return_value = {"SnapshotId": "snap-abc"}
        result = AwsIRForensics(services, DredgeConfig()).get_ebs_snapshot("vol-123")
        assert result.success is True
        assert result.details["snapshot_id"] == "snap-abc"

    def test_custom_description(self):
        services = make_services()
        services.ec2.create_snapshot.return_value = {"SnapshotId": "snap-x"}
        AwsIRForensics(services, DredgeConfig()).get_ebs_snapshot("vol-1", description="IR case 42")
        services.ec2.create_snapshot.assert_called_once_with(
            VolumeId="vol-1", Description="IR case 42"
        )

    def test_api_error_records_failure(self):
        services = make_services()
        services.ec2.create_snapshot.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_ebs_snapshot("vol-bad")
        assert result.success is False
        assert result.errors


def _make_ec2_with_instance(block_devices=None):
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {
        "Reservations": [{
            "Instances": [{
                "RootDeviceName": "/dev/xvda",
                "BlockDeviceMappings": block_devices or [
                    {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root"}},
                    {"DeviceName": "/dev/sdb", "Ebs": {"VolumeId": "vol-data"}},
                ],
            }]
        }]
    }
    ec2.create_snapshot.side_effect = (
        lambda VolumeId, Description: {"SnapshotId": f"snap-{VolumeId}"}
    )
    return ec2


class TestSnapshotInstanceVolumes:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRForensics(services, DredgeConfig(dry_run=True)).snapshot_instance_volumes("i-123")
        assert result.details.get("dry_run") is True

    def test_snapshots_all_volumes_by_default(self):
        ec2 = _make_ec2_with_instance()
        services = make_services()
        services.ec2 = ec2
        result = AwsIRForensics(services, DredgeConfig()).snapshot_instance_volumes("i-123")
        assert result.success is True
        assert "vol-root" in result.details["snapshots"]
        assert "vol-data" in result.details["snapshots"]

    def test_skips_root_when_include_root_false(self):
        ec2 = _make_ec2_with_instance()
        services = make_services()
        services.ec2 = ec2
        result = AwsIRForensics(services, DredgeConfig()).snapshot_instance_volumes(
            "i-123", include_root=False
        )
        assert "vol-root" not in result.details["snapshots"]
        assert "vol-data" in result.details["snapshots"]

    def test_non_ebs_mappings_skipped(self):
        ec2 = _make_ec2_with_instance(block_devices=[
            {"DeviceName": "/dev/xvda", "Ebs": None},
            {"DeviceName": "/dev/sdb", "Ebs": {"VolumeId": "vol-data"}},
        ])
        services = make_services()
        services.ec2 = ec2
        result = AwsIRForensics(services, DredgeConfig()).snapshot_instance_volumes("i-123")
        assert list(result.details["snapshots"].keys()) == ["vol-data"]

    def test_no_instance_found_records_fatal(self):
        services = make_services()
        services.ec2.describe_instances.return_value = {"Reservations": []}
        result = AwsIRForensics(services, DredgeConfig()).snapshot_instance_volumes("i-bad")
        assert result.success is False
        assert any("Fatal error" in e for e in result.errors)

    def test_snapshot_failure_per_volume_recorded(self):
        ec2 = _make_ec2_with_instance(block_devices=[
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-bad"}}
        ])
        ec2.create_snapshot.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2
        result = AwsIRForensics(services, DredgeConfig()).snapshot_instance_volumes("i-123")
        assert result.success is False
        assert any("vol-bad" in e for e in result.errors)


class TestGetLambdaEnvironment:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRForensics(services, DredgeConfig(dry_run=True)).get_lambda_environment("fn")
        assert result.details.get("dry_run") is True

    def test_happy_path_returns_env_vars(self):
        services = make_services()
        services.lambda_.get_function_configuration.return_value = {
            "Environment": {"Variables": {"KEY": "val", "SECRET": "shh"}}
        }
        result = AwsIRForensics(services, DredgeConfig()).get_lambda_environment("fn")
        assert result.success is True
        assert result.details["environment_variables"] == {"KEY": "val", "SECRET": "shh"}

    def test_with_qualifier(self):
        services = make_services()
        services.lambda_.get_function_configuration.return_value = {
            "Environment": {"Variables": {}}
        }
        AwsIRForensics(services, DredgeConfig()).get_lambda_environment("fn", qualifier="prod")
        services.lambda_.get_function_configuration.assert_called_once_with(
            FunctionName="fn", Qualifier="prod"
        )

    def test_no_environment_key_returns_empty(self):
        services = make_services()
        services.lambda_.get_function_configuration.return_value = {}
        result = AwsIRForensics(services, DredgeConfig()).get_lambda_environment("fn")
        assert result.success is True
        assert result.details["environment_variables"] == {}

    def test_api_error_records_failure(self):
        services = make_services()
        services.lambda_.get_function_configuration.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_lambda_environment("fn")
        assert result.success is False
        assert result.errors


# =====================================================================
# New forensics methods added in second implementation pass
# =====================================================================


class TestEnableVpcFlowLogs:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRForensics(services, DredgeConfig(dry_run=True)).enable_vpc_flow_logs("vpc-123")
        assert result.details.get("dry_run") is True
        services.ec2.create_flow_logs.assert_not_called()

    def test_happy_path_cloudwatch(self):
        services = make_services()
        services.ec2.create_flow_logs.return_value = {
            "FlowLogIds": ["fl-001"],
            "Unsuccessful": [],
        }
        result = AwsIRForensics(services, DredgeConfig()).enable_vpc_flow_logs(
            "vpc-123", deliver_logs_permission_arn="arn:aws:iam::123:role/FlowLogs"
        )
        assert result.success is True
        assert result.details["flow_log_ids"] == ["fl-001"]
        call_kwargs = services.ec2.create_flow_logs.call_args[1]
        assert call_kwargs["ResourceType"] == "VPC"
        assert call_kwargs["LogDestinationType"] == "cloud-watch-logs"
        assert call_kwargs["DeliverLogsPermissionArn"] == "arn:aws:iam::123:role/FlowLogs"

    def test_s3_destination(self):
        services = make_services()
        services.ec2.create_flow_logs.return_value = {"FlowLogIds": ["fl-002"], "Unsuccessful": []}
        AwsIRForensics(services, DredgeConfig()).enable_vpc_flow_logs(
            "vpc-123",
            log_destination_type="s3",
            log_destination="arn:aws:s3:::my-logs-bucket",
        )
        call_kwargs = services.ec2.create_flow_logs.call_args[1]
        assert call_kwargs["LogDestinationType"] == "s3"
        assert call_kwargs["LogDestination"] == "arn:aws:s3:::my-logs-bucket"

    def test_unsuccessful_records_error(self):
        services = make_services()
        services.ec2.create_flow_logs.return_value = {
            "FlowLogIds": [],
            "Unsuccessful": [{"Error": {"Message": "already exists"}}],
        }
        result = AwsIRForensics(services, DredgeConfig()).enable_vpc_flow_logs("vpc-123")
        assert result.success is False
        assert result.errors

    def test_api_error_records_failure(self):
        services = make_services()
        services.ec2.create_flow_logs.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).enable_vpc_flow_logs("vpc-123")
        assert result.success is False


class TestCaptureSsmSessionHistory:
    def test_happy_path(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {
            "Sessions": [
                {"SessionId": "s-001", "Target": "i-123", "Status": "Terminated"},
                {"SessionId": "s-002", "Target": "i-123", "Status": "Terminated"},
            ],
            "NextToken": None,
        }
        result = AwsIRForensics(services, DredgeConfig()).capture_ssm_session_history(instance_id="i-123")
        assert result.success is True
        assert result.details["statistics"]["total_sessions"] == 2
        call_kwargs = services.ssm.describe_sessions.call_args[1]
        assert call_kwargs["State"] == "History"
        assert {"key": "Target", "value": "i-123"} in call_kwargs["Filters"]

    def test_no_filters_queries_all(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {"Sessions": [], "NextToken": None}
        AwsIRForensics(services, DredgeConfig()).capture_ssm_session_history()
        call_kwargs = services.ssm.describe_sessions.call_args[1]
        assert "Filters" not in call_kwargs

    def test_paginates(self):
        services = make_services()
        services.ssm.describe_sessions.side_effect = [
            {"Sessions": [{"SessionId": "s-001"}], "NextToken": "tok"},
            {"Sessions": [{"SessionId": "s-002"}], "NextToken": None},
        ]
        result = AwsIRForensics(services, DredgeConfig()).capture_ssm_session_history()
        assert len(result.details["sessions"]) == 2

    def test_owner_filter_applied(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {"Sessions": [], "NextToken": None}
        AwsIRForensics(services, DredgeConfig()).capture_ssm_session_history(owner="arn:aws:iam::123:user/alice")
        call_kwargs = services.ssm.describe_sessions.call_args[1]
        assert {"key": "Owner", "value": "arn:aws:iam::123:user/alice"} in call_kwargs["Filters"]

    def test_api_error_records_failure(self):
        services = make_services()
        services.ssm.describe_sessions.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).capture_ssm_session_history()
        assert result.success is False


class TestGetCloudtrailStatus:
    def _make_ct(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "my-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
                "HomeRegion": "us-east-1",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
                "S3BucketName": "my-log-bucket",
            }]
        }
        ct.get_trail_status.return_value = {
            "IsLogging": True,
            "LatestDeliveryTime": None,
            "LatestDeliveryError": None,
        }
        ct.get_event_selectors.return_value = {"EventSelectors": [{"ReadWriteType": "All"}]}
        return ct

    def test_happy_path(self):
        services = make_services()
        services.cloudtrail = self._make_ct()
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is True
        trails = result.details["trails"]
        assert len(trails) == 1
        assert trails[0]["is_logging"] is True
        assert trails[0]["log_file_validation_enabled"] is True
        assert result.details["statistics"]["active_trails"] == 1

    def test_no_trails(self):
        services = make_services()
        services.cloudtrail.describe_trails.return_value = {"trailList": []}
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is True
        assert result.details["statistics"]["total_trails"] == 0
        assert result.details["statistics"]["active_trails"] == 0

    def test_get_trail_status_error_captured(self):
        services = make_services()
        ct = self._make_ct()
        ct.get_trail_status.side_effect = make_client_error()
        services.cloudtrail = ct
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is True  # non-fatal per-trail error
        assert "status_error" in result.details["trails"][0]

    def test_get_event_selectors_error_captured(self):
        services = make_services()
        ct = self._make_ct()
        ct.get_event_selectors.side_effect = make_client_error()
        services.cloudtrail = ct
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is True  # non-fatal per-trail error
        assert "event_selectors_error" in result.details["trails"][0]

    def test_describe_trails_error_records_fatal(self):
        services = make_services()
        services.cloudtrail.describe_trails.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is False


# =====================================================================
# Coverage completion pass: functions with no test class before this
# =====================================================================


def _make_user_resp(user_name="alice"):
    return {"User": {"UserName": user_name, "UserId": "AID123", "Arn": f"arn:aws:iam::123:user/{user_name}"}}


class TestGetIamUserDetail:
    def test_happy_path_all_sections(self):
        services = make_services()
        services.iam.get_user.return_value = _make_user_resp()
        services.iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]}
        services.iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{"AccessKeyId": "AKIA1", "Status": "Active"}]
        }
        services.iam.list_groups_for_user.return_value = {"Groups": [{"GroupName": "admins"}]}

        result = AwsIRForensics(services, DredgeConfig()).get_iam_user_detail("alice")
        assert result.success is True
        assert result.details["user"]["user_name"] == "alice"
        assert result.details["mfa_devices"][0]["serial"] == "arn:aws:iam::123:mfa/alice"
        assert result.details["access_keys"][0]["access_key_id"] == "AKIA1"
        assert result.details["groups"] == ["admins"]

    def test_get_user_fatal_error_returns_early(self):
        services = make_services()
        services.iam.get_user.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_iam_user_detail("alice")
        assert result.success is False
        assert "user" not in result.details
        services.iam.list_mfa_devices.assert_not_called()

    def test_mfa_error_non_fatal(self):
        services = make_services()
        services.iam.get_user.return_value = _make_user_resp()
        services.iam.list_mfa_devices.side_effect = make_client_error()
        services.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        services.iam.list_groups_for_user.return_value = {"Groups": []}
        result = AwsIRForensics(services, DredgeConfig()).get_iam_user_detail("alice")
        assert result.success is True
        assert "mfa_error" in result.details

    def test_access_keys_error_non_fatal(self):
        services = make_services()
        services.iam.get_user.return_value = _make_user_resp()
        services.iam.list_mfa_devices.return_value = {"MFADevices": []}
        services.iam.list_access_keys.side_effect = make_client_error()
        services.iam.list_groups_for_user.return_value = {"Groups": []}
        result = AwsIRForensics(services, DredgeConfig()).get_iam_user_detail("alice")
        assert result.success is True
        assert "access_keys_error" in result.details

    def test_groups_error_non_fatal(self):
        services = make_services()
        services.iam.get_user.return_value = _make_user_resp()
        services.iam.list_mfa_devices.return_value = {"MFADevices": []}
        services.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        services.iam.list_groups_for_user.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_iam_user_detail("alice")
        assert result.success is True
        assert "groups_error" in result.details


class TestGetS3BucketPolicy:
    def test_happy_path_all_sections_present(self):
        services = make_services()
        services.s3.get_bucket_policy.return_value = {"Policy": '{"Statement": []}'}
        services.s3.get_bucket_acl.return_value = {"Owner": {"ID": "o1"}, "Grants": [{"Permission": "READ"}]}
        services.s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
        }
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert result.details["policy"] == '{"Statement": []}'
        assert result.details["acl"]["owner"] == {"ID": "o1"}
        assert result.details["public_access_block"] == {"BlockPublicAcls": True}

    def test_no_such_bucket_policy_gives_none(self):
        services = make_services()
        services.s3.get_bucket_policy.side_effect = make_client_error(code="NoSuchBucketPolicy")
        services.s3.get_bucket_acl.return_value = {"Owner": {}, "Grants": []}
        services.s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert result.details["policy"] is None
        assert "policy_error" not in result.details

    def test_generic_policy_error_recorded(self):
        services = make_services()
        services.s3.get_bucket_policy.side_effect = make_client_error(code="AccessDenied")
        services.s3.get_bucket_acl.return_value = {"Owner": {}, "Grants": []}
        services.s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert "policy_error" in result.details

    def test_acl_error_recorded(self):
        services = make_services()
        services.s3.get_bucket_policy.side_effect = make_client_error(code="NoSuchBucketPolicy")
        services.s3.get_bucket_acl.side_effect = make_client_error()
        services.s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert "acl_error" in result.details

    def test_no_such_public_access_block_gives_none(self):
        services = make_services()
        services.s3.get_bucket_policy.side_effect = make_client_error(code="NoSuchBucketPolicy")
        services.s3.get_bucket_acl.return_value = {"Owner": {}, "Grants": []}
        services.s3.get_public_access_block.side_effect = make_client_error(
            code="NoSuchPublicAccessBlockConfiguration"
        )
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert result.details["public_access_block"] is None
        assert "public_access_block_error" not in result.details

    def test_generic_public_access_block_error_recorded(self):
        services = make_services()
        services.s3.get_bucket_policy.side_effect = make_client_error(code="NoSuchBucketPolicy")
        services.s3.get_bucket_acl.return_value = {"Owner": {}, "Grants": []}
        services.s3.get_public_access_block.side_effect = make_client_error(code="AccessDenied")
        result = AwsIRForensics(services, DredgeConfig()).get_s3_bucket_policy("my-bucket")
        assert result.success is True
        assert "public_access_block_error" in result.details


class TestGetEc2UserData:
    def test_happy_path_decodes_base64(self):
        import base64
        services = make_services()
        encoded = base64.b64encode(b"#!/bin/bash\necho hi").decode()
        services.ec2.describe_instance_attribute.return_value = {"UserData": {"Value": encoded}}
        result = AwsIRForensics(services, DredgeConfig()).get_ec2_user_data("i-123")
        assert result.success is True
        assert result.details["user_data_decoded"] == "#!/bin/bash\necho hi"

    def test_no_user_data_returns_none(self):
        services = make_services()
        services.ec2.describe_instance_attribute.return_value = {"UserData": {}}
        result = AwsIRForensics(services, DredgeConfig()).get_ec2_user_data("i-123")
        assert result.success is True
        assert result.details["user_data_base64"] is None
        assert result.details["user_data_decoded"] is None

    def test_malformed_base64_decoded_is_none(self):
        services = make_services()
        services.ec2.describe_instance_attribute.return_value = {"UserData": {"Value": "not-valid-base64!!"}}
        result = AwsIRForensics(services, DredgeConfig()).get_ec2_user_data("i-123")
        assert result.success is True
        assert result.details["user_data_decoded"] is None

    def test_api_error_records_failure(self):
        services = make_services()
        services.ec2.describe_instance_attribute.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_ec2_user_data("i-123")
        assert result.success is False


class TestListRecentlyActiveRoles:
    def _make_role(self, name, last_used_date=None, region="us-east-1"):
        role = {"RoleName": name, "Arn": f"arn:aws:iam::123:role/{name}"}
        if last_used_date is not None:
            role["RoleLastUsed"] = {"LastUsedDate": last_used_date, "Region": region}
        return role

    def test_role_used_inside_window_included(self):
        from datetime import datetime, timezone
        services = make_services()
        recent = datetime.now(timezone.utc)
        services.iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [self._make_role("recent-role", last_used_date=recent)]}
        ]
        result = AwsIRForensics(services, DredgeConfig()).list_recently_active_roles(hours=24)
        assert result.success is True
        assert result.details["roles"][0]["role_name"] == "recent-role"
        assert result.details["statistics"]["active_in_window"] == 1

    def test_role_used_outside_window_excluded(self):
        from datetime import datetime, timezone, timedelta
        services = make_services()
        stale = datetime.now(timezone.utc) - timedelta(hours=48)
        services.iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [self._make_role("stale-role", last_used_date=stale)]}
        ]
        result = AwsIRForensics(services, DredgeConfig()).list_recently_active_roles(hours=24)
        assert result.details["roles"] == []
        assert result.details["statistics"]["roles_scanned"] == 1

    def test_role_never_used_excluded(self):
        services = make_services()
        services.iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [self._make_role("never-used-role")]}
        ]
        result = AwsIRForensics(services, DredgeConfig()).list_recently_active_roles()
        assert result.details["roles"] == []

    def test_max_roles_cutoff(self):
        from datetime import datetime, timezone
        services = make_services()
        recent = datetime.now(timezone.utc)
        roles = [self._make_role(f"role-{i}", last_used_date=recent) for i in range(5)]
        services.iam.get_paginator.return_value.paginate.return_value = [{"Roles": roles}]
        result = AwsIRForensics(services, DredgeConfig()).list_recently_active_roles(max_roles=2)
        assert result.details["statistics"]["roles_scanned"] == 2

    def test_api_error_records_failure(self):
        services = make_services()
        services.iam.get_paginator.return_value.paginate.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).list_recently_active_roles()
        assert result.success is False
        assert result.details["roles"] == []


class TestGetRdsParameterGroup:
    def test_happy_path(self):
        services = make_services()
        services.rds.get_paginator.return_value.paginate.return_value = [
            {"Parameters": [{"ParameterName": "log_bin", "ParameterValue": "OFF", "Source": "engine-default"}]}
        ]
        result = AwsIRForensics(services, DredgeConfig()).get_rds_parameter_group("my-pg")
        assert result.success is True
        assert result.details["parameters"][0]["name"] == "log_bin"
        assert result.details["group_name"] == "my-pg"
        assert result.details["statistics"]["total_parameters"] == 1
        services.rds.get_paginator.assert_called_once_with("describe_db_parameters")

    def test_max_params_cutoff(self):
        services = make_services()
        params = [{"ParameterName": f"p{i}", "ParameterValue": "x"} for i in range(10)]
        services.rds.get_paginator.return_value.paginate.return_value = [{"Parameters": params}]
        result = AwsIRForensics(services, DredgeConfig()).get_rds_parameter_group("my-pg", max_params=3)
        assert len(result.details["parameters"]) == 3

    def test_api_error_returns_early(self):
        services = make_services()
        services.rds.get_paginator.return_value.paginate.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_rds_parameter_group("my-pg")
        assert result.success is False
        assert "parameters" not in result.details


class TestCaptureGuarddutyFindingDetail:
    def test_no_finding_ids_raises(self):
        services = make_services()
        with pytest.raises(ValueError):
            AwsIRForensics(services, DredgeConfig()).capture_guardduty_finding_detail("detector-1")

    def test_happy_path(self):
        services = make_services()
        services.guardduty.get_findings.return_value = {
            "Findings": [{"Id": "f-1", "Severity": 8.0}]
        }
        result = AwsIRForensics(services, DredgeConfig()).capture_guardduty_finding_detail("detector-1", "f-1")
        assert result.success is True
        assert result.details["findings"][0]["Id"] == "f-1"
        assert result.details["statistics"]["total"] == 1
        services.guardduty.get_findings.assert_called_once_with(
            DetectorId="detector-1", FindingIds=["f-1"]
        )

    def test_multiple_finding_ids(self):
        services = make_services()
        services.guardduty.get_findings.return_value = {"Findings": []}
        AwsIRForensics(services, DredgeConfig()).capture_guardduty_finding_detail("detector-1", "f-1", "f-2")
        services.guardduty.get_findings.assert_called_once_with(
            DetectorId="detector-1", FindingIds=["f-1", "f-2"]
        )

    def test_api_error_records_failure(self):
        services = make_services()
        services.guardduty.get_findings.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).capture_guardduty_finding_detail("detector-1", "f-1")
        assert result.success is False


class TestDownloadS3Logs:
    def _make_s3(self, pages, objects_by_key):
        s3 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = pages
        s3.get_paginator.return_value = paginator

        def get_object(Bucket, Key):
            return {"Body": MagicMock(read=MagicMock(return_value=objects_by_key[Key]))}

        s3.get_object.side_effect = get_object
        return s3

    def test_flattens_keys_and_gunzips(self, tmp_path):
        import gzip

        services = make_services()
        raw_json = b'{"eventName": "ConsoleLogin"}'
        objects = {
            "AWSLogs/123/CloudTrail/us-east-1/2026/08/25/file1.json.gz": gzip.compress(raw_json),
            "AWSLogs/123/CloudTrail/eu-west-1/2026/08/25/file1.json.gz": gzip.compress(raw_json),
        }
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path)
        )

        assert result.success is True
        assert result.details["downloaded"] == 2
        written = sorted(os.listdir(tmp_path))
        assert len(written) == 2
        # flattened, no nested directories created
        assert all(os.path.isfile(tmp_path / f) for f in written)
        for f in written:
            assert (tmp_path / f).read_bytes() == raw_json
            assert f.endswith(".json")
            assert "/" not in f

    def test_skips_non_matching_suffixes(self, tmp_path):
        services = make_services()
        objects = {"logs/readme.txt": b"hello"}
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.details["downloaded"] == 0
        assert result.details["skipped"] == 1
        assert os.listdir(tmp_path) == []

    def test_empty_suffixes_downloads_everything(self, tmp_path):
        services = make_services()
        objects = {"logs/readme.txt": b"hello"}
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path), suffixes=()
        )

        assert result.details["downloaded"] == 1

    def test_object_download_error_recorded_but_others_continue(self, tmp_path):
        services = make_services()
        objects = {
            "a/one.json": b"{}",
            "b/two.json": b"{}",
        }
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        s3 = self._make_s3(pages, objects)

        def get_object(Bucket, Key):
            if Key == "a/one.json":
                raise make_client_error()
            return {"Body": MagicMock(read=MagicMock(return_value=objects[Key]))}

        s3.get_object.side_effect = get_object
        services.s3 = s3

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.success is False
        assert result.details["downloaded"] == 1
        assert "a/one.json" in result.details["failed"]

    def test_list_error_records_failure(self, tmp_path):
        services = make_services()
        paginator = MagicMock()
        paginator.paginate.side_effect = make_client_error()
        services.s3.get_paginator.return_value = paginator

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.success is False

    def test_skips_folder_placeholder_keys(self, tmp_path):
        services = make_services()
        objects = {"logs/one.json": b"{}"}
        pages = [{"Contents": [{"Key": "logs/"}, {"Key": "logs/one.json"}]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.details["downloaded"] == 1

    def test_gzip_decompress_error_recorded(self, tmp_path):
        services = make_services()
        objects = {"logs/bad.json.gz": b"not actually gzip"}
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.success is False
        assert "gzip decompress failed" in result.details["failed"]["logs/bad.json.gz"]

    def test_flattened_name_collision_is_deduped(self, tmp_path):
        services = make_services()
        objects = {
            "a_b/c.json": b"first",
            "a/b_c.json": b"second",
        }
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path)
        )

        assert result.details["downloaded"] == 2
        written = sorted(os.listdir(tmp_path))
        assert written == ["a_b_c.json", "a_b_c__1.json"]

    def test_max_objects_stops_mid_page(self, tmp_path):
        services = make_services()
        objects = {"logs/one.json": b"1", "logs/two.json": b"2"}
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", destination=str(tmp_path), max_objects=1,
        )

        assert result.details["downloaded"] == 1

    def test_cloudtrail_digest_skipped_by_default(self, tmp_path):
        services = make_services()
        objects = {
            "AWSLogs/123/CloudTrail/us-east-1/2026/08/25/log.json.gz": gzip.compress(b"{}"),
            "AWSLogs/123/CloudTrail-Digest/us-east-1/2026/08/25/digest.json.gz": gzip.compress(b"{}"),
        }
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path)
        )

        assert result.details["downloaded"] == 1
        assert result.details["digest_skipped"] == 1
        written = os.listdir(tmp_path)
        assert len(written) == 1
        assert all("CloudTrail-Digest" not in f for f in written)

    def test_cloudtrail_digest_included_when_opted_in(self, tmp_path):
        services = make_services()
        objects = {
            "AWSLogs/123/CloudTrail/us-east-1/2026/08/25/log.json.gz": gzip.compress(b"{}"),
            "AWSLogs/123/CloudTrail-Digest/us-east-1/2026/08/25/digest.json.gz": gzip.compress(b"{}"),
        }
        pages = [{"Contents": [{"Key": k} for k in objects]}]
        services.s3 = self._make_s3(pages, objects)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path),
            exclude_cloudtrail_digest=False,
        )

        assert result.details["downloaded"] == 2
        assert "digest_skipped" not in result.details


def _make_hierarchical_s3(common_prefixes_by_prefix, objects_by_leaf_prefix, object_bodies=None):
    """S3 double for the date-filtered discovery path: routes list_objects_v2
    paginate() calls by whether Delimiter='/' was passed (folder discovery)
    or not (real object listing under a leaf prefix). Every folder-discovery
    prefix queried is recorded on s3.delimited_prefixes_queried, so tests can
    assert that pruned branches were never listed at all."""
    object_bodies = object_bodies or {}
    s3 = MagicMock()
    s3.delimited_prefixes_queried = []

    def get_paginator(name):
        paginator = MagicMock()

        def paginate(**kwargs):
            prefix = kwargs.get("Prefix", "")
            if kwargs.get("Delimiter") == "/":
                s3.delimited_prefixes_queried.append(prefix)
                children = common_prefixes_by_prefix.get(prefix, [])
                return [{"CommonPrefixes": [{"Prefix": c} for c in children]}]
            keys = objects_by_leaf_prefix.get(prefix, [])
            return [{"Contents": [{"Key": k} for k in keys]}]

        paginator.paginate.side_effect = paginate
        return paginator

    s3.get_paginator.side_effect = get_paginator

    def get_object(Bucket, Key):
        return {"Body": MagicMock(read=MagicMock(return_value=object_bodies.get(Key, b"{}")))}

    s3.get_object.side_effect = get_object
    return s3


class TestDiscoverDatePrefixes:
    def _org_tree(self, days=("25", "26", "27"), accounts=("111111111111", "222222222222")):
        tree = {"AWSLogs/": [f"AWSLogs/{a}/" for a in accounts]}
        for a in accounts:
            tree[f"AWSLogs/{a}/"] = [f"AWSLogs/{a}/CloudTrail/"]
            tree[f"AWSLogs/{a}/CloudTrail/"] = [f"AWSLogs/{a}/CloudTrail/us-east-1/"]
            tree[f"AWSLogs/{a}/CloudTrail/us-east-1/"] = [f"AWSLogs/{a}/CloudTrail/us-east-1/2026/"]
            tree[f"AWSLogs/{a}/CloudTrail/us-east-1/2026/"] = [f"AWSLogs/{a}/CloudTrail/us-east-1/2026/08/"]
            tree[f"AWSLogs/{a}/CloudTrail/us-east-1/2026/08/"] = [
                f"AWSLogs/{a}/CloudTrail/us-east-1/2026/08/{d}/" for d in days
            ]
        return tree

    def test_prunes_days_outside_range_across_all_accounts(self):
        s3 = _make_hierarchical_s3(self._org_tree(), {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 27), max_workers=4,
        )

        assert leaves == [
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/27/",
            "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/26/",
            "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/27/",
        ]

    def test_month_boundary_crossing(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": ["AWSLogs/111111111111/CloudTrail/"],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/30/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/31/",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/01/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/02/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 1, 31), date(2026, 2, 1), max_workers=4,
        )

        assert leaves == [
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/31/",
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/01/",
        ]

    def test_out_of_range_year_is_pruned_without_descending(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": ["AWSLogs/111111111111/CloudTrail/"],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2025/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
        )

        assert leaves == ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/"]
        # The out-of-range 2025/ branch must never have been listed at all.
        assert "AWSLogs/111111111111/CloudTrail/us-east-1/2025/" not in s3.delimited_prefixes_queried

    def test_month_outside_range_within_boundary_year_is_pruned(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": ["AWSLogs/111111111111/CloudTrail/"],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/06/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
        )

        assert leaves == ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/"]
        assert "AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/" not in s3.delimited_prefixes_queried
        assert "AWSLogs/111111111111/CloudTrail/us-east-1/2026/06/" not in s3.delimited_prefixes_queried

    def test_non_numeric_month_and_day_folders_are_skipped(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": ["AWSLogs/111111111111/CloudTrail/"],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/_manifest/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/_manifest/",
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
        )

        assert leaves == ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/"]

    def test_invalid_calendar_date_is_skipped(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": ["AWSLogs/111111111111/CloudTrail/"],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/"],
            # "30" isn't a real day in February -- must be skipped, not raise.
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/02/30/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 1, 1), date(2026, 12, 31), max_workers=4,
        )

        assert leaves == []

    def test_non_date_sibling_folders_are_still_walked(self):
        tree = {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": [
                "AWSLogs/111111111111/CloudTrail/",
                "AWSLogs/111111111111/Config/",
            ],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            ],
            "AWSLogs/111111111111/Config/": ["AWSLogs/111111111111/Config/us-east-1/"],
            "AWSLogs/111111111111/Config/us-east-1/": ["AWSLogs/111111111111/Config/us-east-1/2026/"],
            "AWSLogs/111111111111/Config/us-east-1/2026/": ["AWSLogs/111111111111/Config/us-east-1/2026/08/"],
            "AWSLogs/111111111111/Config/us-east-1/2026/08/": [
                "AWSLogs/111111111111/Config/us-east-1/2026/08/26/",
            ],
        }
        s3 = _make_hierarchical_s3(tree, {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
        )

        assert leaves == [
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
            "AWSLogs/111111111111/Config/us-east-1/2026/08/26/",
        ]

    def _tree_with_digest(self):
        return {
            "AWSLogs/": ["AWSLogs/111111111111/"],
            "AWSLogs/111111111111/": [
                "AWSLogs/111111111111/CloudTrail/",
                "AWSLogs/111111111111/CloudTrail-Digest/",
            ],
            "AWSLogs/111111111111/CloudTrail/": ["AWSLogs/111111111111/CloudTrail/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/"],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/": ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/"],
            "AWSLogs/111111111111/CloudTrail-Digest/": ["AWSLogs/111111111111/CloudTrail-Digest/us-east-1/"],
            "AWSLogs/111111111111/CloudTrail-Digest/us-east-1/": ["AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/"],
            "AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/": ["AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/08/"],
            "AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/08/": ["AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/08/26/"],
        }

    def test_digest_subtree_pruned_and_never_listed_by_default(self):
        s3 = _make_hierarchical_s3(self._tree_with_digest(), {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
        )

        assert leaves == ["AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/"]
        # The digest folder must have been pruned at the log-type level, so its
        # region/date folders were never even listed.
        assert not any("CloudTrail-Digest" in p for p in s3.delimited_prefixes_queried)

    def test_digest_subtree_walked_when_opted_in(self):
        s3 = _make_hierarchical_s3(self._tree_with_digest(), {})
        forensics = AwsIRForensics(make_services(), DredgeConfig())

        leaves = forensics._discover_date_prefixes(
            s3, "bucket", "AWSLogs/", date(2026, 8, 26), date(2026, 8, 26), max_workers=4,
            exclude_cloudtrail_digest=False,
        )

        assert leaves == [
            "AWSLogs/111111111111/CloudTrail-Digest/us-east-1/2026/08/26/",
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/",
        ]


class TestDownloadS3LogsDateFiltering:
    def _two_account_two_day_setup(self):
        tree = TestDiscoverDatePrefixes()._org_tree()
        objects_by_leaf_prefix = {
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/26/f1.json.gz",
            ],
            "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/27/": [
                "AWSLogs/111111111111/CloudTrail/us-east-1/2026/08/27/f2.json.gz",
            ],
            "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/26/": [
                "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/26/f3.json.gz",
            ],
            "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/27/": [
                "AWSLogs/222222222222/CloudTrail/us-east-1/2026/08/27/f4.json.gz",
            ],
        }
        import gzip
        body = gzip.compress(b"{}")
        object_bodies = {
            key: body for keys in objects_by_leaf_prefix.values() for key in keys
        }
        return tree, objects_by_leaf_prefix, object_bodies

    def test_only_leaf_prefixes_in_range_are_downloaded(self, tmp_path):
        tree, objects_by_leaf_prefix, bodies = self._two_account_two_day_setup()
        services = make_services()
        services.s3 = _make_hierarchical_s3(tree, objects_by_leaf_prefix, bodies)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path),
            start_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
            end_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
        )

        assert result.success is True
        assert result.details["downloaded"] == 4
        assert sorted(result.details["scanned_prefixes"]) == sorted(objects_by_leaf_prefix.keys())
        assert all("2026/08/25" not in p for p in result.details["scanned_prefixes"])

    def test_days_ago_shortcut_computes_start_time(self, tmp_path, monkeypatch):
        tree, objects_by_leaf_prefix, bodies = self._two_account_two_day_setup()
        services = make_services()
        services.s3 = _make_hierarchical_s3(tree, objects_by_leaf_prefix, bodies)

        class _FixedDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 8, 27, 12, 0, tzinfo=tz)

        monkeypatch.setattr("dredge.aws_ir.forensics.datetime", _FixedDatetime)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path), days_ago=1,
        )

        assert result.details["downloaded"] == 4

    def test_start_time_and_days_ago_are_mutually_exclusive(self, tmp_path):
        with pytest.raises(ValueError):
            AwsIRForensics(make_services(), DredgeConfig()).download_s3_logs(
                "my-bucket", destination=str(tmp_path),
                start_time=datetime(2026, 8, 26, tzinfo=timezone.utc), days_ago=1,
            )

    def test_prefix_without_trailing_slash_is_normalized(self, tmp_path):
        tree, objects_by_leaf_prefix, bodies = self._two_account_two_day_setup()
        services = make_services()
        services.s3 = _make_hierarchical_s3(tree, objects_by_leaf_prefix, bodies)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs", destination=str(tmp_path),
            start_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
            end_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
        )

        assert result.details["downloaded"] == 4

    def test_max_objects_stops_across_leaf_prefixes(self, tmp_path):
        tree, objects_by_leaf_prefix, bodies = self._two_account_two_day_setup()
        services = make_services()
        services.s3 = _make_hierarchical_s3(tree, objects_by_leaf_prefix, bodies)

        result = AwsIRForensics(services, DredgeConfig()).download_s3_logs(
            "my-bucket", prefix="AWSLogs/", destination=str(tmp_path),
            start_time=datetime(2026, 8, 26, tzinfo=timezone.utc),
            end_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
            max_objects=2,
        )

        assert result.details["downloaded"] == 2
