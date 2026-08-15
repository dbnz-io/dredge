import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

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
