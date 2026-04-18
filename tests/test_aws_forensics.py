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

    def test_describe_trails_error_records_fatal(self):
        services = make_services()
        services.cloudtrail.describe_trails.side_effect = make_client_error()
        result = AwsIRForensics(services, DredgeConfig()).get_cloudtrail_status()
        assert result.success is False
