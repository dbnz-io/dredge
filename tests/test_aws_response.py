import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from unittest.mock import MagicMock
import pytest
from botocore.exceptions import ClientError, BotoCoreError

from dredge.aws_ir.response import AwsIRResponse
from dredge.config import DredgeConfig


def make_services():
    return MagicMock()


def make_client_error(code="AccessDenied", op="Operation"):
    return ClientError({"Error": {"Code": code, "Message": "simulated"}}, op)


class TestDisableAccessKey:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_access_key("u", "K")
        assert result.success is True
        assert result.details.get("dry_run") is True
        services.iam.update_access_key.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).disable_access_key("u", "K")
        assert result.success is True
        assert "disabled" in result.details["status"]

    def test_api_error_records_failure(self):
        services = make_services()
        services.iam.update_access_key.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_access_key("u", "K")
        assert result.success is False
        assert result.errors


class TestDeleteAccessKey:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).delete_access_key("u", "K")
        assert result.success is True
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).delete_access_key("u", "K")
        assert result.success is True
        assert "deleted" in result.details["status"]

    def test_api_error(self):
        services = make_services()
        services.iam.delete_access_key.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).delete_access_key("u", "K")
        assert result.success is False


def _make_paginator(pages):
    """Return a mock paginator whose .paginate() yields the given pages list."""
    p = MagicMock()
    p.paginate.return_value = pages
    return p


def _make_iam(
    *,
    keys=None,
    groups=None,
    attached_policies=None,
    inline_policies=None,
    login_profile_exc=False,
    role_attached_policies=None,
    role_inline_policies=None,
):
    iam = MagicMock()
    exc_cls = type("NoSuchEntityException", (Exception,), {})
    iam.exceptions.NoSuchEntityException = exc_cls

    _paginators = {
        "list_access_keys": _make_paginator(
            [{"AccessKeyMetadata": [{"AccessKeyId": k} for k in (keys or [])]}]
        ),
        "list_groups_for_user": _make_paginator(
            [{"Groups": [{"GroupName": g} for g in (groups or [])]}]
        ),
        "list_attached_user_policies": _make_paginator(
            [{"AttachedPolicies": [{"PolicyArn": a} for a in (attached_policies or [])]}]
        ),
        "list_user_policies": _make_paginator(
            [{"PolicyNames": inline_policies or []}]
        ),
        "list_attached_role_policies": _make_paginator(
            [{"AttachedPolicies": [{"PolicyArn": a} for a in (role_attached_policies or [])]}]
        ),
        "list_role_policies": _make_paginator(
            [{"PolicyNames": role_inline_policies or []}]
        ),
    }
    iam.get_paginator.side_effect = lambda op: _paginators.get(op, _make_paginator([{}]))

    if login_profile_exc:
        iam.delete_login_profile.side_effect = exc_cls()
    return iam


class TestDisableUser:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_user("alice")
        assert result.details.get("dry_run") is True
        services.iam.list_access_keys.assert_not_called()

    def test_disables_keys_removes_groups_detaches_policies(self):
        iam = _make_iam(
            keys=["K1", "K2"],
            groups=["grp1"],
            attached_policies=["arn:aws:iam::policy/P1"],
            inline_policies=["inline1"],
        )
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")

        assert result.success is True
        assert result.details["access_keys_disabled"] == ["K1", "K2"]
        assert result.details["groups_removed"] == ["grp1"]
        assert result.details["managed_policies_detached"] == ["arn:aws:iam::policy/P1"]
        assert result.details["inline_policies_deleted"] == ["inline1"]

    def test_no_login_profile_marks_false(self):
        iam = _make_iam(login_profile_exc=True)
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.details["login_profile_deleted"] is False

    def test_key_disable_error_records_partial_failure(self):
        iam = _make_iam(keys=["K1"])
        iam.update_access_key.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")

        assert result.success is False
        assert any("K1" in e for e in result.errors)

    def test_group_remove_error_recorded(self):
        iam = _make_iam(groups=["grp1"])
        iam.remove_user_from_group.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.success is False
        assert any("grp1" in e for e in result.errors)

    def test_policy_detach_error_recorded(self):
        iam = _make_iam(attached_policies=["arn:p/A"])
        iam.detach_user_policy.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.success is False

    def test_inline_policy_delete_error_recorded(self):
        iam = _make_iam(inline_policies=["inline1"])
        iam.delete_user_policy.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.success is False

    def test_fatal_api_error(self):
        services = make_services()
        # Simulate the first paginator call failing
        services.iam.get_paginator.return_value.paginate.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.success is False
        assert any("Fatal error" in e for e in result.errors)

    def test_login_profile_generic_error_recorded(self):
        iam = _make_iam()
        iam.delete_login_profile.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_user("alice")
        assert result.success is False
        assert any("login profile" in e for e in result.errors)


class TestDeleteUser:
    def test_calls_disable_then_deletes(self):
        iam = _make_iam()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_user("alice")

        assert result.success is True
        assert result.details["user_deleted"] is True
        iam.delete_user.assert_called_once_with(UserName="alice")

    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).delete_user("alice")
        assert result.details.get("dry_run") is True
        services.iam.delete_user.assert_not_called()

    def test_delete_failure_records_error(self):
        iam = _make_iam()
        iam.delete_user.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_user("alice")
        assert result.success is False
        assert result.errors

    def test_skips_deletion_when_disable_fails(self):
        # If disable_user has failures (e.g. a key couldn't be deactivated),
        # delete_user must abort rather than delete a partially-cleaned user.
        iam = _make_iam(keys=["K1"])
        iam.update_access_key.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_user("alice")
        assert result.success is False
        iam.delete_user.assert_not_called()


class TestDisableRole:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_role("my-role")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        iam = _make_iam(
            role_attached_policies=["arn:aws:iam::p/A"],
            role_inline_policies=["inline1"],
        )
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_role("my-role")

        assert result.success is True
        assert result.details["trust_relationship_cleared"] is True
        assert result.details["managed_policies_detached"] == ["arn:aws:iam::p/A"]
        assert result.details["inline_policies_deleted"] == ["inline1"]

    def test_policy_detach_error_recorded(self):
        iam = _make_iam(role_attached_policies=["arn:p"])
        iam.detach_role_policy.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_role("my-role")
        assert result.success is False

    def test_inline_policy_delete_error_recorded(self):
        iam = _make_iam(role_inline_policies=["p1"])
        iam.delete_role_policy.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).disable_role("my-role")
        assert result.success is False

    def test_fatal_error(self):
        services = make_services()
        services.iam.get_paginator.return_value.paginate.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_role("my-role")
        assert result.success is False
        assert any("Fatal error" in e for e in result.errors)


class TestBlockS3PublicAccess:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).block_s3_public_access("123456")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_public_access("123456")
        assert result.success is True
        assert "blocked" in result.details["status"]

    def test_api_error(self):
        services = make_services()
        services.s3control.put_public_access_block.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_public_access("123456")
        assert result.success is False


class TestBlockS3BucketPublicAccess:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).block_s3_bucket_public_access("my-bucket")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_bucket_public_access("my-bucket")
        assert result.success is True
        assert result.details["public_access_blocked"] is True
        assert result.details["acl_set_private"] is True
        # Bucket policy is intentionally preserved — Block Public Access already overrides
        # permissive policies, and a restrictive policy could be made more permissive by deletion.
        assert "bucket_policy_deleted" not in result.details
        services.s3.delete_bucket_policy.assert_not_called()

    def test_put_access_block_error(self):
        services = make_services()
        services.s3.put_public_access_block.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_bucket_public_access("my-bucket")
        assert result.success is False

    def test_put_acl_error(self):
        services = make_services()
        services.s3.put_bucket_acl.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_bucket_public_access("my-bucket")
        assert result.success is False


class TestBlockS3ObjectPublicAccess:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).block_s3_object_public_access("bucket", "k")
        assert result.details.get("dry_run") is True

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_object_public_access("bucket", "k")
        assert result.success is True
        assert result.details["acl_set_private"] is True

    def test_api_error(self):
        services = make_services()
        services.s3.put_object_acl.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).block_s3_object_public_access("bucket", "k")
        assert result.success is False


class TestIsolateEc2Instances:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).isolate_ec2_instances(["i-123"])
        assert result.details.get("dry_run") is True

    def test_happy_path_with_existing_sg(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-existing"}]}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001"], vpc_id="vpc-x")

        assert result.success is True
        assert result.details["isolation_security_group_id"] == "sg-existing"

    def test_creates_new_sg_when_not_found(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        ec2.create_security_group.return_value = {"GroupId": "sg-new"}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001"], vpc_id="vpc-x")
        assert result.details["isolation_security_group_id"] == "sg-new"

    def test_infers_vpc_from_instance(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"VpcId": "vpc-inferred"}]}]
        }
        ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-x"}]}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001"])
        assert result.success is True

    def test_missing_instance_raises_fatal(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = {"Reservations": []}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-bad"])
        assert result.success is False
        assert any("Fatal error" in e for e in result.errors)

    def test_per_instance_modify_error(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-x"}]}
        ec2.modify_instance_attribute.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001"], vpc_id="vpc-x")
        assert result.success is False
        assert any("i-001" in e for e in result.errors)

    def test_multi_vpc_isolation(self):
        ec2 = MagicMock()
        ec2.describe_instances.side_effect = [
            {"Reservations": [{"Instances": [{"VpcId": "vpc-1"}]}]},
            {"Reservations": [{"Instances": [{"VpcId": "vpc-2"}]}]},
        ]
        ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-x"}]}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001", "i-002"])
        assert result.success is True
        # Two different VPCs → result stores a map, not a single string
        sg_detail = result.details["isolation_security_group_id"]
        assert isinstance(sg_detail, dict)
        assert set(sg_detail.keys()) == {"vpc-1", "vpc-2"}

    def test_revoke_egress_failure_ignored(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        ec2.create_security_group.return_value = {"GroupId": "sg-new"}
        ec2.revoke_security_group_egress.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        # Should not propagate the revoke error
        result = AwsIRResponse(services, DredgeConfig()).isolate_ec2_instances(["i-001"], vpc_id="vpc-x")
        assert result.details["isolation_security_group_id"] == "sg-new"


class TestDeleteMfaDevices:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).delete_mfa_devices("alice")
        assert result.details.get("dry_run") is True
        services.iam.get_paginator.assert_not_called()

    def test_happy_path_virtual_device(self):
        iam = _make_iam()
        iam.get_paginator.side_effect = lambda op: _make_paginator(
            [{"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]}]
        ) if op == "list_mfa_devices" else _make_paginator([{}])
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_mfa_devices("alice")
        assert result.success is True
        assert "arn:aws:iam::123:mfa/alice" in result.details["devices_deleted"]
        iam.deactivate_mfa_device.assert_called_once()
        iam.delete_virtual_mfa_device.assert_called_once()

    def test_happy_path_hardware_device(self):
        iam = _make_iam()
        iam.get_paginator.side_effect = lambda op: _make_paginator(
            [{"MFADevices": [{"SerialNumber": "GAHT12345678"}]}]
        ) if op == "list_mfa_devices" else _make_paginator([{}])
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_mfa_devices("alice")
        assert result.success is True
        iam.deactivate_mfa_device.assert_called_once()
        iam.delete_virtual_mfa_device.assert_not_called()

    def test_deactivate_error_skips_delete(self):
        iam = _make_iam()
        iam.get_paginator.side_effect = lambda op: _make_paginator(
            [{"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]}]
        ) if op == "list_mfa_devices" else _make_paginator([{}])
        iam.deactivate_mfa_device.side_effect = make_client_error()
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_mfa_devices("alice")
        assert result.success is False
        iam.delete_virtual_mfa_device.assert_not_called()

    def test_no_devices_returns_empty(self):
        iam = _make_iam()
        iam.get_paginator.side_effect = lambda op: _make_paginator(
            [{"MFADevices": []}]
        ) if op == "list_mfa_devices" else _make_paginator([{}])
        services = make_services()
        services.iam = iam

        result = AwsIRResponse(services, DredgeConfig()).delete_mfa_devices("alice")
        assert result.success is True
        assert result.details["devices_deleted"] == []


class TestRevokeActiveSessions:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).revoke_active_sessions("alice")
        assert result.details.get("dry_run") is True
        services.iam.put_user_policy.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).revoke_active_sessions("alice")
        assert result.success is True
        assert result.details["policy_name"] == "DredgeRevokeActiveSessions"
        assert "revocation_time" in result.details
        call_kwargs = services.iam.put_user_policy.call_args[1]
        assert call_kwargs["UserName"] == "alice"
        import json as _json
        doc = _json.loads(call_kwargs["PolicyDocument"])
        assert doc["Statement"][0]["Effect"] == "Deny"
        assert "aws:TokenIssueTime" in doc["Statement"][0]["Condition"]["DateLessThan"]

    def test_api_error_records_failure(self):
        services = make_services()
        services.iam.put_user_policy.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).revoke_active_sessions("alice")
        assert result.success is False


class TestStopEc2Instances:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).stop_ec2_instances(["i-001"])
        assert result.details.get("dry_run") is True
        services.ec2.stop_instances.assert_not_called()

    def test_happy_path(self):
        ec2 = MagicMock()
        ec2.stop_instances.return_value = {
            "StoppingInstances": [{"InstanceId": "i-001", "CurrentState": {"Name": "stopping"}}]
        }
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).stop_ec2_instances(["i-001"])
        assert result.success is True
        assert result.details["stopping"]["i-001"] == "stopping"

    def test_api_error_records_failure(self):
        services = make_services()
        services.ec2.stop_instances.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).stop_ec2_instances(["i-001"])
        assert result.success is False


def _make_instance_desc(instance_id, volumes=None):
    volumes = volumes or []
    return {
        "Reservations": [{
            "Instances": [{
                "InstanceId": instance_id,
                "BlockDeviceMappings": [
                    {"DeviceName": f"/dev/sd{chr(ord('a') + i)}", "Ebs": {"VolumeId": v}}
                    for i, v in enumerate(volumes)
                ],
            }]
        }]
    }


class TestTerminateEc2Instances:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).terminate_ec2_instances(["i-001"])
        assert result.details.get("dry_run") is True
        services.ec2.terminate_instances.assert_not_called()

    def test_happy_path_with_snapshot(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _make_instance_desc("i-001", volumes=["vol-abc"])
        ec2.create_snapshot.return_value = {"SnapshotId": "snap-x"}
        ec2.terminate_instances.return_value = {
            "TerminatingInstances": [{"InstanceId": "i-001", "CurrentState": {"Name": "shutting-down"}}]
        }
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).terminate_ec2_instances(["i-001"])
        assert result.success is True
        assert result.details["snapshots_created"]["i-001"]["vol-abc"] == "snap-x"
        assert result.details["terminating"]["i-001"] == "shutting-down"

    def test_snapshot_first_false_skips_snapshot(self):
        ec2 = MagicMock()
        ec2.terminate_instances.return_value = {"TerminatingInstances": []}
        services = make_services()
        services.ec2 = ec2

        AwsIRResponse(services, DredgeConfig()).terminate_ec2_instances(["i-001"], snapshot_first=False)
        ec2.create_snapshot.assert_not_called()
        ec2.terminate_instances.assert_called_once()

    def test_snapshot_failure_continues_to_terminate(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _make_instance_desc("i-001", volumes=["vol-abc"])
        ec2.create_snapshot.side_effect = make_client_error()
        ec2.terminate_instances.return_value = {"TerminatingInstances": []}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).terminate_ec2_instances(["i-001"])
        assert result.success is False  # snapshot error recorded
        ec2.terminate_instances.assert_called_once()  # termination still happens

    def test_no_volumes_terminates_directly(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = _make_instance_desc("i-001", volumes=[])
        ec2.terminate_instances.return_value = {"TerminatingInstances": []}
        services = make_services()
        services.ec2 = ec2

        AwsIRResponse(services, DredgeConfig()).terminate_ec2_instances(["i-001"])
        ec2.create_snapshot.assert_not_called()
        ec2.terminate_instances.assert_called_once()


def _make_nacl(nacl_id, entries=None):
    return {"NetworkAclId": nacl_id, "Entries": entries or []}


class TestBlockNaclCidrs:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).block_nacl_cidrs("vpc-x", ["10.0.0.1/32"])
        assert result.details.get("dry_run") is True
        services.ec2.describe_network_acls.assert_not_called()

    def test_happy_path_single_nacl_single_cidr(self):
        ec2 = MagicMock()
        ec2.describe_network_acls.return_value = {"NetworkAcls": [_make_nacl("acl-1")]}
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).block_nacl_cidrs("vpc-x", ["10.0.0.1/32"])
        assert result.success is True
        assert ec2.create_network_acl_entry.call_count == 2  # ingress + egress
        assert result.details["rules_added"] == 2

    def test_multiple_cidrs_get_sequential_rule_numbers(self):
        ec2 = MagicMock()
        ec2.describe_network_acls.return_value = {"NetworkAcls": [_make_nacl("acl-1")]}
        services = make_services()
        services.ec2 = ec2

        AwsIRResponse(services, DredgeConfig()).block_nacl_cidrs("vpc-x", ["10.0.0.1/32", "10.0.0.2/32"])
        assert ec2.create_network_acl_entry.call_count == 4  # 2 CIDRs × 2 directions

    def test_rule_number_avoids_conflict_with_existing(self):
        ec2 = MagicMock()
        existing = [{"RuleNumber": 1, "Egress": False}, {"RuleNumber": 1, "Egress": True}]
        ec2.describe_network_acls.return_value = {"NetworkAcls": [_make_nacl("acl-1", entries=existing)]}
        services = make_services()
        services.ec2 = ec2

        AwsIRResponse(services, DredgeConfig()).block_nacl_cidrs("vpc-x", ["10.0.0.1/32"], rule_number_start=1)
        calls = ec2.create_network_acl_entry.call_args_list
        used_numbers = [c[1]["RuleNumber"] for c in calls]
        assert 1 not in used_numbers  # rule 1 was taken; must use something else

    def test_api_error_per_entry_recorded(self):
        ec2 = MagicMock()
        ec2.describe_network_acls.return_value = {"NetworkAcls": [_make_nacl("acl-1")]}
        ec2.create_network_acl_entry.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        result = AwsIRResponse(services, DredgeConfig()).block_nacl_cidrs("vpc-x", ["10.0.0.1/32"])
        assert result.success is False
        assert result.errors


class TestDisableLambdaFunction:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_lambda_function("my-fn")
        assert result.details.get("dry_run") is True
        services.lambda_.put_function_concurrency.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).disable_lambda_function("my-fn")
        assert result.success is True
        assert result.details["reserved_concurrency"] == 0
        services.lambda_.put_function_concurrency.assert_called_once_with(
            FunctionName="my-fn", ReservedConcurrentExecutions=0
        )

    def test_api_error_records_failure(self):
        services = make_services()
        services.lambda_.put_function_concurrency.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_lambda_function("my-fn")
        assert result.success is False


class TestDisableKmsKey:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_kms_key("key-123")
        assert result.details.get("dry_run") is True
        services.kms.disable_key.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).disable_kms_key("key-123")
        assert result.success is True
        assert "disabled" in result.details["status"].lower()
        services.kms.disable_key.assert_called_once_with(KeyId="key-123")

    def test_api_error_records_failure(self):
        services = make_services()
        services.kms.disable_key.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_kms_key("key-123")
        assert result.success is False


class TestScheduleKmsDeletion:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).schedule_kms_key_deletion("key-123")
        assert result.details.get("dry_run") is True
        services.kms.schedule_key_deletion.assert_not_called()

    def test_happy_path(self):
        from datetime import datetime, timezone as tz
        services = make_services()
        deletion_date = datetime(2026, 4, 19, tzinfo=tz.utc)
        services.kms.schedule_key_deletion.return_value = {"DeletionDate": deletion_date}

        result = AwsIRResponse(services, DredgeConfig()).schedule_kms_key_deletion("key-123", pending_window_days=7)
        assert result.success is True
        assert "2026-04-19" in result.details["deletion_date"]
        assert result.details["pending_window_days"] == 7

    def test_invalid_window_raises_value_error(self):
        services = make_services()
        with pytest.raises(ValueError, match="pending_window_days"):
            AwsIRResponse(services, DredgeConfig()).schedule_kms_key_deletion("key-123", pending_window_days=5)
        services.kms.schedule_key_deletion.assert_not_called()

    def test_api_error_records_failure(self):
        services = make_services()
        services.kms.schedule_key_deletion.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).schedule_kms_key_deletion("key-123")
        assert result.success is False


class TestTagResources:
    def test_dry_run_skips_api(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).tag_resources(
            ["arn:aws:ec2:us-east-1:123:instance/i-001"], {"env": "ir"}
        )
        assert result.details.get("dry_run") is True
        services.tagging.tag_resources.assert_not_called()

    def test_happy_path_single_batch(self):
        services = make_services()
        services.tagging.tag_resources.return_value = {"FailedResourcesMap": {}}
        arns = [f"arn:aws:ec2:us-east-1:123:instance/i-{i:03d}" for i in range(5)]

        result = AwsIRResponse(services, DredgeConfig()).tag_resources(arns, {"env": "ir"})
        assert result.success is True
        assert result.details["tagged"] == 5
        services.tagging.tag_resources.assert_called_once()

    def test_batches_of_20(self):
        services = make_services()
        services.tagging.tag_resources.return_value = {"FailedResourcesMap": {}}
        arns = [f"arn:aws:ec2:us-east-1:123:instance/i-{i:03d}" for i in range(45)]

        AwsIRResponse(services, DredgeConfig()).tag_resources(arns, {"env": "ir"})
        assert services.tagging.tag_resources.call_count == 3  # 20 + 20 + 5

    def test_partial_failure_records_errors(self):
        services = make_services()
        services.tagging.tag_resources.return_value = {
            "FailedResourcesMap": {
                "arn:bad:1": {"ErrorMessage": "not found"},
                "arn:bad:2": {"ErrorMessage": "access denied"},
            }
        }
        result = AwsIRResponse(services, DredgeConfig()).tag_resources(
            ["arn:good", "arn:bad:1", "arn:bad:2"], {"env": "ir"}
        )
        assert result.success is False
        assert result.details["tagged"] == 1
        assert len(result.details["failed"]) == 2

    def test_empty_arns_returns_immediately(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).tag_resources([], {"env": "ir"})
        assert result.details["tagged"] == 0
        services.tagging.tag_resources.assert_not_called()

    def test_api_error_per_batch_recorded(self):
        services = make_services()
        services.tagging.tag_resources.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).tag_resources(["arn:x"], {"env": "ir"})
        assert result.success is False


# =====================================================================
# New methods added in second implementation pass
# =====================================================================


class TestIsolateRdsInstance:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).isolate_rds_instance("db-1")
        assert result.details.get("dry_run") is True
        services.rds.describe_db_instances.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        services.rds.describe_db_instances.return_value = {
            "DBInstances": [{
                "DBSubnetGroup": {"VpcId": "vpc-123"},
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-old"}],
            }]
        }
        services.ec2.describe_security_groups.return_value = {"SecurityGroups": [{"GroupId": "sg-iso"}]}
        result = AwsIRResponse(services, DredgeConfig()).isolate_rds_instance("db-1")
        assert result.success is True
        assert result.details["isolation_security_group_id"] == "sg-iso"
        assert result.details["original_security_groups"] == ["sg-old"]
        services.rds.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier="db-1",
            VpcSecurityGroupIds=["sg-iso"],
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )

    def test_instance_not_found(self):
        services = make_services()
        services.rds.describe_db_instances.return_value = {"DBInstances": []}
        result = AwsIRResponse(services, DredgeConfig()).isolate_rds_instance("db-bad")
        assert result.success is False
        assert result.errors

    def test_api_error_records_failure(self):
        services = make_services()
        services.rds.describe_db_instances.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).isolate_rds_instance("db-1")
        assert result.success is False


class TestStopEcsService:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).stop_ecs_service("cluster-1", "svc-1")
        assert result.details.get("dry_run") is True
        services.ecs.update_service.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        services.ecs.update_service.return_value = {"service": {"desiredCount": 0, "runningCount": 2}}
        result = AwsIRResponse(services, DredgeConfig()).stop_ecs_service("cluster-1", "svc-1")
        assert result.success is True
        assert result.details["desired_count"] == 0
        services.ecs.update_service.assert_called_once_with(cluster="cluster-1", service="svc-1", desiredCount=0)

    def test_api_error(self):
        services = make_services()
        services.ecs.update_service.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).stop_ecs_service("c", "s")
        assert result.success is False


class TestStopEcsTask:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).stop_ecs_task("cluster-1", "task-1")
        assert result.details.get("dry_run") is True
        services.ecs.stop_task.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).stop_ecs_task("cluster-1", "task-1")
        assert result.success is True
        assert result.details["status"] == "Task stopped"
        services.ecs.stop_task.assert_called_once_with(
            cluster="cluster-1", task="task-1", reason="Dredge IR containment"
        )

    def test_custom_reason(self):
        services = make_services()
        AwsIRResponse(services, DredgeConfig()).stop_ecs_task("c", "t", reason="Compromised")
        services.ecs.stop_task.assert_called_once_with(cluster="c", task="t", reason="Compromised")

    def test_api_error(self):
        services = make_services()
        services.ecs.stop_task.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).stop_ecs_task("c", "t")
        assert result.success is False


class TestDisableSecretsManagerSecret:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_secrets_manager_secret("sec-1")
        assert result.details.get("dry_run") is True
        services.secretsmanager.delete_secret.assert_not_called()

    def test_happy_path(self):
        from datetime import datetime, timezone
        services = make_services()
        deletion_date = datetime(2026, 4, 19, tzinfo=timezone.utc)
        services.secretsmanager.delete_secret.return_value = {"DeletionDate": deletion_date}
        result = AwsIRResponse(services, DredgeConfig()).disable_secrets_manager_secret("sec-1")
        assert result.success is True
        assert result.details["recovery_window_days"] == 7
        assert "2026-04-19" in result.details["deletion_date"]

    def test_invalid_recovery_window_raises(self):
        services = make_services()
        with pytest.raises(ValueError):
            AwsIRResponse(services, DredgeConfig()).disable_secrets_manager_secret("sec-1", recovery_window_days=3)

    def test_api_error(self):
        services = make_services()
        services.secretsmanager.delete_secret.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_secrets_manager_secret("sec-1")
        assert result.success is False


class TestDisableEventbridgeRule:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).disable_eventbridge_rule("my-rule")
        assert result.details.get("dry_run") is True
        services.events.disable_rule.assert_not_called()

    def test_happy_path(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).disable_eventbridge_rule("my-rule")
        assert result.success is True
        assert result.details["status"] == "Rule disabled"
        services.events.disable_rule.assert_called_once_with(Name="my-rule", EventBusName="default")

    def test_custom_event_bus(self):
        services = make_services()
        AwsIRResponse(services, DredgeConfig()).disable_eventbridge_rule("r", event_bus_name="custom-bus")
        services.events.disable_rule.assert_called_once_with(Name="r", EventBusName="custom-bus")

    def test_api_error(self):
        services = make_services()
        services.events.disable_rule.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).disable_eventbridge_rule("r")
        assert result.success is False


class TestTerminateSsmSessions:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).terminate_ssm_sessions("i-123")
        assert result.details.get("dry_run") is True
        services.ssm.describe_sessions.assert_not_called()

    def test_terminates_all_active_sessions(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {
            "Sessions": [{"SessionId": "s-001"}, {"SessionId": "s-002"}]
        }
        result = AwsIRResponse(services, DredgeConfig()).terminate_ssm_sessions("i-123")
        assert result.success is True
        assert result.details["terminated"] == ["s-001", "s-002"]
        assert result.details["total_terminated"] == 2

    def test_no_active_sessions(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {"Sessions": []}
        result = AwsIRResponse(services, DredgeConfig()).terminate_ssm_sessions("i-123")
        assert result.success is True
        assert result.details["total_terminated"] == 0

    def test_terminate_failure_recorded_per_session(self):
        services = make_services()
        services.ssm.describe_sessions.return_value = {"Sessions": [{"SessionId": "s-bad"}]}
        services.ssm.terminate_session.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).terminate_ssm_sessions("i-123")
        assert result.success is False
        assert any("s-bad" in e for e in result.errors)

    def test_describe_error_records_fatal(self):
        services = make_services()
        services.ssm.describe_sessions.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).terminate_ssm_sessions("i-123")
        assert result.success is False


class TestDeauthorizeSecurityGroupRules:
    def test_no_rules_raises(self):
        services = make_services()
        with pytest.raises(ValueError):
            AwsIRResponse(services, DredgeConfig()).deauthorize_security_group_rules("sg-1")

    def test_dry_run(self):
        services = make_services()
        rules = [{"IpProtocol": "-1"}]
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).deauthorize_security_group_rules(
            "sg-1", ingress_rules=rules
        )
        assert result.details.get("dry_run") is True
        services.ec2.revoke_security_group_ingress.assert_not_called()

    def test_revokes_ingress_only(self):
        services = make_services()
        rules = [{"IpProtocol": "-1"}]
        result = AwsIRResponse(services, DredgeConfig()).deauthorize_security_group_rules(
            "sg-1", ingress_rules=rules
        )
        assert result.success is True
        assert result.details["ingress_rules_revoked"] == 1
        services.ec2.revoke_security_group_ingress.assert_called_once_with(GroupId="sg-1", IpPermissions=rules)
        services.ec2.revoke_security_group_egress.assert_not_called()

    def test_revokes_egress_only(self):
        services = make_services()
        rules = [{"IpProtocol": "tcp"}]
        result = AwsIRResponse(services, DredgeConfig()).deauthorize_security_group_rules(
            "sg-1", egress_rules=rules
        )
        assert result.success is True
        assert result.details["egress_rules_revoked"] == 1
        services.ec2.revoke_security_group_egress.assert_called_once()
        services.ec2.revoke_security_group_ingress.assert_not_called()

    def test_ingress_api_error(self):
        services = make_services()
        services.ec2.revoke_security_group_ingress.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).deauthorize_security_group_rules(
            "sg-1", ingress_rules=[{"IpProtocol": "-1"}]
        )
        assert result.success is False


class TestDetachIamPolicy:
    def test_no_principal_raises(self):
        services = make_services()
        with pytest.raises(ValueError):
            AwsIRResponse(services, DredgeConfig()).detach_iam_policy("arn:aws:iam::123:policy/P")

    def test_both_principals_raises(self):
        services = make_services()
        with pytest.raises(ValueError):
            AwsIRResponse(services, DredgeConfig()).detach_iam_policy(
                "arn:aws:iam::123:policy/P", user_name="u", role_name="r"
            )

    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).detach_iam_policy(
            "arn:p", user_name="alice"
        )
        assert result.details.get("dry_run") is True
        services.iam.detach_user_policy.assert_not_called()

    def test_detach_from_user(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).detach_iam_policy(
            "arn:aws:iam::123:policy/Admin", user_name="alice"
        )
        assert result.success is True
        assert result.details["policy_detached"] == "arn:aws:iam::123:policy/Admin"
        services.iam.detach_user_policy.assert_called_once_with(
            UserName="alice", PolicyArn="arn:aws:iam::123:policy/Admin"
        )

    def test_detach_from_role(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).detach_iam_policy(
            "arn:aws:iam::123:policy/Admin", role_name="my-role"
        )
        assert result.success is True
        services.iam.detach_role_policy.assert_called_once_with(
            RoleName="my-role", PolicyArn="arn:aws:iam::123:policy/Admin"
        )

    def test_api_error(self):
        services = make_services()
        services.iam.detach_user_policy.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).detach_iam_policy("arn:p", user_name="u")
        assert result.success is False


class TestQuarantineS3Bucket:
    def test_dry_run(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig(dry_run=True)).quarantine_s3_bucket("my-bucket")
        assert result.details.get("dry_run") is True
        services.s3.put_public_access_block.assert_not_called()

    def test_happy_path_with_account_id(self):
        services = make_services()
        result = AwsIRResponse(services, DredgeConfig()).quarantine_s3_bucket(
            "my-bucket", account_id="123456789012"
        )
        assert result.success is True
        assert result.details["public_access_blocked"] is True
        assert result.details["quarantine_policy_applied"] is True
        assert result.details["account_id"] == "123456789012"
        services.s3.put_public_access_block.assert_called_once()
        services.s3.put_bucket_policy.assert_called_once()

    def test_auto_detects_account_id_via_sts(self):
        services = make_services()
        services.sts.get_caller_identity.return_value = {"Account": "111122223333"}
        result = AwsIRResponse(services, DredgeConfig()).quarantine_s3_bucket("my-bucket")
        assert result.success is True
        assert result.details["account_id"] == "111122223333"
        services.sts.get_caller_identity.assert_called_once()

    def test_sts_failure_aborts(self):
        services = make_services()
        services.sts.get_caller_identity.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).quarantine_s3_bucket("my-bucket")
        assert result.success is False
        services.s3.put_public_access_block.assert_not_called()

    def test_s3_api_error(self):
        services = make_services()
        services.s3.put_public_access_block.side_effect = make_client_error()
        result = AwsIRResponse(services, DredgeConfig()).quarantine_s3_bucket(
            "my-bucket", account_id="123456789012"
        )
        assert result.success is False

    def test_policy_contains_bucket_name(self):
        import json as _json
        services = make_services()
        AwsIRResponse(services, DredgeConfig()).quarantine_s3_bucket(
            "sensitive-bucket", account_id="123456789012"
        )
        call_kwargs = services.s3.put_bucket_policy.call_args[1]
        policy_doc = _json.loads(call_kwargs["Policy"])
        resources = policy_doc["Statement"][0]["Resource"]
        assert any("sensitive-bucket" in r for r in resources)
