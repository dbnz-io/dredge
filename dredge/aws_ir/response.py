from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

import botocore.exceptions

from .. import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)


class AwsIRResponse:
    """
    High-level incident *response* actions.

    These are orchestration methods that can call multiple AWS APIs
    and multiple low-level helpers under the hood.
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    # --------------------
    # IAM: Access Keys
    # --------------------

    def disable_access_key(self, user_name: str, access_key_id: str) -> OperationResult:
        """
        Set the given access key to Inactive.
        """
        result = OperationResult(
            operation="disable_access_key",
            target=f"user={user_name},access_key_id={access_key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_access_key.dry_run", target=result.target))
            return result

        iam = self._services.iam
        try:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Inactive",
            )
            result.details["status"] = "Access key disabled"
            _log.info(event("aws_ir_response", "disable_access_key.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_access_key.error", target=result.target, error=str(exc)))

        return result

    def delete_access_key(self, user_name: str, access_key_id: str) -> OperationResult:
        """
        Permanently delete the given access key.
        """
        result = OperationResult(
            operation="delete_access_key",
            target=f"user={user_name},access_key_id={access_key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "delete_access_key.dry_run", target=result.target))
            return result

        iam = self._services.iam
        try:
            iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            result.details["status"] = "Access key deleted"
            _log.info(event("aws_ir_response", "delete_access_key.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "delete_access_key.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Users
    # --------------------

    def disable_user(self, user_name: str) -> OperationResult:
        """
        Disable a user by:
          - Deactivating all access keys
          - Removing from all groups
          - Deleting login profile
          - Detaching managed policies
          - Deleting inline policies
        """
        result = OperationResult(
            operation="disable_user",
            target=f"user={user_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_user.dry_run", target=result.target))
            return result

        _log.debug(event("aws_ir_response", "disable_user.start", target=result.target))
        iam = self._services.iam

        try:
            # 1) Disable all access keys (paginated — users can have many)
            key_ids = [
                k["AccessKeyId"]
                for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name)
                for k in page.get("AccessKeyMetadata", [])
            ]
            for key_id in key_ids:
                try:
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=key_id,
                        Status="Inactive",
                    )
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to disable key {key_id}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_user.key_error", user=user_name, key=key_id, error=str(exc)))

            result.details["access_keys_disabled"] = key_ids

            # 2) Remove from groups (paginated)
            group_names = [
                g["GroupName"]
                for page in iam.get_paginator("list_groups_for_user").paginate(UserName=user_name)
                for g in page.get("Groups", [])
            ]
            for group_name in group_names:
                try:
                    iam.remove_user_from_group(
                        GroupName=group_name,
                        UserName=user_name,
                    )
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to remove from group {group_name}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_user.group_error", user=user_name, group=group_name, error=str(exc)))

            result.details["groups_removed"] = group_names

            # 3) Delete login profile (if exists)
            try:
                iam.delete_login_profile(UserName=user_name)
                result.details["login_profile_deleted"] = True
            except iam.exceptions.NoSuchEntityException:
                result.details["login_profile_deleted"] = False
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to delete login profile: {exc}")
                _log.warning(event("aws_ir_response", "disable_user.login_profile_error", user=user_name, error=str(exc)))

            # 4) Detach managed policies (paginated)
            attached_arns = [
                p["PolicyArn"]
                for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=user_name)
                for p in page.get("AttachedPolicies", [])
            ]
            for arn in attached_arns:
                try:
                    iam.detach_user_policy(UserName=user_name, PolicyArn=arn)
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to detach policy {arn}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_user.policy_error", user=user_name, policy=arn, error=str(exc)))

            result.details["managed_policies_detached"] = attached_arns

            # 5) Delete inline policies (paginated)
            inline_names = [
                name
                for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name)
                for name in page.get("PolicyNames", [])
            ]
            for policy_name in inline_names:
                try:
                    iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to delete inline policy {policy_name}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_user.inline_policy_error", user=user_name, policy=policy_name, error=str(exc)))

            result.details["inline_policies_deleted"] = inline_names

            _log.info(event("aws_ir_response", "disable_user.success", target=result.target))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            result.add_error(f"Fatal error disabling user: {exc}")
            _log.error(event("aws_ir_response", "disable_user.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Roles
    # --------------------

    def disable_role(self, role_name: str) -> OperationResult:
        """
        Disable a role by:
          - Detaching all managed policies
          - Deleting all inline policies
          - Clearing trust relationship (set to empty)
        """
        result = OperationResult(
            operation="disable_role",
            target=f"role={role_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_role.dry_run", target=result.target))
            return result

        _log.debug(event("aws_ir_response", "disable_role.start", target=result.target))
        iam = self._services.iam

        try:
            # Detach managed policies (paginated)
            attached_arns = [
                p["PolicyArn"]
                for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
                for p in page.get("AttachedPolicies", [])
            ]
            for arn in attached_arns:
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to detach policy {arn}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_role.policy_error", role=role_name, policy=arn, error=str(exc)))
            result.details["managed_policies_detached"] = attached_arns

            # Delete inline policies (paginated)
            inline_names = [
                name
                for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name)
                for name in page.get("PolicyNames", [])
            ]
            for policy_name in inline_names:
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to delete inline policy {policy_name}: {exc}")
                    _log.warning(event("aws_ir_response", "disable_role.inline_policy_error", role=role_name, policy=policy_name, error=str(exc)))
            result.details["inline_policies_deleted"] = inline_names

            # Clear trust relationship
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument='{"Version":"2012-10-17","Statement":[]}',
            )
            result.details["trust_relationship_cleared"] = True
            _log.info(event("aws_ir_response", "disable_role.success", target=result.target))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            result.add_error(f"Fatal error disabling role {role_name}: {exc}")
            _log.error(event("aws_ir_response", "disable_role.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # S3: Block public access
    # --------------------

    def block_s3_public_access(
        self,
        account_id: str,
        *,
        block_public_acls: bool = True,
        ignore_public_acls: bool = True,
        block_public_policy: bool = True,
        restrict_public_buckets: bool = True,
    ) -> OperationResult:
        """
        Enable S3 Block Public Access at the account level.

        Uses s3control.PutPublicAccessBlock.
        """
        result = OperationResult(
            operation="block_s3_public_access",
            target=f"account={account_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "block_s3_public_access.dry_run", target=result.target))
            return result

        s3control = self._services.s3control

        try:
            s3control.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": block_public_acls,
                    "IgnorePublicAcls": ignore_public_acls,
                    "BlockPublicPolicy": block_public_policy,
                    "RestrictPublicBuckets": restrict_public_buckets,
                },
            )
            result.details["status"] = "S3 public access blocked at account level"
            _log.info(event("aws_ir_response", "block_s3_public_access.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "block_s3_public_access.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # EC2: Isolate instances
    # --------------------

    def isolate_ec2_instances(
        self,
        instance_ids: list[str],
        *,
        vpc_id: Optional[str] = None,
        sg_name: str = "dredge-forensic-isolation",
        description: str = "Dredge forensic isolation group (no inbound/outbound)",
    ) -> OperationResult:
        """
        Isolate one or more EC2 instances by:
          - Creating (or reusing) a security group with no ingress/egress
          - Assigning that SG to the instances (replacing existing groups)
        """
        result = OperationResult(
            operation="isolate_ec2_instances",
            target=",".join(instance_ids),
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "isolate_ec2_instances.dry_run", target=result.target))
            return result

        _log.debug(event("aws_ir_response", "isolate_ec2_instances.start", target=result.target))
        ec2 = self._services.ec2

        try:
            # Build VPC -> [instance_ids] map.
            # When vpc_id is explicit, all instances are assumed to be in that VPC.
            # When not provided, query each instance individually so that instances
            # spread across multiple VPCs are all correctly isolated.
            if vpc_id:
                vpc_map: Dict[str, List[str]] = {vpc_id: list(instance_ids)}
            else:
                vpc_map = {}
                for inst_id in instance_ids:
                    desc = ec2.describe_instances(InstanceIds=[inst_id])
                    reservations = desc.get("Reservations", [])
                    if not reservations or not reservations[0]["Instances"]:
                        raise RuntimeError(f"Unable to describe instance {inst_id}")
                    v = reservations[0]["Instances"][0]["VpcId"]
                    vpc_map.setdefault(v, []).append(inst_id)

            # For each VPC, find/create an isolation SG and apply it to every instance in that VPC.
            sg_map: Dict[str, str] = {}
            for v, insts in vpc_map.items():
                sg_id = self._find_or_create_isolation_sg(
                    ec2=ec2,
                    vpc_id=v,
                    sg_name=sg_name,
                    description=description,
                )
                sg_map[v] = sg_id
                for instance_id in insts:
                    try:
                        ec2.modify_instance_attribute(
                            InstanceId=instance_id,
                            Groups=[sg_id],
                        )
                        _log.info(event("aws_ir_response", "isolate_ec2_instances.instance_isolated", instance=instance_id, sg=sg_id))
                    except botocore.exceptions.ClientError as exc:
                        result.add_error(f"Failed to isolate {instance_id}: {exc}")
                        _log.warning(event("aws_ir_response", "isolate_ec2_instances.instance_error", instance=instance_id, error=str(exc)))

            # Single VPC → store SG ID as a string for backward compatibility.
            # Multiple VPCs → store a vpc_id → sg_id map.
            if len(sg_map) == 1:
                result.details["isolation_security_group_id"] = next(iter(sg_map.values()))
            else:
                result.details["isolation_security_group_id"] = sg_map

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError, RuntimeError) as exc:
            result.add_error(f"Fatal error isolating instances: {exc}")
            _log.error(event("aws_ir_response", "isolate_ec2_instances.fatal", target=result.target, error=str(exc)))

        return result

    # ---- internal helpers ----

    @staticmethod
    def _find_or_create_isolation_sg(ec2, vpc_id: str, sg_name: str, description: str) -> str:
        # Try to find
        resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        groups = resp.get("SecurityGroups", [])
        if groups:
            return groups[0]["GroupId"]

        # Create new SG with no rules
        create_resp = ec2.create_security_group(
            GroupName=sg_name,
            Description=description,
            VpcId=vpc_id,
        )
        sg_id = create_resp["GroupId"]

        # Ensure no ingress/egress rules (API might create default egress)
        try:
            ec2.revoke_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )
        except botocore.exceptions.ClientError:
            # No default egress rules existed — safe to ignore.
            pass

        return sg_id

    # --------------------
    # IAM: Delete user (uses disable_user first)
    # --------------------

    def delete_user(self, user_name: str) -> OperationResult:
        """
        Fully delete an IAM user in a safe-ish way:

          1) Call disable_user(user_name) to:
             - deactivate all access keys
             - remove from groups
             - delete login profile
             - detach managed policies
             - delete inline policies
          2) Delete the IAM user object itself.

        NOTE: This is destructive. Prefer disable_user for containment
        and only delete when you're sure.
        """
        # First, reuse disable_user
        disable_result = self.disable_user(user_name)

        result = OperationResult(
            operation="delete_user",
            target=f"user={user_name}",
            success=disable_result.success,
            details=dict(disable_result.details),
            errors=list(disable_result.errors),
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        # Require a clean disable before permanently deleting the user.
        # If any step of disable_user failed (e.g. a policy couldn't be detached),
        # the user may still have active permissions — aborting is safer than
        # deleting a partially-cleaned user.
        if not disable_result.success:
            result.add_error(
                f"Aborting deletion of user {user_name}: disable_user reported failures. "
                "Resolve errors and retry."
            )
            return result

        iam = self._services.iam

        try:
            iam.delete_user(UserName=user_name)
            result.details["user_deleted"] = True
            _log.info(event("aws_ir_response", "delete_user.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to delete user {user_name}: {exc}")
            _log.warning(event("aws_ir_response", "delete_user.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # S3: Bucket / object level block
    # --------------------

    def block_s3_bucket_public_access(self, bucket_name: str) -> OperationResult:
        """
        Make a bucket 'private' in an IR context by:

          - Setting S3 Block Public Access at bucket level
          - Setting ACL to 'private'
          - Deleting bucket policy (if present)
        """
        result = OperationResult(
            operation="block_s3_bucket_public_access",
            target=f"bucket={bucket_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "block_s3_bucket_public_access.dry_run", target=result.target))
            return result

        s3 = self._services.s3

        try:
            # 1) Block Public Access (bucket-level)
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            result.details["public_access_blocked"] = True
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to set bucket PublicAccessBlock: {exc}")
            _log.warning(event("aws_ir_response", "block_s3_bucket_public_access.access_block_error", bucket=bucket_name, error=str(exc)))

        try:
            # 2) ACL -> private
            s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
            result.details["acl_set_private"] = True
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to set bucket ACL to private: {exc}")
            _log.warning(event("aws_ir_response", "block_s3_bucket_public_access.acl_error", bucket=bucket_name, error=str(exc)))

        # NOTE: The bucket policy is intentionally NOT deleted here.
        # S3 Block Public Access (set above) overrides any permissive policy, so public
        # access is already denied. A restrictive policy (e.g. VPC-only) would be made
        # MORE permissive by deletion. Callers that need to remove the policy may do so
        # explicitly via the S3 API after confirming the policy contents.

        if result.success:
            _log.info(event("aws_ir_response", "block_s3_bucket_public_access.success", target=result.target))

        return result

    def block_s3_object_public_access(self, bucket_name: str, key: str) -> OperationResult:
        """
        Make a single object 'private' by:

          - Setting ACL to 'private'
        """
        result = OperationResult(
            operation="block_s3_object_public_access",
            target=f"bucket={bucket_name},key={key}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "block_s3_object_public_access.dry_run", target=result.target))
            return result

        s3 = self._services.s3

        try:
            s3.put_object_acl(
                Bucket=bucket_name,
                Key=key,
                ACL="private",
            )
            result.details["acl_set_private"] = True
            _log.info(event("aws_ir_response", "block_s3_object_public_access.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to set object ACL to private: {exc}")
            _log.warning(event("aws_ir_response", "block_s3_object_public_access.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: MFA devices
    # --------------------

    def delete_mfa_devices(self, user_name: str) -> OperationResult:
        """
        Deactivate and delete all MFA devices associated with a user.

        Virtual MFA devices (ARN-based serials) are deactivated then deleted.
        Hardware tokens are deactivated only — they cannot be deleted programmatically.
        """
        result = OperationResult(
            operation="delete_mfa_devices",
            target=f"user={user_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "delete_mfa_devices.dry_run", target=result.target))
            return result

        iam = self._services.iam

        try:
            serials = [
                device["SerialNumber"]
                for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name)
                for device in page.get("MFADevices", [])
            ]

            for serial in serials:
                try:
                    iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial)
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to deactivate MFA device {serial}: {exc}")
                    _log.warning(event("aws_ir_response", "delete_mfa_devices.deactivate_error", serial=serial, error=str(exc)))
                    continue  # skip delete if deactivate failed

                # Virtual MFA devices (ARN serials) can be deleted; hardware tokens cannot.
                if serial.startswith("arn:"):
                    try:
                        iam.delete_virtual_mfa_device(SerialNumber=serial)
                    except botocore.exceptions.ClientError as exc:
                        result.add_error(f"Failed to delete virtual MFA device {serial}: {exc}")
                        _log.warning(event("aws_ir_response", "delete_mfa_devices.delete_error", serial=serial, error=str(exc)))

            result.details["devices_deleted"] = serials
            _log.info(event("aws_ir_response", "delete_mfa_devices.success", target=result.target, count=len(serials)))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            result.add_error(f"Fatal error deleting MFA devices: {exc}")
            _log.error(event("aws_ir_response", "delete_mfa_devices.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Session revocation
    # --------------------

    def revoke_active_sessions(self, user_name: str) -> OperationResult:
        """
        Immediately invalidate all active sessions for a user by attaching a
        deny-all inline policy conditioned on aws:TokenIssueTime.

        Any temporary credential (assumed-role STS token) issued before this
        call will be denied on its next AWS API call.

        NOTE: This does NOT revoke permanent IAM access keys. Call disable_user
        for full account lockout.
        """
        result = OperationResult(
            operation="revoke_active_sessions",
            target=f"user={user_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "revoke_active_sessions.dry_run", target=result.target))
            return result

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        policy_name = "DredgeRevokeActiveSessions"
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DredgeRevokeOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": now,
                    }
                },
            }],
        })

        iam = self._services.iam

        try:
            iam.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=policy_doc,
            )
            result.details["policy_name"] = policy_name
            result.details["revocation_time"] = now
            _log.info(event("aws_ir_response", "revoke_active_sessions.success", target=result.target, revocation_time=now))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "revoke_active_sessions.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # EC2: Stop / terminate
    # --------------------

    def stop_ec2_instances(self, instance_ids: List[str]) -> OperationResult:
        """
        Stop one or more EC2 instances (graceful shutdown, can be restarted).
        """
        result = OperationResult(
            operation="stop_ec2_instances",
            target=",".join(instance_ids),
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "stop_ec2_instances.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        try:
            resp = ec2.stop_instances(InstanceIds=instance_ids)
            result.details["stopping"] = {
                item["InstanceId"]: item["CurrentState"]["Name"]
                for item in resp.get("StoppingInstances", [])
            }
            _log.info(event("aws_ir_response", "stop_ec2_instances.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "stop_ec2_instances.error", target=result.target, error=str(exc)))

        return result

    def terminate_ec2_instances(
        self,
        instance_ids: List[str],
        *,
        snapshot_first: bool = True,
    ) -> OperationResult:
        """
        Terminate one or more EC2 instances.

        When snapshot_first=True (default), all attached EBS volumes are
        snapshotted before termination for forensic preservation. Snapshot
        failures are recorded but do not block termination.

        This is DESTRUCTIVE and cannot be undone.
        """
        result = OperationResult(
            operation="terminate_ec2_instances",
            target=",".join(instance_ids),
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "terminate_ec2_instances.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        try:
            if snapshot_first:
                snapshots: Dict[str, Dict[str, str]] = {}
                desc = ec2.describe_instances(InstanceIds=instance_ids)
                for reservation in desc.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        inst_id = instance["InstanceId"]
                        inst_snaps: Dict[str, str] = {}
                        for mapping in instance.get("BlockDeviceMappings", []):
                            ebs = mapping.get("Ebs")
                            if not ebs:
                                continue
                            vol_id = ebs["VolumeId"]
                            try:
                                snap = ec2.create_snapshot(
                                    VolumeId=vol_id,
                                    Description=f"dredge-pre-termination {inst_id} {vol_id}",
                                )
                                inst_snaps[vol_id] = snap["SnapshotId"]
                                _log.info(event("aws_ir_response", "terminate_ec2_instances.snapped", instance=inst_id, volume=vol_id, snapshot=snap["SnapshotId"]))
                            except botocore.exceptions.ClientError as exc:
                                result.add_error(f"Failed to snapshot {vol_id} ({inst_id}): {exc}")
                                _log.warning(event("aws_ir_response", "terminate_ec2_instances.snapshot_error", volume=vol_id, error=str(exc)))
                        snapshots[inst_id] = inst_snaps
                result.details["snapshots_created"] = snapshots

            resp = ec2.terminate_instances(InstanceIds=instance_ids)
            result.details["terminating"] = {
                item["InstanceId"]: item["CurrentState"]["Name"]
                for item in resp.get("TerminatingInstances", [])
            }
            _log.info(event("aws_ir_response", "terminate_ec2_instances.success", target=result.target))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            result.add_error(f"Fatal error terminating instances: {exc}")
            _log.error(event("aws_ir_response", "terminate_ec2_instances.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # VPC: Network ACL blocking
    # --------------------

    def block_nacl_cidrs(
        self,
        vpc_id: str,
        cidrs: List[str],
        *,
        rule_number_start: int = 1,
    ) -> OperationResult:
        """
        Add DENY rules (ingress and egress) for the given CIDRs to every
        Network ACL in the specified VPC.

        Rule numbers are assigned starting at rule_number_start, skipping any
        numbers already in use. Ingress and egress share independent number
        spaces so the same numbers can be used for both directions.
        """
        result = OperationResult(
            operation="block_nacl_cidrs",
            target=f"vpc={vpc_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "block_nacl_cidrs.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        try:
            resp = ec2.describe_network_acls(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            nacls = resp.get("NetworkAcls", [])

            nacls_modified: List[str] = []
            total_rules_added = 0

            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                entries = nacl.get("Entries", [])

                # Build used-number sets per direction (32767 is the AWS default catch-all)
                used_ingress = {
                    e["RuleNumber"] for e in entries
                    if not e.get("Egress") and e["RuleNumber"] != 32767
                }
                used_egress = {
                    e["RuleNumber"] for e in entries
                    if e.get("Egress") and e["RuleNumber"] != 32767
                }

                next_in = max(used_ingress, default=0)
                next_in = max(next_in, rule_number_start - 1) + 1
                # Start at rule_number_start if available, else above existing
                if rule_number_start not in used_ingress:
                    next_in = rule_number_start

                next_eg = max(used_egress, default=0)
                next_eg = max(next_eg, rule_number_start - 1) + 1
                if rule_number_start not in used_egress:
                    next_eg = rule_number_start

                for cidr in cidrs:
                    # Find free ingress rule number
                    while next_in in used_ingress or next_in >= 32767:
                        next_in += 1
                    in_num = next_in
                    used_ingress.add(in_num)
                    next_in += 1

                    # Find free egress rule number
                    while next_eg in used_egress or next_eg >= 32767:
                        next_eg += 1
                    eg_num = next_eg
                    used_egress.add(eg_num)
                    next_eg += 1

                    try:
                        ec2.create_network_acl_entry(
                            NetworkAclId=nacl_id,
                            RuleNumber=in_num,
                            Protocol="-1",
                            RuleAction="deny",
                            Egress=False,
                            CidrBlock=cidr,
                        )
                        total_rules_added += 1
                    except botocore.exceptions.ClientError as exc:
                        result.add_error(f"Failed to add ingress DENY rule for {cidr} on {nacl_id}: {exc}")
                        _log.warning(event("aws_ir_response", "block_nacl_cidrs.ingress_error", nacl=nacl_id, cidr=cidr, error=str(exc)))

                    try:
                        ec2.create_network_acl_entry(
                            NetworkAclId=nacl_id,
                            RuleNumber=eg_num,
                            Protocol="-1",
                            RuleAction="deny",
                            Egress=True,
                            CidrBlock=cidr,
                        )
                        total_rules_added += 1
                    except botocore.exceptions.ClientError as exc:
                        result.add_error(f"Failed to add egress DENY rule for {cidr} on {nacl_id}: {exc}")
                        _log.warning(event("aws_ir_response", "block_nacl_cidrs.egress_error", nacl=nacl_id, cidr=cidr, error=str(exc)))

                nacls_modified.append(nacl_id)

            result.details["nacls_modified"] = nacls_modified
            result.details["rules_added"] = total_rules_added
            _log.info(event("aws_ir_response", "block_nacl_cidrs.success", target=result.target, rules=total_rules_added))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            result.add_error(f"Fatal error blocking NACL CIDRs: {exc}")
            _log.error(event("aws_ir_response", "block_nacl_cidrs.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Lambda: Disable
    # --------------------

    def disable_lambda_function(self, function_name: str) -> OperationResult:
        """
        Throttle a Lambda function to zero by setting reserved concurrency to 0.

        All new invocations will receive TooManyRequestsException. In-flight
        executions are not interrupted.
        """
        result = OperationResult(
            operation="disable_lambda_function",
            target=f"function={function_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_lambda_function.dry_run", target=result.target))
            return result

        lambda_ = self._services.lambda_

        try:
            lambda_.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=0,
            )
            result.details["reserved_concurrency"] = 0
            _log.info(event("aws_ir_response", "disable_lambda_function.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_lambda_function.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # KMS: Disable / schedule deletion
    # --------------------

    def disable_kms_key(self, key_id: str) -> OperationResult:
        """
        Disable a KMS key. Disabled keys cannot be used for cryptographic
        operations but are not deleted.
        """
        result = OperationResult(
            operation="disable_kms_key",
            target=f"key={key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_kms_key.dry_run", target=result.target))
            return result

        try:
            self._services.kms.disable_key(KeyId=key_id)
            result.details["status"] = "Key disabled"
            _log.info(event("aws_ir_response", "disable_kms_key.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_kms_key.error", target=result.target, error=str(exc)))

        return result

    def schedule_kms_key_deletion(
        self,
        key_id: str,
        *,
        pending_window_days: int = 7,
    ) -> OperationResult:
        """
        Schedule a KMS key for deletion.

        pending_window_days must be between 7 and 30. After this window the
        key is permanently deleted and all data encrypted with it becomes
        irrecoverable.
        """
        if not (7 <= pending_window_days <= 30):
            raise ValueError(
                f"pending_window_days must be between 7 and 30, got {pending_window_days}"
            )

        result = OperationResult(
            operation="schedule_kms_key_deletion",
            target=f"key={key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "schedule_kms_key_deletion.dry_run", target=result.target))
            return result

        try:
            resp = self._services.kms.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=pending_window_days,
            )
            result.details["deletion_date"] = resp["DeletionDate"].isoformat()
            result.details["pending_window_days"] = pending_window_days
            _log.info(event("aws_ir_response", "schedule_kms_key_deletion.success", target=result.target, deletion_date=result.details["deletion_date"]))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "schedule_kms_key_deletion.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Tagging
    # --------------------

    def tag_resources(
        self,
        resource_arns: List[str],
        tags: Dict[str, str],
    ) -> OperationResult:
        """
        Apply tags to one or more AWS resources identified by ARN.

        Uses resourcegroupstaggingapi, which supports most AWS resource types.
        Requests are batched automatically (max 20 ARNs per API call).
        """
        result = OperationResult(
            operation="tag_resources",
            target=f"arns={len(resource_arns)}",
            success=True,
        )

        if not resource_arns:
            result.details["tagged"] = 0
            return result

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "tag_resources.dry_run", target=result.target))
            return result

        tagging = self._services.tagging
        all_failed: Dict[str, str] = {}

        for i in range(0, len(resource_arns), 20):
            batch = resource_arns[i:i + 20]
            try:
                resp = tagging.tag_resources(ResourceARNList=batch, Tags=tags)
                for arn, info in resp.get("FailedResourcesMap", {}).items():
                    all_failed[arn] = info.get("ErrorMessage", "unknown error")
            except botocore.exceptions.ClientError as exc:
                for arn in batch:
                    all_failed[arn] = str(exc)
                _log.warning(event("aws_ir_response", "tag_resources.batch_error", batch_start=i, error=str(exc)))

        result.details["tagged"] = len(resource_arns) - len(all_failed)
        if all_failed:
            result.details["failed"] = all_failed
            result.add_error(f"Failed to tag {len(all_failed)} resource(s)")

        _log.info(event("aws_ir_response", "tag_resources.complete", tagged=result.details["tagged"], failed=len(all_failed)))
        return result

    # --------------------
    # RDS: Isolate instance
    # --------------------

    def isolate_rds_instance(
        self,
        db_instance_id: str,
        *,
        sg_name: str = "dredge-rds-isolation",
        description: str = "Dredge IR isolation (no inbound/outbound)",
    ) -> OperationResult:
        """
        Isolate an RDS instance by replacing its security groups with an empty
        isolation SG and disabling public accessibility.

        NOTE: Triggers an RDS modification with ApplyImmediately=True.
        """
        result = OperationResult(
            operation="isolate_rds_instance",
            target=f"db_instance={db_instance_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "isolate_rds_instance.dry_run", target=result.target))
            return result

        rds = self._services.rds
        ec2 = self._services.ec2

        try:
            desc = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
            instances = desc.get("DBInstances", [])
            if not instances:
                raise RuntimeError(f"RDS instance not found: {db_instance_id}")

            db = instances[0]
            vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
            if not vpc_id:
                raise RuntimeError(f"Could not determine VPC ID for {db_instance_id}")

            result.details["original_security_groups"] = [
                sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])
            ]

            sg_id = self._find_or_create_isolation_sg(
                ec2=ec2, vpc_id=vpc_id, sg_name=sg_name, description=description
            )

            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                VpcSecurityGroupIds=[sg_id],
                PubliclyAccessible=False,
                ApplyImmediately=True,
            )
            result.details["isolation_security_group_id"] = sg_id
            result.details["publicly_accessible"] = False
            _log.info(event("aws_ir_response", "isolate_rds_instance.success", target=result.target, sg=sg_id))

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError, RuntimeError) as exc:
            result.add_error(f"Failed to isolate RDS instance: {exc}")
            _log.error(event("aws_ir_response", "isolate_rds_instance.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # ECS: Containment
    # --------------------

    def stop_ecs_service(self, cluster: str, service: str) -> OperationResult:
        """
        Scale an ECS service to 0 desired tasks, preventing new task launches.

        Running tasks continue until they exit; use stop_ecs_task to force-stop
        individual tasks immediately.
        """
        result = OperationResult(
            operation="stop_ecs_service",
            target=f"cluster={cluster},service={service}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "stop_ecs_service.dry_run", target=result.target))
            return result

        try:
            resp = self._services.ecs.update_service(
                cluster=cluster,
                service=service,
                desiredCount=0,
            )
            svc = resp.get("service", {})
            result.details["desired_count"] = svc.get("desiredCount", 0)
            result.details["running_count"] = svc.get("runningCount")
            _log.info(event("aws_ir_response", "stop_ecs_service.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "stop_ecs_service.error", target=result.target, error=str(exc)))

        return result

    def stop_ecs_task(
        self,
        cluster: str,
        task_id: str,
        *,
        reason: str = "Dredge IR containment",
    ) -> OperationResult:
        """
        Force-stop a running ECS task immediately.
        """
        result = OperationResult(
            operation="stop_ecs_task",
            target=f"cluster={cluster},task={task_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "stop_ecs_task.dry_run", target=result.target))
            return result

        try:
            self._services.ecs.stop_task(cluster=cluster, task=task_id, reason=reason)
            result.details["status"] = "Task stopped"
            _log.info(event("aws_ir_response", "stop_ecs_task.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "stop_ecs_task.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Secrets Manager
    # --------------------

    def disable_secrets_manager_secret(
        self,
        secret_id: str,
        *,
        recovery_window_days: int = 7,
    ) -> OperationResult:
        """
        Schedule a Secrets Manager secret for deletion.

        The secret enters a pending-deletion state for recovery_window_days (7–30)
        before being permanently deleted. It cannot be retrieved during this window.
        """
        if not (7 <= recovery_window_days <= 30):
            raise ValueError(f"recovery_window_days must be 7–30, got {recovery_window_days}")

        result = OperationResult(
            operation="disable_secrets_manager_secret",
            target=f"secret={secret_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_secrets_manager_secret.dry_run", target=result.target))
            return result

        try:
            resp = self._services.secretsmanager.delete_secret(
                SecretId=secret_id,
                RecoveryWindowInDays=recovery_window_days,
            )
            deletion_date = resp.get("DeletionDate")
            result.details["deletion_date"] = deletion_date.isoformat() if deletion_date else None
            result.details["recovery_window_days"] = recovery_window_days
            _log.info(event("aws_ir_response", "disable_secrets_manager_secret.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_secrets_manager_secret.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # EventBridge
    # --------------------

    def disable_eventbridge_rule(
        self,
        rule_name: str,
        *,
        event_bus_name: str = "default",
    ) -> OperationResult:
        """
        Disable an EventBridge rule, preventing it from triggering its targets.
        """
        result = OperationResult(
            operation="disable_eventbridge_rule",
            target=f"rule={rule_name},bus={event_bus_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_eventbridge_rule.dry_run", target=result.target))
            return result

        try:
            self._services.events.disable_rule(
                Name=rule_name,
                EventBusName=event_bus_name,
            )
            result.details["status"] = "Rule disabled"
            _log.info(event("aws_ir_response", "disable_eventbridge_rule.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_eventbridge_rule.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # SSM: Terminate sessions
    # --------------------

    def terminate_ssm_sessions(self, instance_id: str) -> OperationResult:
        """
        Terminate all active SSM sessions on the target instance.
        """
        result = OperationResult(
            operation="terminate_ssm_sessions",
            target=f"instance={instance_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "terminate_ssm_sessions.dry_run", target=result.target))
            return result

        ssm = self._services.ssm

        try:
            resp = ssm.describe_sessions(
                State="Active",
                Filters=[{"key": "Target", "value": instance_id}],
            )
            sessions = resp.get("Sessions", [])
            terminated: List[str] = []
            for session in sessions:
                session_id = session["SessionId"]
                try:
                    ssm.terminate_session(SessionId=session_id)
                    terminated.append(session_id)
                    _log.info(event("aws_ir_response", "terminate_ssm_sessions.terminated", session_id=session_id))
                except botocore.exceptions.ClientError as exc:
                    result.add_error(f"Failed to terminate session {session_id}: {exc}")
                    _log.warning(event("aws_ir_response", "terminate_ssm_sessions.session_error", session_id=session_id, error=str(exc)))

            result.details["terminated"] = terminated
            result.details["total_terminated"] = len(terminated)
            _log.info(event("aws_ir_response", "terminate_ssm_sessions.success", target=result.target, count=len(terminated)))

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list SSM sessions: {exc}")
            _log.error(event("aws_ir_response", "terminate_ssm_sessions.fatal", target=result.target, error=str(exc)))

        return result

    # --------------------
    # EC2: Security group rules
    # --------------------

    def deauthorize_security_group_rules(
        self,
        group_id: str,
        *,
        ingress_rules: Optional[List[Dict]] = None,
        egress_rules: Optional[List[Dict]] = None,
    ) -> OperationResult:
        """
        Revoke specific ingress and/or egress rules from a security group.

        ingress_rules and egress_rules are lists of IpPermission dicts in the
        standard AWS format, e.g.:
          {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "1.2.3.4/32"}]}
        """
        if not ingress_rules and not egress_rules:
            raise ValueError("At least one of ingress_rules or egress_rules must be provided")

        result = OperationResult(
            operation="deauthorize_security_group_rules",
            target=f"sg={group_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "deauthorize_security_group_rules.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        if ingress_rules:
            try:
                ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=ingress_rules)
                result.details["ingress_rules_revoked"] = len(ingress_rules)
                _log.info(event("aws_ir_response", "deauthorize_sg_rules.ingress_ok", sg=group_id, count=len(ingress_rules)))
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to revoke ingress rules: {exc}")
                _log.warning(event("aws_ir_response", "deauthorize_sg_rules.ingress_error", sg=group_id, error=str(exc)))

        if egress_rules:
            try:
                ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=egress_rules)
                result.details["egress_rules_revoked"] = len(egress_rules)
                _log.info(event("aws_ir_response", "deauthorize_sg_rules.egress_ok", sg=group_id, count=len(egress_rules)))
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to revoke egress rules: {exc}")
                _log.warning(event("aws_ir_response", "deauthorize_sg_rules.egress_error", sg=group_id, error=str(exc)))

        return result

    # --------------------
    # IAM: Detach single policy
    # --------------------

    def detach_iam_policy(
        self,
        policy_arn: str,
        *,
        user_name: Optional[str] = None,
        role_name: Optional[str] = None,
    ) -> OperationResult:
        """
        Detach a single managed policy from a user or role.

        Exactly one of user_name or role_name must be provided.
        """
        if not user_name and not role_name:
            raise ValueError("Exactly one of user_name or role_name must be provided")
        if user_name and role_name:
            raise ValueError("Provide only one of user_name or role_name, not both")

        principal = f"user={user_name}" if user_name else f"role={role_name}"
        result = OperationResult(
            operation="detach_iam_policy",
            target=f"{principal},policy={policy_arn}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "detach_iam_policy.dry_run", target=result.target))
            return result

        iam = self._services.iam
        try:
            if user_name:
                iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            else:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            result.details["policy_detached"] = policy_arn
            _log.info(event("aws_ir_response", "detach_iam_policy.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "detach_iam_policy.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # S3: Quarantine bucket
    # --------------------

    def quarantine_s3_bucket(
        self,
        bucket_name: str,
        *,
        account_id: Optional[str] = None,
    ) -> OperationResult:
        """
        Quarantine an S3 bucket by:
          1. Enabling Block Public Access at bucket level
          2. Applying a Deny-all bucket policy for principals outside the account

        account_id is auto-detected via STS if not provided.
        """
        result = OperationResult(
            operation="quarantine_s3_bucket",
            target=f"bucket={bucket_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "quarantine_s3_bucket.dry_run", target=result.target))
            return result

        if not account_id:
            try:
                identity = self._services.sts.get_caller_identity()
                account_id = identity["Account"]
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to resolve account ID: {exc}")
                return result

        s3 = self._services.s3

        try:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            result.details["public_access_blocked"] = True

            policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DredgeQuarantineDenyExternal",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                    "Condition": {
                        "StringNotEquals": {"aws:PrincipalAccount": account_id},
                    },
                }],
            })
            s3.put_bucket_policy(Bucket=bucket_name, Policy=policy)
            result.details["quarantine_policy_applied"] = True
            result.details["account_id"] = account_id
            _log.info(event("aws_ir_response", "quarantine_s3_bucket.success", target=result.target))

        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "quarantine_s3_bucket.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Remove from group
    # --------------------

    def remove_user_from_group(self, user_name: str, group_name: str) -> OperationResult:
        """
        Remove an IAM user from a group.

        Groups are the primary way managed policies are inherited. Removing the
        user from a group cuts all permissions granted through that group.
        """
        result = OperationResult(
            operation="remove_user_from_group",
            target=f"user={user_name},group={group_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "remove_user_from_group.dry_run", target=result.target))
            return result

        try:
            self._services.iam.remove_user_from_group(
                UserName=user_name,
                GroupName=group_name,
            )
            result.details["removed"] = True
            _log.info(event("aws_ir_response", "remove_user_from_group.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "remove_user_from_group.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Deny-all inline policy
    # --------------------

    def put_deny_all_inline_policy(
        self,
        *,
        user_name: Optional[str] = None,
        role_name: Optional[str] = None,
        policy_name: str = "DredgeIRDenyAll",
    ) -> OperationResult:
        """
        Attach a Deny-* inline policy to a user or role for immediate lockout.

        Unlike disable_role (which clears the trust policy), this preserves the
        principal while hard-blocking all actions. Useful for quick containment
        before a full forensic review.

        Exactly one of user_name or role_name must be provided.
        """
        if not user_name and not role_name:
            raise ValueError("Provide exactly one of user_name or role_name")
        if user_name and role_name:
            raise ValueError("Provide exactly one of user_name or role_name")

        target = f"user={user_name}" if user_name else f"role={role_name}"
        result = OperationResult(
            operation="put_deny_all_inline_policy",
            target=target,
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "put_deny_all_inline_policy.dry_run", target=result.target))
            return result

        policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DredgeIRDenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }],
        })

        try:
            iam = self._services.iam
            if user_name:
                iam.put_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name,
                    PolicyDocument=policy_document,
                )
            else:
                iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                    PolicyDocument=policy_document,
                )
            result.details["policy_name"] = policy_name
            result.details["applied"] = True
            _log.info(event("aws_ir_response", "put_deny_all_inline_policy.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "put_deny_all_inline_policy.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Revoke active role sessions
    # --------------------

    def revoke_iam_role_sessions(self, role_name: str) -> OperationResult:
        """
        Revoke all active sessions for an IAM role.

        Adds a time-stamped Deny inline policy using aws:TokenIssueTime < now,
        which immediately invalidates all existing STS tokens for this role.
        Tokens issued after this policy is attached will not be affected.
        """
        result = OperationResult(
            operation="revoke_iam_role_sessions",
            target=f"role={role_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "revoke_iam_role_sessions.dry_run", target=result.target))
            return result

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DredgeIRRevokeOldSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": now_iso,
                    },
                },
            }],
        })

        try:
            self._services.iam.put_role_policy(
                RoleName=role_name,
                PolicyName="DredgeIRRevokeOldSessions",
                PolicyDocument=policy_document,
            )
            result.details["revocation_time"] = now_iso
            result.details["applied"] = True
            _log.info(event("aws_ir_response", "revoke_iam_role_sessions.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "revoke_iam_role_sessions.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # Lambda: Disable event source mapping
    # --------------------

    def disable_lambda_event_source_mapping(self, uuid: str) -> OperationResult:
        """
        Disable a Lambda event source mapping (SQS, Kinesis, DynamoDB trigger).

        Stops the Lambda from consuming events from the source without deleting
        the mapping. Use list_event_source_mappings to find UUIDs.
        """
        result = OperationResult(
            operation="disable_lambda_event_source_mapping",
            target=f"esm={uuid}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "disable_lambda_event_source_mapping.dry_run", target=result.target))
            return result

        try:
            resp = self._services.lambda_.update_event_source_mapping(
                UUID=uuid,
                Enabled=False,
            )
            result.details["state"] = resp.get("State")
            result.details["function_arn"] = resp.get("FunctionArn")
            _log.info(event("aws_ir_response", "disable_lambda_event_source_mapping.success", target=result.target))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "disable_lambda_event_source_mapping.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # ECR: Delete image
    # --------------------

    def delete_ecr_image(
        self,
        repository: str,
        image_digest: str,
        *,
        registry_id: Optional[str] = None,
    ) -> OperationResult:
        """
        Delete a container image from an ECR repository.

        Removes the image by digest so it cannot be re-deployed. Use the digest
        (sha256:...) rather than tag, as tags are mutable.

        Args:
            repository:   ECR repository name.
            image_digest: Image digest, e.g. "sha256:abc123...".
            registry_id:  AWS account ID owning the registry. Defaults to caller account.
        """
        result = OperationResult(
            operation="delete_ecr_image",
            target=f"repo={repository},digest={image_digest[:19]}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_response", "delete_ecr_image.dry_run", target=result.target))
            return result

        kwargs: Dict = {
            "repositoryName": repository,
            "imageIds": [{"imageDigest": image_digest}],
        }
        if registry_id:
            kwargs["registryId"] = registry_id

        try:
            resp = self._services.ecr.batch_delete_image(**kwargs)
            failures = resp.get("failures", [])
            if failures:
                for f in failures:
                    result.add_error(f"ECR delete failure: {f.get('failureCode')} — {f.get('failureReason')}")
                _log.warning(event("aws_ir_response", "delete_ecr_image.partial_failure", target=result.target, failures=len(failures)))
            else:
                result.details["deleted"] = True
                _log.info(event("aws_ir_response", "delete_ecr_image.success", target=result.target))
            result.details["image_ids_deleted"] = resp.get("imageIds", [])
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_response", "delete_ecr_image.error", target=result.target, error=str(exc)))

        return result
