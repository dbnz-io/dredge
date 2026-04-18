from __future__ import annotations

from typing import Any, Dict, List, Optional

import botocore.exceptions

from .. import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)


class AwsIRForensics:
    """
    Forensics-focused actions (snapshots, evidence collection, etc.).

    Example:
        dredge.aws_ir.forensics.get_ebs_snapshot(volume_id="vol-123", description="IR case X")
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def get_ebs_snapshot(
        self,
        volume_id: str,
        *,
        description: str = "Dredge forensic snapshot",
    ) -> OperationResult:
        """
        Create a snapshot of the specified EBS volume.
        """
        result = OperationResult(
            operation="get_ebs_snapshot",
            target=f"volume={volume_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_forensics", "get_ebs_snapshot.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        try:
            resp = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=description,
            )
            snapshot_id = resp["SnapshotId"]
            result.details["snapshot_id"] = snapshot_id
            _log.info(event("aws_ir_forensics", "get_ebs_snapshot.success", target=result.target, snapshot_id=snapshot_id))
        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_forensics", "get_ebs_snapshot.error", target=result.target, error=str(exc)))

        return result

    def snapshot_instance_volumes(
        self,
        instance_id: str,
        *,
        include_root: bool = True,
        description_prefix: str = "Dredge forensic snapshot",
    ) -> OperationResult:
        """
        Snapshot all (or non-root) EBS volumes attached to an instance.
        """
        result = OperationResult(
            operation="snapshot_instance_volumes",
            target=f"instance={instance_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_forensics", "snapshot_instance_volumes.dry_run", target=result.target))
            return result

        _log.debug(event("aws_ir_forensics", "snapshot_instance_volumes.start", target=result.target))
        ec2 = self._services.ec2
        snapshot_ids: Dict[str, str] = {}

        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
            reservations = desc.get("Reservations", [])
            if not reservations or not reservations[0]["Instances"]:
                raise RuntimeError(f"No instance found: {instance_id}")

            instance = reservations[0]["Instances"][0]
            block_devices = instance.get("BlockDeviceMappings", [])
            root_device_name = instance.get("RootDeviceName")

            for mapping in block_devices:
                device_name = mapping.get("DeviceName")
                ebs = mapping.get("Ebs")
                if not ebs:
                    continue

                volume_id = ebs["VolumeId"]

                if not include_root and device_name == root_device_name:
                    continue

                try:
                    desc_text = f"{description_prefix} for {instance_id} ({device_name})"
                    snap_resp = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=desc_text,
                    )
                    snapshot_id = snap_resp["SnapshotId"]
                    snapshot_ids[volume_id] = snapshot_id
                    _log.info(event("aws_ir_forensics", "snapshot_instance_volumes.volume_snapped", volume=volume_id, snapshot=snapshot_id))
                except botocore.exceptions.ClientError as exc:
                    result.add_error(
                        f"Failed to snapshot volume {volume_id} on {device_name}: {exc}"
                    )
                    _log.warning(event("aws_ir_forensics", "snapshot_instance_volumes.volume_error", volume=volume_id, error=str(exc)))

            result.details["snapshots"] = snapshot_ids

        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError, RuntimeError) as exc:
            result.add_error(f"Fatal error snapshotting instance volumes: {exc}")
            _log.error(event("aws_ir_forensics", "snapshot_instance_volumes.fatal", target=result.target, error=str(exc)))

        return result

    def get_lambda_environment(
        self,
        function_name: str,
        *,
        qualifier: str | None = None,
    ) -> OperationResult:
        """
        Fetch environment variables for a Lambda function.

        NOTE: Returns env vars in cleartext in result.details — handle
        the result carefully to avoid leaking secrets into logs.
        """
        result = OperationResult(
            operation="get_lambda_environment",
            target=f"function={function_name},qualifier={qualifier or 'LATEST'}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_forensics", "get_lambda_environment.dry_run", target=result.target))
            return result

        lambda_client = self._services.lambda_

        try:
            kwargs = {"FunctionName": function_name}
            if qualifier:
                kwargs["Qualifier"] = qualifier

            resp = lambda_client.get_function_configuration(**kwargs)
            env = resp.get("Environment", {}).get("Variables", {})

            result.details["environment_variables"] = env
            _log.info(event("aws_ir_forensics", "get_lambda_environment.success", target=result.target, var_count=len(env)))
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to fetch lambda environment: {exc}")
            _log.warning(event("aws_ir_forensics", "get_lambda_environment.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # VPC Flow Logs
    # --------------------

    def enable_vpc_flow_logs(
        self,
        vpc_id: str,
        *,
        log_group_name: str = "/aws/vpc/flowlogs",
        deliver_logs_permission_arn: Optional[str] = None,
        log_destination_type: str = "cloud-watch-logs",
        log_destination: Optional[str] = None,
        traffic_type: str = "ALL",
    ) -> OperationResult:
        """
        Enable VPC flow logs for a VPC.

        For cloud-watch-logs destination, deliver_logs_permission_arn is the IAM
        role that grants VPC permission to publish to CloudWatch Logs.
        For s3 destination, set log_destination_type="s3" and provide the S3
        bucket ARN as log_destination.

        Args:
            vpc_id:                       VPC to enable flow logs on.
            log_group_name:               CloudWatch Logs group name.
            deliver_logs_permission_arn:  IAM role ARN for CloudWatch Logs delivery.
            log_destination_type:         "cloud-watch-logs" or "s3".
            log_destination:              Destination ARN for s3 type.
            traffic_type:                 "ALL", "ACCEPT", or "REJECT".
        """
        result = OperationResult(
            operation="enable_vpc_flow_logs",
            target=f"vpc={vpc_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            _log.info(event("aws_ir_forensics", "enable_vpc_flow_logs.dry_run", target=result.target))
            return result

        ec2 = self._services.ec2

        params: Dict[str, Any] = {
            "ResourceIds": [vpc_id],
            "ResourceType": "VPC",
            "TrafficType": traffic_type,
            "LogDestinationType": log_destination_type,
        }
        if log_destination_type == "cloud-watch-logs":
            params["LogGroupName"] = log_group_name
            if deliver_logs_permission_arn:
                params["DeliverLogsPermissionArn"] = deliver_logs_permission_arn
        elif log_destination_type == "s3" and log_destination:
            params["LogDestination"] = log_destination

        try:
            resp = ec2.create_flow_logs(**params)
            flow_log_ids = resp.get("FlowLogIds", [])
            unsuccessful = resp.get("Unsuccessful", [])

            result.details["flow_log_ids"] = flow_log_ids
            for item in unsuccessful:
                result.add_error(
                    f"Flow log creation failed: {item.get('Error', {}).get('Message', 'unknown')}"
                )
            _log.info(event("aws_ir_forensics", "enable_vpc_flow_logs.success", target=result.target, flow_log_ids=flow_log_ids))

        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.warning(event("aws_ir_forensics", "enable_vpc_flow_logs.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # SSM Session History
    # --------------------

    def capture_ssm_session_history(
        self,
        *,
        instance_id: Optional[str] = None,
        owner: Optional[str] = None,
        max_sessions: int = 100,
    ) -> OperationResult:
        """
        Retrieve completed SSM session history.

        Args:
            instance_id:  Filter sessions by target instance ID.
            owner:        Filter by session owner (IAM user/role ARN or username).
            max_sessions: Maximum sessions to return.

        Returns:
            OperationResult with details["sessions"] = list of session metadata dicts.
        """
        result = OperationResult(
            operation="capture_ssm_session_history",
            target=f"instance={instance_id or 'all'}",
            success=True,
        )

        filters: List[Dict[str, str]] = []
        if instance_id:
            filters.append({"key": "Target", "value": instance_id})
        if owner:
            filters.append({"key": "Owner", "value": owner})

        ssm = self._services.ssm
        sessions: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(sessions) < max_sessions:
                params: Dict[str, Any] = {"State": "History"}
                if filters:
                    params["Filters"] = filters
                if next_token:
                    params["NextToken"] = next_token

                resp = ssm.describe_sessions(**params)
                batch = resp.get("Sessions", [])
                sessions.extend(batch[:max_sessions - len(sessions)])
                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to retrieve SSM session history: {exc}")
            _log.error(event("aws_ir_forensics", "capture_ssm_session_history.error", target=result.target, error=str(exc)))

        result.details["sessions"] = sessions
        result.details["statistics"] = {"total_sessions": len(sessions)}
        _log.info(event("aws_ir_forensics", "capture_ssm_session_history.complete", target=result.target, total=len(sessions)))
        return result

    # --------------------
    # CloudTrail integrity
    # --------------------

    def get_cloudtrail_status(
        self,
        *,
        include_shadow_trails: bool = False,
    ) -> OperationResult:
        """
        Retrieve the status and configuration of all CloudTrail trails.

        Checks whether each trail is actively logging and returns event selector
        info to verify management and/or data events are being captured.

        Args:
            include_shadow_trails: If True, include trails created in other regions
                                   that replicate logs to this region.

        Returns:
            OperationResult with details["trails"] = list of trail status dicts.
        """
        result = OperationResult(
            operation="get_cloudtrail_status",
            target="cloudtrail",
            success=True,
        )

        ct = self._services.cloudtrail

        try:
            trails_resp = ct.describe_trails(includeShadowTrails=include_shadow_trails)
            trail_list = trails_resp.get("trailList", [])

            trail_statuses: List[Dict[str, Any]] = []
            for trail in trail_list:
                trail_name = trail.get("TrailARN") or trail.get("Name")
                status: Dict[str, Any] = {
                    "name": trail.get("Name"),
                    "arn": trail.get("TrailARN"),
                    "home_region": trail.get("HomeRegion"),
                    "is_multi_region": trail.get("IsMultiRegionTrail"),
                    "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                    "s3_bucket": trail.get("S3BucketName"),
                    "cloudwatch_logs_group": trail.get("CloudWatchLogsLogGroupArn"),
                }

                try:
                    trail_status = ct.get_trail_status(Name=trail_name)
                    status["is_logging"] = trail_status.get("IsLogging")
                    status["latest_delivery_time"] = (
                        trail_status["LatestDeliveryTime"].isoformat()
                        if trail_status.get("LatestDeliveryTime") else None
                    )
                    status["latest_delivery_error"] = trail_status.get("LatestDeliveryError")
                except botocore.exceptions.ClientError as exc:
                    status["status_error"] = str(exc)

                try:
                    sel_resp = ct.get_event_selectors(TrailName=trail_name)
                    status["event_selectors"] = sel_resp.get("EventSelectors", [])
                    status["advanced_event_selectors"] = sel_resp.get("AdvancedEventSelectors", [])
                except botocore.exceptions.ClientError as exc:
                    status["event_selectors_error"] = str(exc)

                trail_statuses.append(status)

            result.details["trails"] = trail_statuses
            result.details["statistics"] = {
                "total_trails": len(trail_statuses),
                "active_trails": sum(1 for t in trail_statuses if t.get("is_logging")),
            }
            _log.info(event("aws_ir_forensics", "get_cloudtrail_status.complete", trails=len(trail_statuses)))

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to describe CloudTrail trails: {exc}")
            _log.error(event("aws_ir_forensics", "get_cloudtrail_status.fatal", error=str(exc)))

        return result

    # --------------------
    # IAM User detail
    # --------------------

    def get_iam_user_detail(self, user_name: str) -> OperationResult:
        """
        Capture a comprehensive snapshot of an IAM user.

        Collects: user metadata, MFA devices, access keys (status + age),
        and group memberships. Useful for scoping impact before containment.
        """
        result = OperationResult(
            operation="get_iam_user_detail",
            target=f"user={user_name}",
            success=True,
        )

        iam = self._services.iam

        try:
            user_resp = iam.get_user(UserName=user_name)
            user = user_resp.get("User", {})
            result.details["user"] = {
                "user_name": user.get("UserName"),
                "user_id": user.get("UserId"),
                "arn": user.get("Arn"),
                "create_date": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
                "password_last_used": user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
                "tags": user.get("Tags", []),
            }
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to get user: {exc}")
            return result

        try:
            mfa_resp = iam.list_mfa_devices(UserName=user_name)
            result.details["mfa_devices"] = [
                {
                    "serial": d.get("SerialNumber"),
                    "enable_date": d.get("EnableDate").isoformat() if d.get("EnableDate") else None,
                }
                for d in mfa_resp.get("MFADevices", [])
            ]
        except botocore.exceptions.ClientError as exc:
            result.details["mfa_error"] = str(exc)

        try:
            keys_resp = iam.list_access_keys(UserName=user_name)
            result.details["access_keys"] = [
                {
                    "access_key_id": k.get("AccessKeyId"),
                    "status": k.get("Status"),
                    "create_date": k.get("CreateDate").isoformat() if k.get("CreateDate") else None,
                }
                for k in keys_resp.get("AccessKeyMetadata", [])
            ]
        except botocore.exceptions.ClientError as exc:
            result.details["access_keys_error"] = str(exc)

        try:
            groups_resp = iam.list_groups_for_user(UserName=user_name)
            result.details["groups"] = [g.get("GroupName") for g in groups_resp.get("Groups", [])]
        except botocore.exceptions.ClientError as exc:
            result.details["groups_error"] = str(exc)

        _log.info(event("aws_ir_forensics", "get_iam_user_detail.success", target=result.target))
        return result

    # --------------------
    # S3: Bucket policy + ACL
    # --------------------

    def get_s3_bucket_policy(self, bucket_name: str) -> OperationResult:
        """
        Capture the bucket policy, ACL, and public access block configuration.

        Useful for preserving the state of an exposed bucket before remediation.
        """
        result = OperationResult(
            operation="get_s3_bucket_policy",
            target=f"bucket={bucket_name}",
            success=True,
        )

        s3 = self._services.s3

        try:
            try:
                policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
                result.details["policy"] = policy_resp.get("Policy")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "NoSuchBucketPolicy":
                    result.details["policy"] = None
                else:
                    result.details["policy_error"] = str(exc)

            try:
                acl_resp = s3.get_bucket_acl(Bucket=bucket_name)
                result.details["acl"] = {
                    "owner": acl_resp.get("Owner"),
                    "grants": acl_resp.get("Grants", []),
                }
            except botocore.exceptions.ClientError as exc:
                result.details["acl_error"] = str(exc)

            try:
                pab_resp = s3.get_public_access_block(Bucket=bucket_name)
                result.details["public_access_block"] = pab_resp.get("PublicAccessBlockConfiguration")
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    result.details["public_access_block"] = None
                else:
                    result.details["public_access_block_error"] = str(exc)

            _log.info(event("aws_ir_forensics", "get_s3_bucket_policy.success", target=result.target))

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to inspect bucket {bucket_name}: {exc}")
            _log.error(event("aws_ir_forensics", "get_s3_bucket_policy.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # EC2: User data
    # --------------------

    def get_ec2_user_data(self, instance_id: str) -> OperationResult:
        """
        Capture the EC2 instance user-data script.

        User data is a common attacker persistence mechanism (e.g., backdoor
        added to cloud-init scripts). The raw base64-encoded value and a decoded
        UTF-8 version are both returned.
        """
        import base64

        result = OperationResult(
            operation="get_ec2_user_data",
            target=f"instance={instance_id}",
            success=True,
        )

        try:
            resp = self._services.ec2.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="userData",
            )
            user_data = resp.get("UserData", {}).get("Value")
            result.details["user_data_base64"] = user_data

            if user_data:
                try:
                    decoded = base64.b64decode(user_data).decode("utf-8", errors="replace")
                    result.details["user_data_decoded"] = decoded
                except Exception:
                    result.details["user_data_decoded"] = None
            else:
                result.details["user_data_decoded"] = None

            _log.info(event("aws_ir_forensics", "get_ec2_user_data.success", target=result.target))

        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.error(event("aws_ir_forensics", "get_ec2_user_data.error", target=result.target, error=str(exc)))

        return result

    # --------------------
    # IAM: Recently active roles
    # --------------------

    def list_recently_active_roles(
        self,
        *,
        hours: int = 24,
        max_roles: int = 200,
    ) -> OperationResult:
        """
        List IAM roles that have been used within the specified time window.

        Uses the RoleLastUsed field (available since 2018). Useful for scoping
        which roles were active during the incident window.

        Args:
            hours:     How many hours back to look.
            max_roles: Maximum roles to return.
        """
        from datetime import timedelta

        result = OperationResult(
            operation="list_recently_active_roles",
            target=f"iam,window={hours}h",
            success=True,
        )

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        active_roles: List[Dict[str, Any]] = []
        total_scanned = 0

        try:
            iam = self._services.iam
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    if total_scanned >= max_roles:
                        break

                    last_used = role.get("RoleLastUsed", {})
                    last_used_date = last_used.get("LastUsedDate")

                    if last_used_date and last_used_date >= cutoff:
                        active_roles.append({
                            "role_name": role.get("RoleName"),
                            "role_arn": role.get("Arn"),
                            "last_used_date": last_used_date.isoformat(),
                            "last_used_region": last_used.get("Region"),
                        })

                    total_scanned += 1

                if total_scanned >= max_roles:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list IAM roles: {exc}")
            _log.error(event("aws_ir_forensics", "list_recently_active_roles.error", error=str(exc)))

        result.details["roles"] = active_roles
        result.details["statistics"] = {
            "roles_scanned": total_scanned,
            "active_in_window": len(active_roles),
            "window_hours": hours,
        }
        _log.info(event("aws_ir_forensics", "list_recently_active_roles.complete",
                        scanned=total_scanned, active=len(active_roles)))
        return result

    # --------------------
    # RDS: Parameter group
    # --------------------

    def get_rds_parameter_group(
        self,
        group_name: str,
        *,
        max_params: int = 500,
    ) -> OperationResult:
        """
        Retrieve all parameters from an RDS DB parameter group.

        Captures the group configuration as evidence before any changes are made.
        Look for unexpected settings like log_bin, require_secure_transport=OFF,
        or general_log/slow_query_log being disabled.

        Args:
            group_name: Name of the DB parameter group.
            max_params: Maximum parameters to retrieve.
        """
        result = OperationResult(
            operation="get_rds_parameter_group",
            target=f"rds_pg={group_name}",
            success=True,
        )

        rds = self._services.rds
        params: List[Dict[str, Any]] = []

        try:
            paginator = rds.get_paginator("describe_db_parameters")
            for page in paginator.paginate(DBParameterGroupName=group_name):
                for param in page.get("Parameters", []):
                    if len(params) >= max_params:
                        break
                    params.append({
                        "name": param.get("ParameterName"),
                        "value": param.get("ParameterValue"),
                        "apply_type": param.get("ApplyType"),
                        "is_modifiable": param.get("IsModifiable"),
                        "source": param.get("Source"),
                    })
                if len(params) >= max_params:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to get RDS parameter group {group_name}: {exc}")
            _log.error(event("aws_ir_forensics", "get_rds_parameter_group.error", target=result.target, error=str(exc)))
            return result

        result.details["parameters"] = params
        result.details["group_name"] = group_name
        result.details["statistics"] = {"total_parameters": len(params)}
        _log.info(event("aws_ir_forensics", "get_rds_parameter_group.success",
                        target=result.target, total=len(params)))
        return result

    # --------------------
    # GuardDuty: Finding detail
    # --------------------

    def capture_guardduty_finding_detail(
        self,
        detector_id: str,
        *finding_ids: str,
    ) -> OperationResult:
        """
        Retrieve full GuardDuty finding objects, including network connections,
        process details, threat intelligence matches, and severity scores.

        Args:
            detector_id: GuardDuty detector ID.
            *finding_ids: One or more finding IDs to retrieve (max 50).
        """
        if not finding_ids:
            raise ValueError("At least one finding_id is required")

        result = OperationResult(
            operation="capture_guardduty_finding_detail",
            target=f"detector={detector_id},findings={len(finding_ids)}",
            success=True,
        )

        try:
            resp = self._services.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=list(finding_ids[:50]),
            )
            findings = resp.get("Findings", [])
            result.details["findings"] = findings
            result.details["statistics"] = {"total": len(findings)}
            _log.info(event("aws_ir_forensics", "capture_guardduty_finding_detail.success",
                            target=result.target, total=len(findings)))

        except botocore.exceptions.ClientError as exc:
            result.add_error(str(exc))
            _log.error(event("aws_ir_forensics", "capture_guardduty_finding_detail.error",
                             target=result.target, error=str(exc)))

        return result
