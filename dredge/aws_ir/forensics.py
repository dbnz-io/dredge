from __future__ import annotations

import gzip
import os
import re
import threading
from calendar import monthrange
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import botocore.exceptions

from .. import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)

# Sane bound on what counts as a "year" folder (vs. e.g. an account ID or
# other numeric-looking path segment) when walking a log bucket's hierarchy
# looking for dated .../YYYY/MM/DD/ folders.
_YEAR_RE = re.compile(r"^(19|20)\d{2}$")
_TWO_DIGIT_RE = re.compile(r"^\d{2}$")

# CloudTrail writes two things into a trail bucket: the actual event logs
# under a ``.../CloudTrail/<region>/...`` path and separate hash-chain digest
# files under ``.../CloudTrail-Digest/<region>/...``. The digests are only
# useful for log-integrity validation, not threat hunting, and in an org
# trail they roughly double the object count -- so downloads skip them by
# default.
_CLOUDTRAIL_DIGEST_SEGMENT = "CloudTrail-Digest"


def _is_cloudtrail_digest_key(key: str) -> bool:
    """True if any path segment of `key` is the CloudTrail digest folder."""
    return f"/{_CLOUDTRAIL_DIGEST_SEGMENT}/" in f"/{key}"


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

        except botocore.exceptions.ClientError as exc:  # pragma: no cover
            # Defensive only: every ClientError-raising call above (policy,
            # ACL, public-access-block) already has its own inner
            # try/except that catches ClientError and never re-raises, so
            # this outer handler has no reachable path under the current
            # function body. Kept as a safety net, not chased for coverage.
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
        from datetime import datetime, timedelta, timezone

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

    # --------------------
    # S3: Flat log download
    # --------------------

    @staticmethod
    def _list_common_prefixes(s3, bucket: str, prefix: str) -> List[str]:
        """One level of a Delimiter='/' listing: the "subfolders" directly
        under `prefix`, as full prefix strings (each ending in '/')."""
        prefixes: List[str] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                prefixes.append(cp["Prefix"])
        return prefixes

    def _discover_date_prefixes(
        self,
        s3,
        bucket: str,
        root_prefix: str,
        start_date: date,
        end_date: date,
        max_workers: int,
        exclude_cloudtrail_digest: bool = True,
    ) -> List[str]:
        """
        Walk the bucket's folder hierarchy under root_prefix looking for
        CloudTrail/Config-style dated folders (.../YYYY/MM/DD/) and return
        only the leaf prefixes whose date falls within [start_date, end_date].

        Every non-date folder (org-id/account-id/region/log-type, however
        many levels deep) is walked unconditionally -- there's no generic
        way to know where the tree bottoms out otherwise. Once a folder
        name matches a 4-digit year, pruning kicks in: only years in range
        are descended into, then only months in range for boundary years,
        then only days in range for boundary months. That keeps the number
        of S3 list calls proportional to (accounts x regions x log-types),
        not to years of accumulated log history -- each level of the walk
        is also fanned out across max_workers threads, since e.g. the
        account-id level alone can be hundreds of parallel listings wide in
        an AWS Organization.
        """
        # frontier entries: (prefix, date_state); date_state is None (not
        # yet inside a date path), ("year", y), or ("month", y, m).
        frontier: List[Tuple[str, Any]] = [(root_prefix, None)]
        leaves: List[str] = []

        while frontier:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                children_lists = list(pool.map(
                    lambda node: self._list_common_prefixes(s3, bucket, node[0]), frontier,
                ))

            next_frontier: List[Tuple[str, Any]] = []
            for (node_prefix, date_state), children in zip(frontier, children_lists):
                for child_prefix in children:
                    name = child_prefix[len(node_prefix):].rstrip("/")

                    if date_state is None:
                        if exclude_cloudtrail_digest and name == _CLOUDTRAIL_DIGEST_SEGMENT:
                            # Prune the whole digest subtree -- never even list
                            # its dated folders.
                            continue
                        if _YEAR_RE.match(name):
                            if start_date.year <= int(name) <= end_date.year:
                                next_frontier.append((child_prefix, ("year", int(name))))
                            # else: a year folder outside the window -- prune.
                        else:
                            next_frontier.append((child_prefix, None))
                        continue

                    if date_state[0] == "year":
                        _, y = date_state
                        if not (_TWO_DIGIT_RE.match(name) and 1 <= int(name) <= 12):
                            continue
                        m = int(name)
                        month_start = date(y, m, 1)
                        month_end = date(y, m, monthrange(y, m)[1])
                        if month_end < start_date or month_start > end_date:
                            continue
                        next_frontier.append((child_prefix, ("month", y, m)))
                        continue

                    # date_state[0] == "month"
                    _, y, m = date_state
                    if not (_TWO_DIGIT_RE.match(name) and 1 <= int(name) <= 31):
                        continue
                    try:
                        day_date = date(y, m, int(name))
                    except ValueError:
                        continue
                    if start_date <= day_date <= end_date:
                        leaves.append(child_prefix)

            frontier = next_frontier

        return sorted(leaves)

    def download_s3_logs(
        self,
        bucket: str,
        *,
        prefix: Optional[str] = None,
        destination: str,
        suffixes: Sequence[str] = (".json", ".json.gz"),
        decompress_gzip: bool = True,
        max_objects: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        days_ago: Optional[int] = None,
        max_workers: int = 8,
        exclude_cloudtrail_digest: bool = True,
    ) -> OperationResult:
        """
        Download log objects from an S3 bucket/prefix into a single flat local
        directory, instead of mirroring the bucket's key structure the way
        `aws s3 cp --recursive` does.

        Each file is named after its full S3 key with "/" replaced by "_", so
        objects from different "folders" (e.g. different regions/dates in a
        CloudTrail bucket) never collide. ".gz" objects are gunzipped by
        default so the local files are plain JSON.

        Date filtering (start_time/end_time/days_ago):
            For an organization/Control Tower CloudTrail bucket, keys are
            laid out as
            ``[<prefix>/][o-xxxxxxxxxx/]<account-id>/CloudTrail/<region>/<year>/<month>/<day>/*``
            -- listing the whole bucket (or running one download per region)
            to pull the last couple of days across every account doesn't
            scale. Passing start_time (or days_ago, a shortcut for "N days
            ago until now") switches to a two-phase approach instead:
              1. Walk the folder hierarchy under `prefix` with Delimiter="/"
                 (cheap -- no object bodies) to discover every account/
                 region/log-type folder, pruning branches by year/month/day
                 as soon as a dated folder is reached, so years of unrelated
                 history are never listed no matter how many accounts or
                 regions exist.
              2. Only the day folders inside [start_time, end_time] get a
                 real object listing + download.
            end_time defaults to now when start_time/days_ago is given.
            `prefix` should point at or above the account-id level for this
            to work -- if it already points inside a dated folder, use the
            plain (non-date-filtered) form instead.

        Args:
            bucket: S3 bucket name.
            prefix: Only download keys under this prefix.
            destination: Local directory to write files into (created if missing).
            suffixes: Only download keys ending in one of these (case-insensitive).
                Pass an empty sequence to download every object under the prefix.
            decompress_gzip: Gunzip ".gz" objects and drop the ".gz" suffix locally.
            max_objects: Stop after downloading this many objects.
            start_time: Only consider log objects dated on/after this day
                (see "Date filtering" above). Mutually exclusive with days_ago.
            end_time: Only consider log objects dated on/before this day.
                Defaults to now when start_time/days_ago is given.
            days_ago: Shortcut for start_time = now - timedelta(days=days_ago).
            max_workers: Concurrency for both the folder-discovery phase (when
                date filtering is active) and the object downloads. Object
                GETs are the bottleneck for a large trail bucket, so they run
                across this many threads instead of one-at-a-time.
            exclude_cloudtrail_digest: Skip CloudTrail digest objects (keys
                under a ``CloudTrail-Digest/`` folder). On by default -- the
                digests are integrity-validation artifacts, not event logs,
                and dropping them roughly halves the objects pulled from an
                org trail bucket. When date filtering is active the digest
                subtree is also pruned during discovery, so its dated folders
                are never even listed.

        Raises:
            ValueError: Both start_time and days_ago are given.

        Returns:
            OperationResult with:
              - details["downloaded"]: count of files written
              - details["local_files"]: list of local file paths written
              - details["skipped"]: count of keys that didn't match `suffixes`
              - details["digest_skipped"]: count of CloudTrail digest keys
                skipped (only when exclude_cloudtrail_digest is set)
              - details["failed"]: {key: error} for objects that failed to download
              - details["scanned_prefixes"]: leaf date prefixes that were
                listed (date-filtered calls only)
        """
        if start_time is not None and days_ago is not None:
            raise ValueError("start_time and days_ago are mutually exclusive")

        if days_ago is not None:
            start_time = datetime.now(timezone.utc) - timedelta(days=days_ago)

        date_filtered = start_time is not None
        if date_filtered and end_time is None:
            end_time = datetime.now(timezone.utc)

        target = f"bucket={bucket}" + (f",prefix={prefix}" if prefix else "")
        if date_filtered:
            target += f",start_time={start_time.isoformat()},end_time={end_time.isoformat()}"
        result = OperationResult(operation="download_s3_logs", target=target, success=True)

        os.makedirs(destination, exist_ok=True)

        s3 = self._services.s3
        lower_suffixes = tuple(s.lower() for s in suffixes)

        local_files: List[str] = []
        failed: Dict[str, str] = {}
        seen_names: Dict[str, int] = {}
        skipped = 0
        digest_skipped = 0
        # Only download bookkeeping (local_files/failed/seen_names) is touched
        # from worker threads; listing/counter updates stay on the main thread.
        state_lock = threading.Lock()

        def _dedupe_locked(name: str) -> str:
            """Reserve a unique local filename. Caller must hold state_lock."""
            if name not in seen_names:
                seen_names[name] = 0
                return name
            seen_names[name] += 1
            if "." in name:
                stem, ext = name.rsplit(".", 1)
                return f"{stem}__{seen_names[name]}.{ext}"
            return f"{name}__{seen_names[name]}"

        def _download_one(key: str) -> None:
            """Fetch, optionally gunzip, and write one object. Records its own
            failures; safe to run concurrently across the download pool."""
            try:
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            except botocore.exceptions.ClientError as exc:
                with state_lock:
                    failed[key] = str(exc)
                _log.warning(event("aws_ir_forensics", "download_s3_logs.object_error",
                                    target=result.target, key=key, error=str(exc)))
                return

            local_name = key.replace("/", "_")
            if decompress_gzip and local_name.lower().endswith(".gz"):
                try:
                    body = gzip.decompress(body)
                    local_name = local_name[: -len(".gz")]
                except OSError as exc:
                    with state_lock:
                        failed[key] = f"gzip decompress failed: {exc}"
                    return

            with state_lock:
                local_name = _dedupe_locked(local_name)
            local_path = os.path.join(destination, local_name)
            with open(local_path, "wb") as fh:
                fh.write(body)
            with state_lock:
                local_files.append(local_path)

        # Number of download tasks submitted so far -- bounds max_objects.
        # Listing is serial on the main thread, so a plain int is safe here.
        submitted = [0]

        def _submit_matching_under_prefix(executor, list_prefix: Optional[str]):
            """List one prefix (Contents, no delimiter) and submit a download
            task for every matching object. Returns (futures, reached_limit)."""
            nonlocal skipped, digest_skipped
            list_kwargs: Dict[str, Any] = {"Bucket": bucket}
            if list_prefix:
                list_kwargs["Prefix"] = list_prefix

            futures = []
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(**list_kwargs):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith("/"):
                        continue
                    if exclude_cloudtrail_digest and _is_cloudtrail_digest_key(key):
                        digest_skipped += 1
                        continue
                    if lower_suffixes and not key.lower().endswith(lower_suffixes):
                        skipped += 1
                        continue
                    if max_objects is not None and submitted[0] >= max_objects:
                        return futures, True

                    futures.append(executor.submit(_download_one, key))
                    submitted[0] += 1
            return futures, (max_objects is not None and submitted[0] >= max_objects)

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                if date_filtered:
                    root_prefix = prefix or ""
                    if root_prefix and not root_prefix.endswith("/"):
                        root_prefix += "/"
                    leaf_prefixes = self._discover_date_prefixes(
                        s3, bucket, root_prefix, start_time.date(), end_time.date(),
                        max_workers, exclude_cloudtrail_digest=exclude_cloudtrail_digest,
                    )
                    result.details["scanned_prefixes"] = leaf_prefixes
                    for leaf_prefix in leaf_prefixes:
                        _, reached_limit = _submit_matching_under_prefix(executor, leaf_prefix)
                        if reached_limit:
                            break
                else:
                    _submit_matching_under_prefix(executor, prefix)
                # Leaving the `with` block waits for every submitted download.
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list objects in s3://{bucket}: {exc}")
            _log.error(event("aws_ir_forensics", "download_s3_logs.list_error",
                             target=result.target, error=str(exc)))
            return result

        result.details["destination"] = destination
        result.details["downloaded"] = len(local_files)
        result.details["local_files"] = local_files
        result.details["skipped"] = skipped
        if exclude_cloudtrail_digest:
            result.details["digest_skipped"] = digest_skipped
        if failed:
            result.details["failed"] = failed
            result.add_error(f"Failed to download {len(failed)} object(s)")

        _log.info(event("aws_ir_forensics", "download_s3_logs.complete", target=result.target,
                        downloaded=len(local_files), skipped=skipped,
                        digest_skipped=digest_skipped, failed=len(failed)))
        return result
