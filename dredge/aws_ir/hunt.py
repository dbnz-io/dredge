from __future__ import annotations

import json
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import botocore.exceptions

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .models import OperationResult

_log = get_logger(__name__)

_THROTTLE_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
}


class AwsIRHunt:
    """
    Hunt / search utilities over CloudTrail LookupEvents.

    Example:
        dredge.aws_ir.hunt.lookup_events(
            user_name="alice",
            event_name="ConsoleLogin",
            max_events=100,
        )
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def lookup_events(
        self,
        *,
        user_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        event_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
    ) -> OperationResult:
        """
        Search CloudTrail LookupEvents by simple filters.

        CloudTrail LookupEvents only supports ONE LookupAttribute per call.
        We choose the most specific one (access_key_id > user_name > event_name)
        and then apply additional filters (e.g., source_ip) client-side.

        NOTE: source_ip is always applied client-side — CloudTrail does not
        support it as a server-side LookupAttribute. It MUST be combined with
        at least one of user_name, access_key_id, or event_name, otherwise
        the call will scan all events in the time range, which is expensive
        and may silently miss matching records if total events exceed max_events.

        Args:
            user_name: Filter by CloudTrail Username.
            access_key_id: Filter by AccessKeyId.
            event_name: Filter by EventName (e.g., "ConsoleLogin").
            source_ip: Filter by sourceIPAddress (client-side only).
            start_time: Earliest event time (UTC). Defaults to now - 24h.
            end_time: Latest event time (UTC). Defaults to now.
            max_events: Maximum number of events to return.
            page_size: CloudTrail MaxResults per request (<= 50).
            throttle_max_retries: Max retries on throttling.
            throttle_base_delay: Base seconds for exponential backoff.

        Raises:
            ValueError: If source_ip is the only filter provided. CloudTrail
                cannot filter by IP server-side; combining it with a sole
                source_ip filter would scan all events and silently truncate
                results at max_events.

        Returns:
            OperationResult with:
              - details["events"]: list of normalized event dicts
              - details["statistics"]: counts and filter info
        """
        if source_ip and not any([user_name, access_key_id, event_name]):
            raise ValueError(
                "source_ip cannot be the sole filter for CloudTrail lookup_events. "
                "CloudTrail does not support IP-based server-side filtering; using "
                "source_ip alone would scan all events in the time range and silently "
                "truncate results at max_events. Provide at least one of: "
                "user_name, access_key_id, event_name."
            )

        now = datetime.now(timezone.utc)

        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="lookup_events",
            target=self._build_target_string(
                user_name=user_name,
                access_key_id=access_key_id,
                event_name=event_name,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        _log.debug(event("aws_ir_hunt", "lookup_events.start", target=result.target, max_events=max_events))

        cloudtrail = self._services.cloudtrail

        lookup_attributes = self._build_lookup_attributes(
            user_name=user_name,
            access_key_id=access_key_id,
            event_name=event_name,
        )

        # Pre-compute whether we need a client-side event_name filter.
        # This is needed when a different attribute (access_key_id or user_name) was
        # chosen as the primary LookupAttribute, so event_name wasn't filtered server-side.
        apply_event_name_filter: bool = (
            event_name is not None
            and bool(lookup_attributes)
            and lookup_attributes[0]["AttributeKey"] != "EventName"
        )

        events: List[Dict[str, Any]] = []
        total_api_calls = 0
        next_token: Optional[str] = None

        # Main pagination loop
        while True:
            if len(events) >= max_events:
                break

            params: Dict[str, Any] = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": min(page_size, 50),
            }
            if lookup_attributes:
                params["LookupAttributes"] = lookup_attributes
            if next_token:
                params["NextToken"] = next_token

            try:
                resp = self._call_with_backoff(
                    cloudtrail.lookup_events,
                    params=params,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
                total_api_calls += 1
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
                result.add_error(f"Failed to lookup CloudTrail events: {exc}")
                _log.error(event("aws_ir_hunt", "lookup_events.api_error", target=result.target, error=str(exc)))
                break

            raw_events = resp.get("Events", [])
            for raw_event in raw_events:
                if len(events) >= max_events:
                    break

                # Fast path: EventName is a top-level field — filter before any JSON work.
                if apply_event_name_filter and raw_event.get("EventName") != event_name:
                    continue

                # source_ip is only available inside the CloudTrailEvent JSON blob.
                # Parse it once here; pass the result to _normalize_event to avoid re-parsing.
                ct_dict: Optional[Dict[str, Any]] = None
                if source_ip:
                    raw_ct = raw_event.get("CloudTrailEvent")
                    if raw_ct:
                        try:
                            ct_dict = json.loads(raw_ct)
                        except ValueError:
                            ct_dict = {}
                    event_ip = raw_event.get("SourceIPAddress", (ct_dict or {}).get("sourceIPAddress"))
                    if event_ip != source_ip:
                        continue

                events.append(self._normalize_event(raw_event, ct=ct_dict))

            next_token = resp.get("NextToken")
            if not next_token:
                break

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "api_calls": total_api_calls,
            "lookup_attributes": lookup_attributes,
            "time_range": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
        }

        _log.info(event("aws_ir_hunt", "lookup_events.complete", target=result.target, total_events=len(events), api_calls=total_api_calls))

        return result

    # ----------------- internal helpers -----------------

    @staticmethod
    def _build_target_string(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
        source_ip: Optional[str],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        bits = []
        if user_name:
            bits.append(f"user={user_name}")
        if access_key_id:
            bits.append(f"access_key_id={access_key_id}")
        if event_name:
            bits.append(f"event_name={event_name}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        bits.append(f"time={start_time.isoformat()}..{end_time.isoformat()}")
        return ",".join(bits)

    @staticmethod
    def _build_lookup_attributes(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
    ) -> List[Dict[str, str]]:
        """
        Choose the primary CloudTrail LookupAttribute.

        Priority:
            1) AccessKeyId
            2) Username
            3) EventName
        """
        if access_key_id:
            return [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}]
        if user_name:
            return [{"AttributeKey": "Username", "AttributeValue": user_name}]
        if event_name:
            return [{"AttributeKey": "EventName", "AttributeValue": event_name}]
        return []

    @staticmethod
    def _normalize_event(
        raw: Dict[str, Any],
        *,
        ct: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize a CloudTrail event from LookupEvents into a simple dict.

        ct: pre-parsed CloudTrailEvent JSON dict, if already parsed by the
            caller (e.g. during source_ip filtering) to avoid double-parsing.
        """
        if ct is None:
            raw_ct = raw.get("CloudTrailEvent")
            if raw_ct:
                try:
                    ct = json.loads(raw_ct)
                except ValueError:
                    ct = {}
        ct = ct or {}

        # SourceIPAddress at top-level takes precedence over the embedded JSON value.
        source_ip = raw.get("SourceIPAddress", ct.get("sourceIPAddress"))

        return {
            "event_id": raw.get("EventId"),
            "event_name": raw.get("EventName"),
            "event_time": (
                raw["EventTime"].isoformat() if raw.get("EventTime") else None
            ),
            "username": raw.get("Username"),
            "event_source": raw.get("EventSource"),
            "aws_region": raw.get("AwsRegion"),
            "read_only": raw.get("ReadOnly"),
            "access_key_id": raw.get("AccessKeyId"),
            "source_ip_address": source_ip,
            "resources": raw.get("Resources", []),
            "raw_cloudtrail_event": raw.get("CloudTrailEvent"),
        }

    @staticmethod
    def _call_with_backoff(
        func,
        *,
        params: Dict[str, Any],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> Dict[str, Any]:
        """
        Call an AWS API with basic exponential backoff on throttling.
        """
        attempt = 0
        while True:
            try:
                return func(**params)
            except botocore.exceptions.ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_ERROR_CODES or attempt >= throttle_max_retries:
                    raise

                delay = throttle_base_delay * (2**attempt)
                _log.warning(event("aws_ir_hunt", "cloudtrail_throttle", code=code, attempt=attempt, delay=delay))
                time.sleep(delay)
                attempt += 1

    # =====================
    # GuardDuty
    # =====================

    def list_guardduty_findings(
        self,
        detector_id: str,
        *,
        severity_min: float = 0.0,
        max_findings: int = 100,
        finding_types: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> OperationResult:
        """
        List and retrieve GuardDuty findings for a detector.

        Args:
            detector_id:   GuardDuty detector ID.
            severity_min:  Minimum severity (0.0–8.9). 4.0 = Medium, 7.0 = High.
            max_findings:  Maximum number of findings to return.
            finding_types: Optional list of finding type strings to filter by.
            start_time:    Only include findings updated at or after this time.
            end_time:      Only include findings updated before or at this time.

        Returns:
            OperationResult with details["findings"] = list of normalized finding dicts.
        """
        result = OperationResult(
            operation="list_guardduty_findings",
            target=f"detector={detector_id}",
            success=True,
        )

        gd = self._services.guardduty

        # Build FindingCriteria
        criterion: Dict[str, Any] = {}
        if severity_min > 0.0:
            criterion["severity"] = {"Gte": severity_min}
        if finding_types:
            criterion["type"] = {"Eq": finding_types}
        if start_time:
            criterion["updatedAt"] = {"Gte": start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}
        if end_time:
            criterion.setdefault("updatedAt", {})["Lte"] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Phase 1: collect finding IDs (paginated, max 50 per call)
        finding_ids: List[str] = []
        next_token: Optional[str] = None

        try:
            while len(finding_ids) < max_findings:
                params: Dict[str, Any] = {
                    "DetectorId": detector_id,
                    "MaxResults": min(50, max_findings - len(finding_ids)),
                }
                if criterion:
                    params["FindingCriteria"] = {"Criterion": criterion}
                if next_token:
                    params["NextToken"] = next_token

                resp = gd.list_findings(**params)
                batch = resp.get("FindingIds", [])
                remaining = max_findings - len(finding_ids)
                finding_ids.extend(batch[:remaining])

                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list GuardDuty findings: {exc}")
            _log.error(event("aws_ir_hunt", "list_guardduty_findings.list_error", target=result.target, error=str(exc)))
            return result

        # Phase 2: fetch full finding details in batches of 50
        findings: List[Dict[str, Any]] = []
        for i in range(0, len(finding_ids), 50):
            batch_ids = finding_ids[i:i + 50]
            try:
                resp = gd.get_findings(DetectorId=detector_id, FindingIds=batch_ids)
                findings.extend(resp.get("Findings", []))
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to get findings batch {i}–{i+50}: {exc}")
                _log.warning(event("aws_ir_hunt", "list_guardduty_findings.get_error", batch=i, error=str(exc)))

        result.details["findings"] = [self._normalize_guardduty_finding(f) for f in findings]
        result.details["statistics"] = {
            "total_findings": len(findings),
            "detector_id": detector_id,
            "severity_min": severity_min,
        }
        _log.info(event("aws_ir_hunt", "list_guardduty_findings.complete", target=result.target, total=len(findings)))
        return result

    @staticmethod
    def _normalize_guardduty_finding(f: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "finding_id": f.get("Id"),
            "type": f.get("Type"),
            "severity": f.get("Severity"),
            "title": f.get("Title"),
            "description": f.get("Description"),
            "region": f.get("Region"),
            "account_id": f.get("AccountId"),
            "created_at": f.get("CreatedAt"),
            "updated_at": f.get("UpdatedAt"),
            "resource_type": f.get("Resource", {}).get("ResourceType"),
            "service_name": f.get("Service", {}).get("ServiceName"),
            "raw": f,
        }

    # =====================
    # CloudWatch Logs Insights
    # =====================

    def hunt_cloudwatch_logs(
        self,
        log_group: str,
        query: str,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_results: int = 1000,
        poll_interval: float = 1.0,
        max_wait_seconds: float = 60.0,
    ) -> OperationResult:
        """
        Run a CloudWatch Logs Insights query and return the results.

        Args:
            log_group:        Log group name (e.g. /aws/lambda/my-function).
            query:            Logs Insights query string.
            start_time:       Query window start (UTC). Defaults to now - 24h.
            end_time:         Query window end (UTC). Defaults to now.
            max_results:      Maximum rows to return (API-level cap).
            poll_interval:    Seconds between status polls.
            max_wait_seconds: Maximum total seconds to wait for query completion.

        Returns:
            OperationResult with details["results"] = list of flat row dicts.
        """
        now = datetime.now(timezone.utc)
        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="hunt_cloudwatch_logs",
            target=f"log_group={log_group}",
            success=True,
        )

        logs = self._services.logs

        # Start query
        try:
            resp = logs.start_query(
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query,
                limit=max_results,
            )
            query_id = resp["queryId"]
        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to start CloudWatch Logs Insights query: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_cloudwatch_logs.start_error", target=result.target, error=str(exc)))
            return result

        # Poll for completion
        elapsed = 0.0
        status = "Running"
        raw_results: List[Any] = []

        _TERMINAL_STATUSES = {"Complete", "Failed", "Cancelled", "Timeout"}

        while elapsed < max_wait_seconds:
            time.sleep(poll_interval)
            elapsed += poll_interval

            try:
                resp = logs.get_query_results(queryId=query_id)
            except botocore.exceptions.ClientError as exc:
                result.add_error(f"Failed to get query results: {exc}")
                _log.error(event("aws_ir_hunt", "hunt_cloudwatch_logs.poll_error", query_id=query_id, error=str(exc)))
                return result

            status = resp.get("status", "Unknown")

            if status == "Complete":
                raw_results = resp.get("results", [])
                break

            if status in _TERMINAL_STATUSES:
                result.add_error(f"CloudWatch Logs Insights query ended with status: {status}")
                _log.warning(event("aws_ir_hunt", "hunt_cloudwatch_logs.terminal_status", query_id=query_id, status=status))
                return result

        if status not in _TERMINAL_STATUSES and status != "Complete":
            result.add_error(f"Query timed out after {max_wait_seconds}s (status: {status})")
            _log.warning(event("aws_ir_hunt", "hunt_cloudwatch_logs.timeout", query_id=query_id, elapsed=elapsed))
            try:
                logs.stop_query(queryId=query_id)
            except botocore.exceptions.ClientError:
                pass
            return result

        # Normalize: each row is List[{"field": str, "value": str}]
        normalized = [
            {item["field"]: item["value"] for item in row}
            for row in raw_results
        ]

        result.details["results"] = normalized
        result.details["statistics"] = {
            "query_id": query_id,
            "status": status,
            "total_results": len(normalized),
            "log_group": log_group,
        }
        _log.info(event("aws_ir_hunt", "hunt_cloudwatch_logs.complete", target=result.target, total=len(normalized)))
        return result

    # =====================
    # Security Hub
    # =====================

    def hunt_security_hub_findings(
        self,
        *,
        severity_labels: Optional[List[str]] = None,
        workflow_status: Optional[List[str]] = None,
        product_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_findings: int = 100,
    ) -> OperationResult:
        """
        Query Security Hub findings with optional filters.

        Args:
            severity_labels: e.g. ["HIGH", "CRITICAL"]
            workflow_status: e.g. ["NEW", "NOTIFIED"]
            product_name:    e.g. "GuardDuty"
            start_time:      Filter by UpdatedAt >= start_time.
            end_time:        Filter by UpdatedAt <= end_time.
            max_findings:    Maximum findings to return.

        Returns:
            OperationResult with details["findings"] = list of finding dicts.
        """
        result = OperationResult(
            operation="hunt_security_hub_findings",
            target="security_hub",
            success=True,
        )

        filters: Dict[str, Any] = {}
        if severity_labels:
            filters["SeverityLabel"] = [{"Value": lbl, "Comparison": "EQUALS"} for lbl in severity_labels]
        if workflow_status:
            filters["WorkflowStatus"] = [{"Value": s, "Comparison": "EQUALS"} for s in workflow_status]
        if product_name:
            filters["ProductName"] = [{"Value": product_name, "Comparison": "EQUALS"}]
        updated_at: Dict[str, str] = {}
        if start_time:
            updated_at["Start"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        if end_time:
            updated_at["End"] = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        if updated_at:
            filters["UpdatedAt"] = [updated_at]

        hub = self._services.securityhub
        findings: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(findings) < max_findings:
                params: Dict[str, Any] = {
                    "Filters": filters,
                    "MaxResults": min(100, max_findings - len(findings)),
                }
                if next_token:
                    params["NextToken"] = next_token

                resp = hub.get_findings(**params)
                batch = resp.get("Findings", [])
                findings.extend(batch)
                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to query Security Hub: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_security_hub_findings.error", error=str(exc)))

        result.details["findings"] = findings
        result.details["statistics"] = {"total_findings": len(findings)}
        _log.info(event("aws_ir_hunt", "hunt_security_hub_findings.complete", total=len(findings)))
        return result

    # =====================
    # IAM Access Analyzer
    # =====================

    def hunt_access_analyzer_findings(
        self,
        analyzer_arn: str,
        *,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
        max_findings: int = 100,
    ) -> OperationResult:
        """
        List IAM Access Analyzer findings for a given analyzer.

        Args:
            analyzer_arn:  ARN of the Access Analyzer.
            status:        Filter by finding status: "ACTIVE", "ARCHIVED", "RESOLVED".
            resource_type: Filter by resource type (e.g. "AWS::S3::Bucket").
            max_findings:  Maximum findings to return.

        Returns:
            OperationResult with details["findings"] = list of finding dicts.
        """
        result = OperationResult(
            operation="hunt_access_analyzer_findings",
            target=f"analyzer={analyzer_arn}",
            success=True,
        )

        filter_criteria: Dict[str, Any] = {}
        if status:
            filter_criteria["status"] = {"eq": [status]}
        if resource_type:
            filter_criteria["resourceType"] = {"eq": [resource_type]}

        aa = self._services.accessanalyzer
        findings: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(findings) < max_findings:
                params: Dict[str, Any] = {
                    "analyzerArn": analyzer_arn,
                    "maxResults": min(100, max_findings - len(findings)),
                }
                if filter_criteria:
                    params["filter"] = filter_criteria
                if next_token:
                    params["nextToken"] = next_token

                resp = aa.list_findings(**params)
                batch = resp.get("findings", [])
                findings.extend(batch)
                next_token = resp.get("nextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list Access Analyzer findings: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_access_analyzer_findings.error", error=str(exc)))

        result.details["findings"] = findings
        result.details["statistics"] = {"total_findings": len(findings)}
        _log.info(event("aws_ir_hunt", "hunt_access_analyzer_findings.complete", total=len(findings)))
        return result

    # =====================
    # AWS Config
    # =====================

    def hunt_config_resource_history(
        self,
        resource_type: str,
        resource_id: str,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_items: int = 100,
    ) -> OperationResult:
        """
        Retrieve configuration history for a specific AWS resource via AWS Config.

        Args:
            resource_type: e.g. "AWS::EC2::Instance", "AWS::IAM::User"
            resource_id:   The resource ID (not ARN).
            start_time:    Only return configurations recorded after this time.
            end_time:      Only return configurations recorded before this time.
            max_items:     Maximum configuration items to return.

        Returns:
            OperationResult with details["configuration_items"] = list of config snapshots.
        """
        result = OperationResult(
            operation="hunt_config_resource_history",
            target=f"resource_type={resource_type},resource_id={resource_id}",
            success=True,
        )

        config = self._services.awsconfig
        items: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        try:
            while len(items) < max_items:
                params: Dict[str, Any] = {
                    "resourceType": resource_type,
                    "resourceId": resource_id,
                    "limit": min(100, max_items - len(items)),
                }
                if start_time:
                    params["earlierTime"] = start_time
                if end_time:
                    params["laterTime"] = end_time
                if next_token:
                    params["nextToken"] = next_token

                resp = config.get_resource_config_history(**params)
                batch = resp.get("configurationItems", [])
                items.extend(batch)
                next_token = resp.get("nextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to get resource config history: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_config_resource_history.error", error=str(exc)))

        result.details["configuration_items"] = items
        result.details["statistics"] = {
            "total_items": len(items),
            "resource_type": resource_type,
            "resource_id": resource_id,
        }
        _log.info(event("aws_ir_hunt", "hunt_config_resource_history.complete", total=len(items)))
        return result

    # =====================
    # IAM Credential Report
    # =====================

    def get_iam_credential_report(
        self,
        *,
        max_wait_seconds: float = 30.0,
        poll_interval: float = 1.0,
    ) -> OperationResult:
        """
        Generate and retrieve the IAM credential report.

        The report contains one row per IAM user with columns for access key
        status, password last used, MFA active, etc.

        Args:
            max_wait_seconds: Maximum time to wait for report generation.
            poll_interval:    Seconds between status polls.

        Returns:
            OperationResult with details["users"] = list of per-user dicts
            parsed from the CSV report.
        """
        import csv
        import io

        result = OperationResult(
            operation="get_iam_credential_report",
            target="iam",
            success=True,
        )

        iam = self._services.iam
        elapsed = 0.0
        state = "STARTED"

        try:
            while elapsed <= max_wait_seconds:
                resp = iam.generate_credential_report()
                state = resp.get("State", "STARTED")
                if state == "COMPLETE":
                    break
                if elapsed < max_wait_seconds:
                    time.sleep(poll_interval)
                    elapsed += poll_interval
                else:
                    break

            if state != "COMPLETE":
                result.add_error(f"IAM credential report did not complete within {max_wait_seconds}s (state: {state})")
                return result

            report_resp = iam.get_credential_report()
            content = report_resp.get("Content", b"")
            if isinstance(content, (bytes, bytearray)):
                content = content.decode("utf-8")

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to generate IAM credential report: {exc}")
            _log.error(event("aws_ir_hunt", "get_iam_credential_report.error", error=str(exc)))
            return result

        users = list(csv.DictReader(io.StringIO(content)))
        result.details["users"] = users
        result.details["statistics"] = {"total_users": len(users)}
        _log.info(event("aws_ir_hunt", "get_iam_credential_report.complete", total=len(users)))
        return result

    # =====================
    # S3: Exposed buckets
    # =====================

    def hunt_exposed_s3_buckets(self) -> OperationResult:
        """
        List S3 buckets that may be publicly accessible.

        Checks each bucket's public access block configuration and flags any
        bucket where block public access is not fully enabled. Buckets with
        NoSuchPublicAccessBlockConfiguration are also flagged as potentially exposed.

        Returns:
            OperationResult with details["exposed_buckets"] = list of bucket names,
            details["buckets"] = per-bucket findings.
        """
        result = OperationResult(
            operation="hunt_exposed_s3_buckets",
            target="s3",
            success=True,
        )

        s3 = self._services.s3
        findings: List[Dict[str, Any]] = []
        exposed: List[str] = []

        try:
            resp = s3.list_buckets()
            buckets = resp.get("Buckets", [])

            for bucket in buckets:
                name = bucket["Name"]
                entry: Dict[str, Any] = {"bucket": name, "exposed": False, "reason": None}

                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    fully_blocked = all([
                        cfg.get("BlockPublicAcls"),
                        cfg.get("IgnorePublicAcls"),
                        cfg.get("BlockPublicPolicy"),
                        cfg.get("RestrictPublicBuckets"),
                    ])
                    if not fully_blocked:
                        entry["exposed"] = True
                        entry["reason"] = "public_access_block_incomplete"
                        entry["public_access_block"] = cfg
                        exposed.append(name)
                except botocore.exceptions.ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code == "NoSuchPublicAccessBlockConfiguration":
                        entry["exposed"] = True
                        entry["reason"] = "no_public_access_block"
                        exposed.append(name)
                    else:
                        entry["check_error"] = str(exc)

                findings.append(entry)

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list S3 buckets: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_exposed_s3_buckets.error", error=str(exc)))

        result.details["buckets"] = findings
        result.details["exposed_buckets"] = exposed
        result.details["statistics"] = {
            "total_buckets": len(findings),
            "exposed_count": len(exposed),
        }
        _log.info(event("aws_ir_hunt", "hunt_exposed_s3_buckets.complete", total=len(findings), exposed=len(exposed)))
        return result

    # =====================
    # IAM: Admin principals
    # =====================

    def list_iam_admin_principals(self) -> OperationResult:
        """
        Find IAM users and roles with administrator-level access.

        Checks for principals with AdministratorAccess managed policy attached
        or any inline policy containing Action: * with Effect: Allow.

        Returns:
            OperationResult with details["admin_users"] and details["admin_roles"].
        """
        result = OperationResult(
            operation="list_iam_admin_principals",
            target="iam",
            success=True,
        )

        iam = self._services.iam
        admin_users: List[str] = []
        admin_roles: List[str] = []
        _ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

        try:
            # Users with AdministratorAccess or wildcard inline policy
            for page in iam.get_paginator("list_users").paginate():
                for user in page.get("Users", []):
                    name = user["UserName"]
                    is_admin = False

                    # Attached managed policies
                    for ap in iam.get_paginator("list_attached_user_policies").paginate(UserName=name):
                        for p in ap.get("AttachedPolicies", []):
                            if p["PolicyArn"] == _ADMIN_ARN:
                                is_admin = True

                    # Inline policies
                    if not is_admin:
                        for ip in iam.get_paginator("list_user_policies").paginate(UserName=name):
                            for pname in ip.get("PolicyNames", []):
                                doc = iam.get_user_policy(UserName=name, PolicyName=pname)
                                pd = doc.get("PolicyDocument", {})
                                for stmt in pd.get("Statement", []):
                                    if stmt.get("Effect") == "Allow" and stmt.get("Action") in ("*", ["*"]):
                                        is_admin = True

                    if is_admin:
                        admin_users.append(name)

            # Roles with AdministratorAccess or wildcard inline policy
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    name = role["RoleName"]
                    is_admin = False

                    for ap in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                        for p in ap.get("AttachedPolicies", []):
                            if p["PolicyArn"] == _ADMIN_ARN:
                                is_admin = True

                    if not is_admin:
                        for ip in iam.get_paginator("list_role_policies").paginate(RoleName=name):
                            for pname in ip.get("PolicyNames", []):
                                doc = iam.get_role_policy(RoleName=name, PolicyName=pname)
                                pd = doc.get("PolicyDocument", {})
                                for stmt in pd.get("Statement", []):
                                    if stmt.get("Effect") == "Allow" and stmt.get("Action") in ("*", ["*"]):
                                        is_admin = True

                    if is_admin:
                        admin_roles.append(name)

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to enumerate IAM principals: {exc}")
            _log.error(event("aws_ir_hunt", "list_iam_admin_principals.error", error=str(exc)))

        result.details["admin_users"] = admin_users
        result.details["admin_roles"] = admin_roles
        result.details["statistics"] = {
            "admin_users": len(admin_users),
            "admin_roles": len(admin_roles),
        }
        _log.info(event("aws_ir_hunt", "list_iam_admin_principals.complete",
                        users=len(admin_users), roles=len(admin_roles)))
        return result

    # =====================
    # CloudTrail: Login hunt
    # =====================

    def hunt_unusual_login_locations(
        self,
        *,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 200,
    ) -> OperationResult:
        """
        Hunt for console login events in CloudTrail.

        Returns all ConsoleLogin events in the time window. Callers can inspect
        source IPs, user agents, and MFA usage to identify anomalous logins.

        Args:
            start_time:  Earliest event time (UTC).
            end_time:    Latest event time (UTC).
            max_events:  Maximum events to return.

        Returns:
            OperationResult with details["events"] = list of login event dicts.
        """
        result = OperationResult(
            operation="hunt_unusual_login_locations",
            target="cloudtrail",
            success=True,
        )

        ct = self._services.cloudtrail
        events: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        lookup_attrs = [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}]

        try:
            while len(events) < max_events:
                params: Dict[str, Any] = {
                    "LookupAttributes": lookup_attrs,
                    "MaxResults": min(50, max_events - len(events)),
                }
                if start_time:
                    params["StartTime"] = start_time
                if end_time:
                    params["EndTime"] = end_time
                if next_token:
                    params["NextToken"] = next_token

                resp = ct.lookup_events(**params)
                batch = resp.get("Events", [])
                events.extend(batch)
                next_token = resp.get("NextToken")
                if not next_token or not batch:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"CloudTrail lookup failed: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_unusual_login_locations.error", error=str(exc)))

        result.details["events"] = events
        result.details["statistics"] = {"total_events": len(events)}
        _log.info(event("aws_ir_hunt", "hunt_unusual_login_locations.complete", total=len(events)))
        return result

    # =====================
    # EC2: Public snapshots
    # =====================

    def list_public_snapshots(
        self,
        *,
        owner_id: Optional[str] = None,
    ) -> OperationResult:
        """
        List EBS snapshots that are shared publicly.

        Public snapshots are a significant data-leakage vector. This method
        lists all snapshots restorable by any AWS account (RestorableByUserIds=all).

        Args:
            owner_id: AWS account ID to restrict results to. If omitted, returns
                      any publicly-visible snapshot.

        Returns:
            OperationResult with details["snapshots"] = list of snapshot dicts.
        """
        result = OperationResult(
            operation="list_public_snapshots",
            target=f"account={owner_id or 'all'}",
            success=True,
        )

        ec2 = self._services.ec2
        snapshots: List[Dict[str, Any]] = []

        describe_kwargs: Dict[str, Any] = {
            "RestorableByUserIds": ["all"],
        }
        if owner_id:
            describe_kwargs["OwnerIds"] = [owner_id]

        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(**describe_kwargs):
                for snap in page.get("Snapshots", []):
                    snapshots.append({
                        "snapshot_id": snap.get("SnapshotId"),
                        "volume_id": snap.get("VolumeId"),
                        "owner_id": snap.get("OwnerId"),
                        "start_time": snap.get("StartTime").isoformat() if snap.get("StartTime") else None,
                        "volume_size": snap.get("VolumeSize"),
                        "description": snap.get("Description"),
                        "encrypted": snap.get("Encrypted"),
                        "tags": snap.get("Tags", []),
                    })

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list public snapshots: {exc}")
            _log.error(event("aws_ir_hunt", "list_public_snapshots.error", error=str(exc)))

        result.details["snapshots"] = snapshots
        result.details["statistics"] = {"total_public_snapshots": len(snapshots)}
        _log.info(event("aws_ir_hunt", "list_public_snapshots.complete", total=len(snapshots)))
        return result

    # =====================
    # Lambda: Env secret hunt
    # =====================

    def hunt_lambda_env_secrets(
        self,
        *,
        patterns: Optional[List[str]] = None,
        max_functions: int = 200,
    ) -> OperationResult:
        """
        List Lambda functions whose environment variables may contain secrets.

        Checks env var names against known secret-like patterns (KEY, SECRET,
        TOKEN, PASSWORD, CREDENTIAL, etc.). Returns function names + flagged
        var names (never values).

        Args:
            patterns:      Additional env var name substrings to flag.
            max_functions: Maximum functions to scan.

        Returns:
            OperationResult with details["flagged"] = list of {function, flagged_vars}.
        """
        _DEFAULT_PATTERNS = {
            "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL",
            "PRIVATE", "API_KEY", "AUTH", "ACCESS_KEY", "CLIENT_SECRET",
        }
        check_patterns = _DEFAULT_PATTERNS | {p.upper() for p in (patterns or [])}

        result = OperationResult(
            operation="hunt_lambda_env_secrets",
            target="lambda",
            success=True,
        )

        lambda_ = self._services.lambda_
        flagged: List[Dict[str, Any]] = []
        total_scanned = 0

        try:
            paginator = lambda_.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    if total_scanned >= max_functions:
                        break

                    total_scanned += 1
                    fn_name = fn.get("FunctionName", "")
                    env_vars = fn.get("Environment", {}).get("Variables", {})

                    suspect_keys = [
                        k for k in env_vars
                        if any(pat in k.upper() for pat in check_patterns)
                    ]

                    if suspect_keys:
                        flagged.append({
                            "function": fn_name,
                            "runtime": fn.get("Runtime"),
                            "flagged_vars": suspect_keys,
                        })

                if total_scanned >= max_functions:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to list Lambda functions: {exc}")
            _log.error(event("aws_ir_hunt", "hunt_lambda_env_secrets.error", error=str(exc)))

        result.details["flagged"] = flagged
        result.details["statistics"] = {
            "functions_scanned": total_scanned,
            "functions_flagged": len(flagged),
        }
        _log.info(event("aws_ir_hunt", "hunt_lambda_env_secrets.complete",
                        scanned=total_scanned, flagged=len(flagged)))
        return result

    # =====================
    # EC2: Open security groups
    # =====================

    def list_open_security_groups(
        self,
        *,
        ports: Optional[List[int]] = None,
        max_groups: int = 500,
    ) -> OperationResult:
        """
        Find EC2 security groups with ingress rules open to 0.0.0.0/0 or ::/0.

        Optionally restrict to specific destination ports.

        Args:
            ports:      If provided, only flag rules matching these ports.
            max_groups: Maximum security groups to return.

        Returns:
            OperationResult with details["open_groups"] = list of group findings.
        """
        result = OperationResult(
            operation="list_open_security_groups",
            target="ec2",
            success=True,
        )

        ec2 = self._services.ec2
        open_groups: List[Dict[str, Any]] = []
        total = 0

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    if total >= max_groups:
                        break

                    total += 1
                    open_rules: List[Dict[str, Any]] = []

                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")

                        # Check if this port range overlaps requested ports
                        if ports:
                            port_match = any(
                                (from_port is None or from_port <= p) and
                                (to_port is None or to_port >= p)
                                for p in ports
                            )
                            if not port_match:
                                continue

                        open_cidrs = [
                            r["CidrIp"] for r in perm.get("IpRanges", [])
                            if r.get("CidrIp") in ("0.0.0.0/0",)
                        ]
                        open_ipv6 = [
                            r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])
                            if r.get("CidrIpv6") in ("::/0",)
                        ]

                        if open_cidrs or open_ipv6:
                            open_rules.append({
                                "protocol": perm.get("IpProtocol"),
                                "from_port": from_port,
                                "to_port": to_port,
                                "open_cidrs": open_cidrs + open_ipv6,
                            })

                    if open_rules:
                        open_groups.append({
                            "group_id": sg.get("GroupId"),
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "open_rules": open_rules,
                        })

                if total >= max_groups:
                    break

        except botocore.exceptions.ClientError as exc:
            result.add_error(f"Failed to describe security groups: {exc}")
            _log.error(event("aws_ir_hunt", "list_open_security_groups.error", error=str(exc)))

        result.details["open_groups"] = open_groups
        result.details["statistics"] = {
            "groups_scanned": total,
            "open_groups_count": len(open_groups),
        }
        _log.info(event("aws_ir_hunt", "list_open_security_groups.complete",
                        scanned=total, open=len(open_groups)))
        return result
