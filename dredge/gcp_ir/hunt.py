from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from google.api_core import exceptions as g_exceptions
from google.cloud import logging_v2 as logging

from .config import GcpIRConfig
from .services import GcpLoggingService
from .models import OperationResult
from ..log import get_logger, event as log_event

_log = get_logger(__name__)


class GcpIRHunt:
    """
    Hunt / search utilities over Google Cloud Logging.

    Primarily aimed at Cloud Audit Logs, but works for any logs
    you can filter with the Logging query language.:contentReference[oaicite:1]{index=1}
    """

    def __init__(self, services: GcpLoggingService, config: GcpIRConfig) -> None:
        self._services = services
        self._config = config

    # ------------------- public API -------------------

    def search_logs(
        self,
        *,
        principal_email: Optional[str] = None,
        method_name: Optional[str] = None,
        resource_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        log_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_entries: int = 500,
        page_size: int = 100,
        order_desc: bool = True,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        Search GCP logs using simple IR-friendly filters.

        Args:
            principal_email: Filter on protoPayload.authenticationInfo.principalEmail.
            method_name:     Filter on protoPayload.methodName.
            resource_name:   Filter on protoPayload.resourceName.
            source_ip:       Filter on protoPayload.requestMetadata.callerIp.
            log_id:          Log ID; if omitted, uses config.default_log_id.
                             Examples: "cloudaudit.googleapis.com/activity"
            start_time:      Earliest event time (UTC).
            end_time:        Latest event time (UTC).
            max_entries:     Max number of log entries to return.
            page_size:       Page size for the API (<=1000 recommended).
            order_desc:      If True, newest first.
        """
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        log_id_value = log_id or self._config.default_log_id
        filter_str = self._build_filter(
            principal_email=principal_email,
            method_name=method_name,
            resource_name=resource_name,
            source_ip=source_ip,
            log_id=log_id_value,
            start_time=start_time,
            end_time=end_time,
        )

        result = OperationResult(
            operation="gcp_search_logs",
            target=self._target_string(
                principal_email=principal_email,
                method_name=method_name,
                resource_name=resource_name,
                source_ip=source_ip,
                log_id=log_id_value,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        entries: List[Dict[str, Any]] = []
        page_token: Optional[str] = None
        order_by = logging.DESCENDING if order_desc else logging.ASCENDING

        while len(entries) < max_entries:
            try:
                iterator = self._call_with_backoff(
                    filter_=filter_str,
                    page_size=min(max(page_size, 1), 1000),
                    order_by=order_by,
                    page_token=page_token,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
            except (RuntimeError, g_exceptions.GoogleAPICallError) as exc:
                result.add_error(f"GCP Logging API failed: {exc}")
                _log.error(log_event("gcp_ir_hunt", "search_logs.api_error", target=result.target, error=str(exc)))
                break

            # iterator.pages yields each page; we break after first page
            try:
                page = next(iterator.pages)
            except StopIteration:
                break

            for entry in page:
                if len(entries) >= max_entries:
                    break
                entries.append(self._normalize_entry(entry))

            page_token = iterator.next_page_token
            if not page_token or len(entries) >= max_entries:
                break

        result.details["entries"] = entries
        result.details["statistics"] = {
            "total_entries_returned": len(entries),
            "filter": filter_str,
            "log_id": log_id_value,
        }

        return result

    def search_today(
        self,
        *,
        principal_email: Optional[str] = None,
        method_name: Optional[str] = None,
        resource_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        log_id: Optional[str] = None,
        max_entries: int = 500,
    ) -> OperationResult:
        """
        Convenience wrapper: fetch *today's* logs (UTC calendar day).

        You can still filter by principal, method, resource name, or source IP.
        """
        now = datetime.now(timezone.utc)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)

        return self.search_logs(
            principal_email=principal_email,
            method_name=method_name,
            resource_name=resource_name,
            source_ip=source_ip,
            log_id=log_id,
            start_time=start,
            end_time=end,
            max_entries=max_entries,
        )

    # ------------------- internal helpers -------------------

    @staticmethod
    def _target_string(
        *,
        principal_email: Optional[str],
        method_name: Optional[str],
        resource_name: Optional[str],
        source_ip: Optional[str],
        log_id: str,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        bits = [f"log_id={log_id}"]
        if principal_email:
            bits.append(f"principal={principal_email}")
        if method_name:
            bits.append(f"method={method_name}")
        if resource_name:
            bits.append(f"resource={resource_name}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        if start_time or end_time:
            bits.append(
                f"timestamp={start_time.isoformat() if start_time else ''}"
                f"..{end_time.isoformat() if end_time else ''}"
            )
        return ",".join(bits)

    @staticmethod
    def _build_filter(
        *,
        principal_email: Optional[str],
        method_name: Optional[str],
        resource_name: Optional[str],
        source_ip: Optional[str],
        log_id: str,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        """
        Build a Cloud Logging filter expression using the Logging query language.:contentReference[oaicite:2]{index=2}
        """
        parts: List[str] = []

        # Restrict to a specific log ID (e.g. cloudaudit.googleapis.com/activity)
        # Using log_id() helper makes filters nicer.
        parts.append(f'log_id("{log_id}")')

        # Common Cloud Audit Logs fields:
        #   protoPayload.authenticationInfo.principalEmail
        #   protoPayload.methodName
        #   protoPayload.resourceName
        #   protoPayload.requestMetadata.callerIp
        if principal_email:
            parts.append(
                f'protoPayload.authenticationInfo.principalEmail="{principal_email}"'
            )
        if method_name:
            parts.append(f'protoPayload.methodName="{method_name}"')
        if resource_name:
            parts.append(f'protoPayload.resourceName="{resource_name}"')
        if source_ip:
            parts.append(
                f'protoPayload.requestMetadata.callerIp="{source_ip}"'
            )

        if start_time or end_time:
            def ts(dt: datetime) -> str:
                # Cloud Logging expects RFC3339 timestamps
                return dt.astimezone(timezone.utc).isoformat()

            if start_time and end_time:
                # Same calendar day? Use >= and <= with full timestamps for precision.
                parts.append(
                    f'timestamp >= "{ts(start_time)}" AND timestamp <= "{ts(end_time)}"'
                )
            elif start_time:
                parts.append(f'timestamp >= "{ts(start_time)}"')
            elif end_time:
                parts.append(f'timestamp <= "{ts(end_time)}"')

        return " AND ".join(parts)

    @staticmethod
    def _normalize_entry(entry: logging.entries.LogEntry) -> Dict[str, Any]:
        """
        Normalize a Cloud Logging entry into a stable dict for JSON serialization.
        """
        return {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "log_name": entry.log_name,
            "severity": entry.severity,
            "trace": entry.trace,
            "span_id": entry.span_id,
            "insert_id": entry.insert_id,
            "resource": dict(entry.resource) if entry.resource else None,
            "labels": dict(entry.labels) if entry.labels else None,
            "payload": entry.payload,  # can be dict, str, or proto
        }

    def _call_with_backoff(
        self,
        *,
        filter_: str,
        page_size: int,
        order_by: str,
        page_token: Optional[str],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> logging.entries.Iterator:
        """
        Call Cloud Logging with a simple exponential backoff on resource exhaustion.
        """
        attempt = 0
        while True:
            try:
                iterator = self._services.list_entries(
                    filter_=filter_,
                    page_size=page_size,
                    order_by=order_by,
                    page_token=page_token,
                )
                return iterator
            except (g_exceptions.ResourceExhausted, g_exceptions.TooManyRequests) as exc:
                if attempt >= throttle_max_retries:
                    raise RuntimeError(
                        f"GCP Logging rate limit exceeded and retries exhausted: {exc}"
                    ) from exc
                delay = throttle_base_delay * (2 ** attempt)
                _log.warning(log_event("gcp_ir_hunt", "rate_limit", attempt=attempt, delay=delay))
                time.sleep(delay)
                attempt += 1
