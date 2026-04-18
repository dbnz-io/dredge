import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from dredge.gcp_ir.config import GcpIRConfig
from dredge.gcp_ir.hunt import GcpIRHunt


def make_config(**kw):
    return GcpIRConfig(project_id="test-project", **kw)


def make_services():
    return MagicMock()


def make_entry(log_name="projects/p/logs/audit", severity="INFO"):
    entry = MagicMock()
    entry.timestamp = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    entry.log_name = log_name
    entry.severity = severity
    entry.trace = "trace-1"
    entry.span_id = "span-1"
    entry.insert_id = "insert-1"
    entry.resource = None
    entry.labels = None
    entry.payload = {"methodName": "iam.createKey"}
    return entry


def make_iterator(entries, next_page_token=None):
    iterator = MagicMock()
    iterator.pages = iter([list(entries)])
    iterator.next_page_token = next_page_token
    return iterator


class TestBuildFilter:
    def test_log_id_always_present(self):
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="cloudaudit.googleapis.com/activity",
            start_time=None, end_time=None,
        )
        assert 'log_id("cloudaudit.googleapis.com/activity")' in f

    def test_principal_email_included(self):
        f = GcpIRHunt._build_filter(
            principal_email="user@example.com", method_name=None, resource_name=None,
            source_ip=None, log_id="log/id", start_time=None, end_time=None,
        )
        assert 'user@example.com' in f
        assert 'principalEmail' in f

    def test_method_name_included(self):
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name="iam.createKey", resource_name=None,
            source_ip=None, log_id="log/id", start_time=None, end_time=None,
        )
        assert 'iam.createKey' in f

    def test_resource_name_included(self):
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name="projects/123",
            source_ip=None, log_id="log/id", start_time=None, end_time=None,
        )
        assert 'projects/123' in f

    def test_source_ip_included(self):
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name=None,
            source_ip="1.2.3.4", log_id="log/id", start_time=None, end_time=None,
        )
        assert '1.2.3.4' in f
        assert 'callerIp' in f

    def test_both_times_uses_range(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="log/id", start_time=start, end_time=end,
        )
        assert 'timestamp >=' in f
        assert 'timestamp <=' in f

    def test_only_start_time(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="log/id", start_time=start, end_time=None,
        )
        assert 'timestamp >=' in f
        assert 'timestamp <=' not in f

    def test_only_end_time(self):
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        f = GcpIRHunt._build_filter(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="log/id", start_time=None, end_time=end,
        )
        assert 'timestamp <=' in f
        assert 'timestamp >=' not in f


class TestTargetString:
    def test_log_id_always_present(self):
        s = GcpIRHunt._target_string(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="my-log", start_time=None, end_time=None,
        )
        assert "log_id=my-log" in s

    def test_all_optional_fields(self):
        s = GcpIRHunt._target_string(
            principal_email="u@e.com", method_name="iam.x",
            resource_name="projects/r", source_ip="1.1.1.1",
            log_id="log/id",
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        )
        assert "principal=u@e.com" in s
        assert "method=iam.x" in s
        assert "resource=projects/r" in s
        assert "source_ip=1.1.1.1" in s
        assert "timestamp=" in s

    def test_only_start_time(self):
        s = GcpIRHunt._target_string(
            principal_email=None, method_name=None, resource_name=None,
            source_ip=None, log_id="l",
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=None,
        )
        assert "timestamp=" in s


class TestNormalizeEntry:
    def test_normalizes_standard_entry(self):
        entry = make_entry()
        n = GcpIRHunt._normalize_entry(entry)
        assert n["log_name"] == "projects/p/logs/audit"
        assert n["severity"] == "INFO"
        assert n["payload"] == {"methodName": "iam.createKey"}
        assert "2024-01-01" in n["timestamp"]

    def test_none_timestamp(self):
        entry = make_entry()
        entry.timestamp = None
        n = GcpIRHunt._normalize_entry(entry)
        assert n["timestamp"] is None

    def test_resource_converted_to_dict(self):
        entry = make_entry()
        entry.resource = {"type": "project", "labels": {"project_id": "abc"}}
        n = GcpIRHunt._normalize_entry(entry)
        assert n["resource"] == {"type": "project", "labels": {"project_id": "abc"}}

    def test_labels_converted_to_dict(self):
        entry = make_entry()
        entry.labels = {"env": "prod"}
        n = GcpIRHunt._normalize_entry(entry)
        assert n["labels"] == {"env": "prod"}


class TestSearchLogs:
    def test_happy_path_returns_entries(self):
        services = make_services()
        services.list_entries.return_value = make_iterator([make_entry()])

        result = GcpIRHunt(services, make_config()).search_logs()

        assert result.success is True
        assert len(result.details["entries"]) == 1

    def test_empty_page_stops_iteration(self):
        services = make_services()
        services.list_entries.return_value = make_iterator([])

        result = GcpIRHunt(services, make_config()).search_logs()

        assert result.success is True
        assert result.details["entries"] == []

    def test_stop_iteration_stops_loop(self):
        services = make_services()
        iterator = MagicMock()
        iterator.pages = iter([])  # immediately raises StopIteration on next()
        iterator.next_page_token = None
        services.list_entries.return_value = iterator

        result = GcpIRHunt(services, make_config()).search_logs()
        assert result.success is True
        assert result.details["entries"] == []

    def test_api_error_records_failure(self):
        from google.api_core import exceptions as g_exceptions
        services = make_services()
        services.list_entries.side_effect = g_exceptions.PermissionDenied("no access")

        result = GcpIRHunt(services, make_config()).search_logs()

        assert result.success is False
        assert any("GCP Logging API failed" in e for e in result.errors)

    def test_timezone_naive_times_get_utc(self):
        services = make_services()
        services.list_entries.return_value = make_iterator([])

        result = GcpIRHunt(services, make_config()).search_logs(
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 2),
        )
        assert result.success is True

    def test_max_entries_respected(self):
        entries = [make_entry() for _ in range(10)]
        services = make_services()
        services.list_entries.return_value = make_iterator(entries)

        result = GcpIRHunt(services, make_config()).search_logs(max_entries=5)
        assert len(result.details["entries"]) == 5

    def test_pagination_follows_next_page_token(self):
        services = make_services()

        iter1 = make_iterator([make_entry()], next_page_token="tok123")
        iter2 = make_iterator([make_entry()], next_page_token=None)
        services.list_entries.side_effect = [iter1, iter2]

        result = GcpIRHunt(services, make_config()).search_logs(max_entries=10)

        assert len(result.details["entries"]) == 2
        assert services.list_entries.call_count == 2

    def test_statistics_in_result(self):
        services = make_services()
        services.list_entries.return_value = make_iterator([])

        result = GcpIRHunt(services, make_config()).search_logs(
            principal_email="u@e.com"
        )
        stats = result.details["statistics"]
        assert "filter" in stats
        assert "log_id" in stats
        assert stats["total_entries_returned"] == 0


class TestSearchToday:
    def test_calls_search_logs_with_today_range(self):
        services = make_services()
        services.list_entries.return_value = make_iterator([])

        result = GcpIRHunt(services, make_config()).search_today(principal_email="u@e.com")

        assert result.success is True
        services.list_entries.assert_called_once()


class TestCallWithBackoff:
    def test_rate_limit_retries(self):
        from google.api_core import exceptions as g_exceptions

        services = make_services()
        services.list_entries.side_effect = [
            g_exceptions.ResourceExhausted("rate limited"),
            make_iterator([]),
        ]

        hunt = GcpIRHunt(services, make_config())

        with patch("time.sleep"):
            result = hunt.search_logs()

        assert result.success is True
        assert services.list_entries.call_count == 2

    def test_too_many_requests_retries(self):
        from google.api_core import exceptions as g_exceptions

        services = make_services()
        services.list_entries.side_effect = [
            g_exceptions.TooManyRequests("too many"),
            make_iterator([]),
        ]

        hunt = GcpIRHunt(services, make_config())

        with patch("time.sleep"):
            result = hunt.search_logs()

        assert result.success is True

    def test_rate_limit_exhausts_retries(self):
        from google.api_core import exceptions as g_exceptions

        services = make_services()
        services.list_entries.side_effect = g_exceptions.ResourceExhausted("persistent")

        hunt = GcpIRHunt(services, make_config())

        with patch("time.sleep"):
            result = hunt.search_logs(throttle_max_retries=1)

        assert result.success is False
        assert any("GCP Logging API failed" in e for e in result.errors)
