import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
import requests.exceptions

from dredge.github_ir.hunt import GitHubIRHunt
from dredge.github_ir.config import GitHubIRConfig


def make_config():
    return GitHubIRConfig(org="test-org", token="tok")


def make_services():
    services = MagicMock()
    services.audit_log_path_base = "/orgs/test-org/audit-log"
    return services


def make_response(status_code, json_data=None, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else []
    resp.headers = headers or {}
    resp.text = str(json_data)
    return resp


class TestSearchAuditLogEdgeCases:
    def test_naive_start_time_converted_to_utc(self):
        services = make_services()
        services.get.return_value = make_response(200, [])

        result = GitHubIRHunt(services, make_config()).search_audit_log(
            start_time=datetime(2024, 1, 1),
        )
        assert result.success is True

    def test_naive_end_time_converted_to_utc(self):
        services = make_services()
        services.get.return_value = make_response(200, [])

        result = GitHubIRHunt(services, make_config()).search_audit_log(
            end_time=datetime(2024, 1, 2),
        )
        assert result.success is True

    def test_phrase_included_when_actor_set(self):
        services = make_services()
        services.get.return_value = make_response(200, [])

        GitHubIRHunt(services, make_config()).search_audit_log(actor="alice")

        call_params = services.get.call_args[1]["params"]
        assert "phrase" in call_params
        assert "actor:alice" in call_params["phrase"]

    def test_empty_response_stops_loop(self):
        services = make_services()
        services.get.return_value = make_response(200, [])

        result = GitHubIRHunt(services, make_config()).search_audit_log()

        assert result.details["events"] == []
        services.get.assert_called_once()

    def test_non_list_response_stops_loop(self):
        services = make_services()
        services.get.return_value = make_response(200, {"error": "bad"})

        result = GitHubIRHunt(services, make_config()).search_audit_log()
        assert result.success is True
        assert result.details["events"] == []

    def test_api_error_records_failure(self):
        services = make_services()
        services.get.side_effect = requests.exceptions.ConnectionError("network error")

        result = GitHubIRHunt(services, make_config()).search_audit_log()

        assert result.success is False
        assert result.errors

    def test_max_events_respected(self):
        events = [{"action": f"a.{i}", "actor": "u"} for i in range(10)]
        services = make_services()
        services.get.return_value = make_response(200, events)

        result = GitHubIRHunt(services, make_config()).search_audit_log(max_events=3, per_page=10)
        assert len(result.details["events"]) == 3


class TestTargetString:
    def test_only_action(self):
        s = GitHubIRHunt._target_string(
            actor=None, action="repo.create", repo=None, source_ip=None,
            start_time=None, end_time=None,
        )
        assert "action=repo.create" in s

    def test_only_repo(self):
        s = GitHubIRHunt._target_string(
            actor=None, action=None, repo="org/repo", source_ip=None,
            start_time=None, end_time=None,
        )
        assert "repo=org/repo" in s

    def test_only_source_ip(self):
        s = GitHubIRHunt._target_string(
            actor=None, action=None, repo=None, source_ip="1.2.3.4",
            start_time=None, end_time=None,
        )
        assert "source_ip=1.2.3.4" in s

    def test_no_filters_returns_default(self):
        s = GitHubIRHunt._target_string(
            actor=None, action=None, repo=None, source_ip=None,
            start_time=None, end_time=None,
        )
        assert s == "github_audit_log"

    def test_with_only_start_time(self):
        s = GitHubIRHunt._target_string(
            actor=None, action=None, repo=None, source_ip=None,
            start_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end_time=None,
        )
        assert "created=" in s

    def test_with_only_end_time(self):
        s = GitHubIRHunt._target_string(
            actor=None, action=None, repo=None, source_ip=None,
            start_time=None,
            end_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        )
        assert "created=" in s


class TestBuildPhrase:
    def test_only_end_time(self):
        end = datetime(2024, 1, 15, tzinfo=timezone.utc)
        phrase = GitHubIRHunt._build_phrase(
            actor=None, action=None, repo=None, source_ip=None,
            start_time=None, end_time=end,
        )
        assert "created:<=" in phrase
        assert "2024-01-15" in phrase

    def test_only_start_time(self):
        start = datetime(2024, 3, 1, tzinfo=timezone.utc)
        phrase = GitHubIRHunt._build_phrase(
            actor=None, action=None, repo=None, source_ip=None,
            start_time=start, end_time=None,
        )
        assert "created:>=" in phrase

    def test_source_ip_becomes_actor_ip(self):
        phrase = GitHubIRHunt._build_phrase(
            actor=None, action=None, repo=None, source_ip="10.0.0.1",
            start_time=None, end_time=None,
        )
        assert "actor_ip:10.0.0.1" in phrase


class TestCallWithBackoff:
    def test_rate_limit_429_retries_then_succeeds(self):
        services = make_services()
        services.get.side_effect = [
            make_response(429, headers={"X-RateLimit-Remaining": "5"}),
            make_response(200, []),
        ]

        hunt = GitHubIRHunt(services, make_config())

        with patch("time.sleep"):
            resp = hunt._call_with_backoff(
                path="/orgs/x/audit-log", params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )

        assert resp.status_code == 200
        assert services.get.call_count == 2

    def test_rate_limit_with_reset_header_waits(self):
        future_reset = str(int(time.time()) + 60)
        services = make_services()
        services.get.side_effect = [
            make_response(429, headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": future_reset,
            }),
            make_response(200, []),
        ]

        hunt = GitHubIRHunt(services, make_config())

        with patch("time.sleep") as mock_sleep:
            hunt._call_with_backoff(
                path="/orgs/x/audit-log", params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )

        mock_sleep.assert_called_once()

    def test_rate_limit_invalid_reset_header_falls_back(self):
        services = make_services()
        services.get.side_effect = [
            make_response(429, headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "not-a-number",
            }),
            make_response(200, []),
        ]

        hunt = GitHubIRHunt(services, make_config())

        with patch("time.sleep"):
            resp = hunt._call_with_backoff(
                path="/orgs/x/audit-log", params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )

        assert resp.status_code == 200

    def test_non_rate_limit_error_raises(self):
        services = make_services()
        services.get.return_value = make_response(500, {"message": "server error"})

        hunt = GitHubIRHunt(services, make_config())

        with pytest.raises(RuntimeError, match="GitHub API error 500"):
            hunt._call_with_backoff(
                path="/orgs/x/audit-log", params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )

    def test_non_json_error_body_handled(self):
        services = make_services()
        resp = make_response(404)
        resp.json.side_effect = ValueError("not json")
        resp.text = "Not Found"
        services.get.return_value = resp

        hunt = GitHubIRHunt(services, make_config())

        with pytest.raises(RuntimeError, match="GitHub API error 404"):
            hunt._call_with_backoff(
                path="/orgs/x/audit-log", params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )

    def test_exhausts_retries_then_raises(self):
        services = make_services()
        services.get.return_value = make_response(429, headers={"X-RateLimit-Remaining": "5"})

        hunt = GitHubIRHunt(services, make_config())

        with patch("time.sleep"):
            with pytest.raises(RuntimeError, match="GitHub API error 429"):
                hunt._call_with_backoff(
                    path="/orgs/x/audit-log", params={},
                    throttle_max_retries=2, throttle_base_delay=0.1,
                )
