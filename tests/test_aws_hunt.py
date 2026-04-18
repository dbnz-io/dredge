import os
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call
import pytest
from botocore.exceptions import ClientError

from dredge.aws_ir.hunt import AwsIRHunt
from dredge.config import DredgeConfig


def make_services():
    return MagicMock()


def make_client_error(code="AccessDenied"):
    return ClientError({"Error": {"Code": code, "Message": "Rate exceeded"}}, "LookupEvents")


def make_event(event_name="ConsoleLogin", username="alice", source_ip="1.1.1.1"):
    return {
        "EventId": "evt-001",
        "EventName": event_name,
        "EventTime": datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        "Username": username,
        "EventSource": "signin.amazonaws.com",
        "AwsRegion": "us-east-1",
        "ReadOnly": False,
        "AccessKeyId": "AKIAKEY",
        "SourceIPAddress": source_ip,
        "Resources": [],
        "CloudTrailEvent": json.dumps({"sourceIPAddress": source_ip}),
    }


class TestBuildLookupAttributes:
    def test_access_key_id_takes_priority(self):
        attrs = AwsIRHunt._build_lookup_attributes(
            access_key_id="AK123", user_name="alice", event_name="ConsoleLogin"
        )
        assert attrs[0]["AttributeKey"] == "AccessKeyId"
        assert attrs[0]["AttributeValue"] == "AK123"

    def test_user_name_second_priority(self):
        attrs = AwsIRHunt._build_lookup_attributes(
            access_key_id=None, user_name="alice", event_name="ConsoleLogin"
        )
        assert attrs[0]["AttributeKey"] == "Username"
        assert attrs[0]["AttributeValue"] == "alice"

    def test_event_name_third_priority(self):
        attrs = AwsIRHunt._build_lookup_attributes(
            access_key_id=None, user_name=None, event_name="ConsoleLogin"
        )
        assert attrs[0]["AttributeKey"] == "EventName"

    def test_no_filters_returns_empty(self):
        attrs = AwsIRHunt._build_lookup_attributes(
            access_key_id=None, user_name=None, event_name=None
        )
        assert attrs == []


class TestNormalizeEvent:
    def test_happy_path(self):
        n = AwsIRHunt._normalize_event(make_event())
        assert n["event_name"] == "ConsoleLogin"
        assert n["username"] == "alice"
        assert n["source_ip_address"] == "1.1.1.1"

    def test_top_level_source_ip_wins(self):
        event = {
            "EventId": "e",
            "EventName": "GetObject",
            "SourceIPAddress": "9.9.9.9",
            "CloudTrailEvent": json.dumps({"sourceIPAddress": "1.1.1.1"}),
        }
        n = AwsIRHunt._normalize_event(event)
        assert n["source_ip_address"] == "9.9.9.9"

    def test_invalid_cloudtrail_json_handled(self):
        event = {
            "EventId": "e",
            "EventName": "GetObject",
            "CloudTrailEvent": "not valid json",
        }
        n = AwsIRHunt._normalize_event(event)
        assert n["source_ip_address"] is None

    def test_no_cloudtrail_event(self):
        event = {"EventId": "e", "EventName": "GetObject"}
        n = AwsIRHunt._normalize_event(event)
        assert n["event_id"] == "e"
        assert n["source_ip_address"] is None

    def test_event_time_isoformat(self):
        event = {
            "EventId": "e",
            "EventName": "X",
            "EventTime": datetime(2024, 6, 1, tzinfo=timezone.utc),
        }
        n = AwsIRHunt._normalize_event(event)
        assert "2024-06-01" in n["event_time"]

    def test_no_event_time_returns_none(self):
        n = AwsIRHunt._normalize_event({"EventId": "e", "EventName": "X"})
        assert n["event_time"] is None


class TestBuildTargetString:
    def test_all_fields(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        s = AwsIRHunt._build_target_string(
            user_name="alice", access_key_id="AK", event_name="Login",
            source_ip="1.2.3.4", start_time=start, end_time=end,
        )
        assert "user=alice" in s
        assert "access_key_id=AK" in s
        assert "event_name=Login" in s
        assert "source_ip=1.2.3.4" in s

    def test_no_optional_fields(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        s = AwsIRHunt._build_target_string(
            user_name=None, access_key_id=None, event_name=None,
            source_ip=None, start_time=start, end_time=end,
        )
        assert "time=" in s


class TestCallWithBackoff:
    def test_succeeds_on_first_try(self):
        func = MagicMock(return_value={"Events": []})
        result = AwsIRHunt._call_with_backoff(
            func, params={"Arg": "val"},
            throttle_max_retries=3, throttle_base_delay=0.1,
        )
        assert result == {"Events": []}
        func.assert_called_once_with(Arg="val")

    def test_retries_on_throttle_then_succeeds(self):
        func = MagicMock(side_effect=[
            make_client_error("Throttling"),
            {"Events": []},
        ])
        with patch("time.sleep"):
            result = AwsIRHunt._call_with_backoff(
                func, params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )
        assert result == {"Events": []}
        assert func.call_count == 2

    def test_non_throttle_error_raised_immediately(self):
        func = MagicMock(side_effect=make_client_error("NoSuchBucket"))
        with pytest.raises(ClientError):
            AwsIRHunt._call_with_backoff(
                func, params={},
                throttle_max_retries=3, throttle_base_delay=0.1,
            )
        func.assert_called_once()

    def test_exhausts_retries_and_raises(self):
        func = MagicMock(side_effect=make_client_error("Throttling"))
        with patch("time.sleep"):
            with pytest.raises(ClientError):
                AwsIRHunt._call_with_backoff(
                    func, params={},
                    throttle_max_retries=2, throttle_base_delay=0.1,
                )


class TestLookupEventsValidation:
    def test_source_ip_only_raises_value_error(self):
        services = make_services()
        hunt = AwsIRHunt(services, DredgeConfig())
        with pytest.raises(ValueError, match="source_ip cannot be the sole filter"):
            hunt.lookup_events(source_ip="1.2.3.4")

    def test_source_ip_with_user_name_is_allowed(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail
        # Should not raise
        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice", source_ip="1.2.3.4")
        assert result.success is True


class TestLookupEvents:
    def test_returns_events_from_single_page(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [make_event()], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice")

        assert result.success is True
        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["username"] == "alice"

    def test_paginates_until_no_next_token(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [
            {"Events": [make_event("Login")], "NextToken": "tok"},
            {"Events": [make_event("GetObject")], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice")
        assert len(result.details["events"]) == 2

    def test_max_events_limit(self):
        events = [make_event(f"Ev{i}") for i in range(10)]
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": events, "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(max_events=3)
        assert len(result.details["events"]) == 3

    def test_source_ip_filter_applied_client_side(self):
        events = [make_event(source_ip="1.1.1.1"), make_event(source_ip="2.2.2.2")]
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": events, "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice", source_ip="1.1.1.1")

        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["source_ip_address"] == "1.1.1.1"

    def test_event_name_client_side_filter_when_access_key_primary(self):
        events = [make_event("ConsoleLogin"), make_event("GetObject")]
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": events, "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(
            access_key_id="AK123", event_name="ConsoleLogin"
        )
        assert all(e["event_name"] == "ConsoleLogin" for e in result.details["events"])

    def test_api_error_records_failure(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = make_client_error()
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events()
        assert result.success is False
        assert result.errors

    def test_defaults_to_last_24h(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events()

        stats = result.details["statistics"]
        assert stats["time_range"]["start_time"] < stats["time_range"]["end_time"]

    def test_no_lookup_attributes_when_no_filters(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events()
        assert result.details["statistics"]["lookup_attributes"] == []

    def test_max_events_stops_before_next_page_request(self):
        # Fill max_events on page 1; NextToken exists but line 113 breaks before fetching page 2
        events = [make_event(f"Ev{i}") for i in range(5)]
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": events, "NextToken": "tok"}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(max_events=5)

        assert len(result.details["events"]) == 5
        cloudtrail.lookup_events.assert_called_once()  # never fetched page 2

    def test_statistics_include_api_calls(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).lookup_events()
        assert result.details["statistics"]["api_calls"] == 1


def _make_finding(finding_id="f-001", severity=5.0, ftype="UnauthorizedAccess:EC2/SSHBruteForce"):
    return {
        "Id": finding_id,
        "Type": ftype,
        "Severity": severity,
        "Title": "Brute force attempt",
        "Description": "SSH brute force",
        "Region": "us-east-1",
        "AccountId": "123456789012",
        "CreatedAt": "2024-01-01T00:00:00Z",
        "UpdatedAt": "2024-01-01T01:00:00Z",
        "Resource": {"ResourceType": "Instance"},
        "Service": {"ServiceName": "guardduty"},
    }


class TestListGuarddutyFindings:
    def test_happy_path(self):
        gd = MagicMock()
        gd.list_findings.return_value = {"FindingIds": ["f-001"], "NextToken": None}
        gd.get_findings.return_value = {"Findings": [_make_finding()]}
        services = make_services()
        services.guardduty = gd

        result = AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123")
        assert result.success is True
        assert len(result.details["findings"]) == 1
        assert result.details["findings"][0]["finding_id"] == "f-001"
        assert result.details["findings"][0]["severity"] == 5.0

    def test_severity_min_included_in_criteria(self):
        gd = MagicMock()
        gd.list_findings.return_value = {"FindingIds": [], "NextToken": None}
        services = make_services()
        services.guardduty = gd

        AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123", severity_min=4.0)
        call_kwargs = gd.list_findings.call_args[1]
        criterion = call_kwargs["FindingCriteria"]["Criterion"]
        assert criterion["severity"]["Gte"] == 4.0

    def test_finding_types_filter_in_criteria(self):
        gd = MagicMock()
        gd.list_findings.return_value = {"FindingIds": [], "NextToken": None}
        services = make_services()
        services.guardduty = gd

        AwsIRHunt(services, DredgeConfig()).list_guardduty_findings(
            "det-123", finding_types=["UnauthorizedAccess:EC2/SSHBruteForce"]
        )
        call_kwargs = gd.list_findings.call_args[1]
        criterion = call_kwargs["FindingCriteria"]["Criterion"]
        assert criterion["type"]["Eq"] == ["UnauthorizedAccess:EC2/SSHBruteForce"]

    def test_paginates_finding_ids(self):
        gd = MagicMock()
        gd.list_findings.side_effect = [
            {"FindingIds": ["f-001", "f-002"], "NextToken": "tok"},
            {"FindingIds": ["f-003"], "NextToken": None},
        ]
        gd.get_findings.return_value = {"Findings": [_make_finding(fid) for fid in ["f-001", "f-002", "f-003"]]}
        services = make_services()
        services.guardduty = gd

        result = AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123", max_findings=100)
        assert len(result.details["findings"]) == 3
        assert gd.list_findings.call_count == 2

    def test_max_findings_limits_ids_collected(self):
        gd = MagicMock()
        gd.list_findings.return_value = {"FindingIds": ["f-001", "f-002", "f-003"], "NextToken": None}
        gd.get_findings.return_value = {"Findings": [_make_finding("f-001"), _make_finding("f-002")]}
        services = make_services()
        services.guardduty = gd

        result = AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123", max_findings=2)
        # Only 2 IDs should be collected; get_findings called with those 2
        ids_fetched = gd.get_findings.call_args[1]["FindingIds"]
        assert len(ids_fetched) == 2

    def test_list_findings_api_error(self):
        gd = MagicMock()
        gd.list_findings.side_effect = make_client_error()
        services = make_services()
        services.guardduty = gd

        result = AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123")
        assert result.success is False
        assert result.errors

    def test_get_findings_api_error_records_failure(self):
        gd = MagicMock()
        gd.list_findings.return_value = {"FindingIds": ["f-001"], "NextToken": None}
        gd.get_findings.side_effect = make_client_error()
        services = make_services()
        services.guardduty = gd

        result = AwsIRHunt(services, DredgeConfig()).list_guardduty_findings("det-123")
        assert result.success is False


class TestHuntCloudwatchLogs:
    def test_happy_path(self):
        logs = MagicMock()
        logs.start_query.return_value = {"queryId": "q-001"}
        logs.get_query_results.return_value = {
            "status": "Complete",
            "results": [[{"field": "@message", "value": "hello"}]],
        }
        services = make_services()
        services.logs = logs

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).hunt_cloudwatch_logs(
                "/aws/lambda/fn", "fields @message"
            )

        assert result.success is True
        assert result.details["results"] == [{"@message": "hello"}]
        assert result.details["statistics"]["query_id"] == "q-001"

    def test_polls_until_complete(self):
        logs = MagicMock()
        logs.start_query.return_value = {"queryId": "q-001"}
        logs.get_query_results.side_effect = [
            {"status": "Running", "results": []},
            {"status": "Complete", "results": [[{"field": "f", "value": "v"}]]},
        ]
        services = make_services()
        services.logs = logs

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).hunt_cloudwatch_logs(
                "/aws/lambda/fn", "fields @message"
            )

        assert result.success is True
        assert logs.get_query_results.call_count == 2

    def test_times_out_records_failure(self):
        logs = MagicMock()
        logs.start_query.return_value = {"queryId": "q-001"}
        logs.get_query_results.return_value = {"status": "Running", "results": []}
        services = make_services()
        services.logs = logs

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).hunt_cloudwatch_logs(
                "/aws/lambda/fn", "fields @message",
                poll_interval=1.0, max_wait_seconds=2.0,
            )

        assert result.success is False
        assert result.errors

    def test_failed_status_records_failure(self):
        logs = MagicMock()
        logs.start_query.return_value = {"queryId": "q-001"}
        logs.get_query_results.return_value = {"status": "Failed", "results": []}
        services = make_services()
        services.logs = logs

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).hunt_cloudwatch_logs(
                "/aws/lambda/fn", "fields @message"
            )

        assert result.success is False

    def test_start_query_api_error(self):
        logs = MagicMock()
        logs.start_query.side_effect = make_client_error()
        services = make_services()
        services.logs = logs

        result = AwsIRHunt(services, DredgeConfig()).hunt_cloudwatch_logs(
            "/aws/lambda/fn", "fields @message"
        )
        assert result.success is False
        assert result.errors


# =====================================================================
# New hunt methods added in second implementation pass
# =====================================================================


class TestHuntSecurityHubFindings:
    def test_happy_path(self):
        services = make_services()
        services.securityhub.get_findings.return_value = {
            "Findings": [{"Id": "f-001", "Severity": {"Label": "HIGH"}}],
            "NextToken": None,
        }
        result = AwsIRHunt(services, DredgeConfig()).hunt_security_hub_findings(severity_labels=["HIGH"])
        assert result.success is True
        assert len(result.details["findings"]) == 1
        call_filters = services.securityhub.get_findings.call_args[1]["Filters"]
        assert call_filters["SeverityLabel"] == [{"Value": "HIGH", "Comparison": "EQUALS"}]

    def test_paginates(self):
        services = make_services()
        services.securityhub.get_findings.side_effect = [
            {"Findings": [{"Id": "f-001"}], "NextToken": "tok"},
            {"Findings": [{"Id": "f-002"}], "NextToken": None},
        ]
        result = AwsIRHunt(services, DredgeConfig()).hunt_security_hub_findings(max_findings=100)
        assert len(result.details["findings"]) == 2
        assert services.securityhub.get_findings.call_count == 2

    def test_api_error_records_failure(self):
        services = make_services()
        services.securityhub.get_findings.side_effect = make_client_error()
        result = AwsIRHunt(services, DredgeConfig()).hunt_security_hub_findings()
        assert result.success is False

    def test_time_range_filters_added(self):
        services = make_services()
        services.securityhub.get_findings.return_value = {"Findings": [], "NextToken": None}
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        AwsIRHunt(services, DredgeConfig()).hunt_security_hub_findings(start_time=start, end_time=end)
        call_filters = services.securityhub.get_findings.call_args[1]["Filters"]
        assert "UpdatedAt" in call_filters
        assert call_filters["UpdatedAt"][0]["Start"] == "2026-01-01T00:00:00Z"
        assert call_filters["UpdatedAt"][0]["End"] == "2026-01-02T00:00:00Z"


class TestHuntAccessAnalyzerFindings:
    def test_happy_path(self):
        services = make_services()
        services.accessanalyzer.list_findings.return_value = {
            "findings": [{"id": "aa-001", "status": "ACTIVE"}],
            "nextToken": None,
        }
        result = AwsIRHunt(services, DredgeConfig()).hunt_access_analyzer_findings("arn:aws:aa:analyzer/1")
        assert result.success is True
        assert len(result.details["findings"]) == 1

    def test_status_filter_applied(self):
        services = make_services()
        services.accessanalyzer.list_findings.return_value = {"findings": [], "nextToken": None}
        AwsIRHunt(services, DredgeConfig()).hunt_access_analyzer_findings(
            "arn:aws:aa:analyzer/1", status="ACTIVE"
        )
        call_kwargs = services.accessanalyzer.list_findings.call_args[1]
        assert call_kwargs["filter"]["status"] == {"eq": ["ACTIVE"]}

    def test_paginates(self):
        services = make_services()
        services.accessanalyzer.list_findings.side_effect = [
            {"findings": [{"id": "aa-001"}], "nextToken": "tok"},
            {"findings": [{"id": "aa-002"}], "nextToken": None},
        ]
        result = AwsIRHunt(services, DredgeConfig()).hunt_access_analyzer_findings("arn:a")
        assert len(result.details["findings"]) == 2

    def test_api_error_records_failure(self):
        services = make_services()
        services.accessanalyzer.list_findings.side_effect = make_client_error()
        result = AwsIRHunt(services, DredgeConfig()).hunt_access_analyzer_findings("arn:a")
        assert result.success is False


class TestHuntConfigResourceHistory:
    def test_happy_path(self):
        services = make_services()
        services.awsconfig.get_resource_config_history.return_value = {
            "configurationItems": [{"configurationItemCaptureTime": "2026-01-01"}],
            "nextToken": None,
        }
        result = AwsIRHunt(services, DredgeConfig()).hunt_config_resource_history(
            "AWS::EC2::Instance", "i-123"
        )
        assert result.success is True
        assert len(result.details["configuration_items"]) == 1
        assert result.details["statistics"]["resource_type"] == "AWS::EC2::Instance"

    def test_passes_time_range(self):
        services = make_services()
        services.awsconfig.get_resource_config_history.return_value = {
            "configurationItems": [], "nextToken": None
        }
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        AwsIRHunt(services, DredgeConfig()).hunt_config_resource_history(
            "AWS::EC2::Instance", "i-123", start_time=start
        )
        call_kwargs = services.awsconfig.get_resource_config_history.call_args[1]
        assert call_kwargs["earlierTime"] == start

    def test_paginates(self):
        services = make_services()
        services.awsconfig.get_resource_config_history.side_effect = [
            {"configurationItems": [{"id": "c1"}], "nextToken": "tok"},
            {"configurationItems": [{"id": "c2"}], "nextToken": None},
        ]
        result = AwsIRHunt(services, DredgeConfig()).hunt_config_resource_history("t", "r")
        assert len(result.details["configuration_items"]) == 2

    def test_api_error_records_failure(self):
        services = make_services()
        services.awsconfig.get_resource_config_history.side_effect = make_client_error()
        result = AwsIRHunt(services, DredgeConfig()).hunt_config_resource_history("t", "r")
        assert result.success is False


class TestGetIamCredentialReport:
    _CSV = "user,arn,user_creation_time\nalice,arn:aws:iam::123:user/alice,2025-01-01\nbob,arn:aws:iam::123:user/bob,2025-01-02\n"

    def test_happy_path_complete_immediately(self):
        services = make_services()
        services.iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        services.iam.get_credential_report.return_value = {"Content": self._CSV.encode()}

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).get_iam_credential_report()

        assert result.success is True
        assert result.details["statistics"]["total_users"] == 2
        assert result.details["users"][0]["user"] == "alice"

    def test_polls_until_complete(self):
        services = make_services()
        services.iam.generate_credential_report.side_effect = [
            {"State": "STARTED"},
            {"State": "INPROGRESS"},
            {"State": "COMPLETE"},
        ]
        services.iam.get_credential_report.return_value = {"Content": self._CSV.encode()}

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).get_iam_credential_report()

        assert result.success is True
        assert services.iam.generate_credential_report.call_count == 3

    def test_timeout_records_failure(self):
        services = make_services()
        services.iam.generate_credential_report.return_value = {"State": "INPROGRESS"}

        with patch("time.sleep"):
            result = AwsIRHunt(services, DredgeConfig()).get_iam_credential_report(
                max_wait_seconds=1.0, poll_interval=1.0
            )

        assert result.success is False
        assert result.errors

    def test_api_error_records_failure(self):
        services = make_services()
        services.iam.generate_credential_report.side_effect = make_client_error()
        result = AwsIRHunt(services, DredgeConfig()).get_iam_credential_report()
        assert result.success is False
