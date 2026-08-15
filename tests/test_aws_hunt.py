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


def _make_paginator(pages):
    p = MagicMock()
    p.paginate.return_value = pages
    return p


class TestHuntExposedS3Buckets:
    def test_happy_path_no_exposure(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "safe-bucket"}]}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        services = make_services()
        services.s3 = s3

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_s3_buckets()
        assert result.success is True
        assert result.details["exposed_buckets"] == []
        assert result.details["buckets"][0]["exposed"] is False

    def test_incomplete_public_access_block_flagged(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "leaky-bucket"}]}
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        services = make_services()
        services.s3 = s3

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_s3_buckets()
        assert result.details["exposed_buckets"] == ["leaky-bucket"]
        assert result.details["buckets"][0]["reason"] == "public_access_block_incomplete"

    def test_no_such_public_access_block_configuration_flagged(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "no-pab-bucket"}]}
        s3.get_public_access_block.side_effect = make_client_error(
            code="NoSuchPublicAccessBlockConfiguration"
        )
        services = make_services()
        services.s3 = s3

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_s3_buckets()
        assert result.details["exposed_buckets"] == ["no-pab-bucket"]
        assert result.details["buckets"][0]["reason"] == "no_public_access_block"

    def test_other_bucket_error_recorded_not_fatal(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "other-bucket"}]}
        s3.get_public_access_block.side_effect = make_client_error(code="AccessDenied")
        services = make_services()
        services.s3 = s3

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_s3_buckets()
        assert result.success is True
        assert result.details["exposed_buckets"] == []
        assert "check_error" in result.details["buckets"][0]

    def test_list_buckets_fatal_error(self):
        s3 = MagicMock()
        s3.list_buckets.side_effect = make_client_error()
        services = make_services()
        services.s3 = s3

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_s3_buckets()
        assert result.success is False
        assert result.errors


def _make_iam_admin(
    *,
    users=None,
    user_attached=None,
    user_inline=None,
    user_policy_docs=None,
    roles=None,
    role_attached=None,
    role_inline=None,
    role_policy_docs=None,
):
    iam = MagicMock()
    _paginators = {
        "list_users": _make_paginator(
            [{"Users": [{"UserName": u} for u in (users or [])]}]
        ),
        "list_attached_user_policies": _make_paginator(
            [{"AttachedPolicies": [{"PolicyArn": a} for a in (user_attached or [])]}]
        ),
        "list_user_policies": _make_paginator(
            [{"PolicyNames": user_inline or []}]
        ),
        "list_roles": _make_paginator(
            [{"Roles": [{"RoleName": r} for r in (roles or [])]}]
        ),
        "list_attached_role_policies": _make_paginator(
            [{"AttachedPolicies": [{"PolicyArn": a} for a in (role_attached or [])]}]
        ),
        "list_role_policies": _make_paginator(
            [{"PolicyNames": role_inline or []}]
        ),
    }
    iam.get_paginator.side_effect = lambda op: _paginators.get(op, _make_paginator([{}]))
    iam.get_user_policy.side_effect = lambda UserName, PolicyName: (user_policy_docs or {}).get(
        PolicyName, {"PolicyDocument": {"Statement": []}}
    )
    iam.get_role_policy.side_effect = lambda RoleName, PolicyName: (role_policy_docs or {}).get(
        PolicyName, {"PolicyDocument": {"Statement": []}}
    )
    return iam


class TestListIamAdminPrincipals:
    def test_no_admins(self):
        services = make_services()
        services.iam = _make_iam_admin(users=["alice"], roles=["role-a"])

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.success is True
        assert result.details["admin_users"] == []
        assert result.details["admin_roles"] == []

    def test_user_admin_via_managed_policy(self):
        services = make_services()
        services.iam = _make_iam_admin(
            users=["alice"],
            user_attached=["arn:aws:iam::aws:policy/AdministratorAccess"],
        )

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.details["admin_users"] == ["alice"]

    def test_user_admin_via_wildcard_inline_policy(self):
        services = make_services()
        services.iam = _make_iam_admin(
            users=["bob"],
            user_inline=["danger"],
            user_policy_docs={
                "danger": {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}
            },
        )

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.details["admin_users"] == ["bob"]

    def test_role_admin_via_managed_policy(self):
        services = make_services()
        services.iam = _make_iam_admin(
            roles=["role-admin"],
            role_attached=["arn:aws:iam::aws:policy/AdministratorAccess"],
        )

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.details["admin_roles"] == ["role-admin"]

    def test_role_admin_via_wildcard_inline_policy(self):
        services = make_services()
        services.iam = _make_iam_admin(
            roles=["role-danger"],
            role_inline=["danger"],
            role_policy_docs={
                "danger": {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["*"]}]}}
            },
        )

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.details["admin_roles"] == ["role-danger"]

    def test_api_error_records_failure(self):
        services = make_services()
        iam = _make_iam_admin()
        iam.get_paginator.side_effect = make_client_error()
        services.iam = iam

        result = AwsIRHunt(services, DredgeConfig()).list_iam_admin_principals()
        assert result.success is False
        assert result.errors


class TestHuntUnusualLoginLocations:
    def test_happy_path(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {"Events": [make_event()], "NextToken": None}
        services = make_services()
        services.cloudtrail = ct

        result = AwsIRHunt(services, DredgeConfig()).hunt_unusual_login_locations()
        assert result.success is True
        assert result.details["statistics"]["total_events"] == 1
        ct.lookup_events.assert_called_once()
        assert ct.lookup_events.call_args[1]["LookupAttributes"] == [
            {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
        ]

    def test_start_end_time_passed_through(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = ct

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        AwsIRHunt(services, DredgeConfig()).hunt_unusual_login_locations(start_time=start, end_time=end)
        call_kwargs = ct.lookup_events.call_args[1]
        assert call_kwargs["StartTime"] == start
        assert call_kwargs["EndTime"] == end

    def test_paginates_until_max_events(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [
            {"Events": [make_event(), make_event()], "NextToken": "tok"},
            {"Events": [make_event()], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = ct

        result = AwsIRHunt(services, DredgeConfig()).hunt_unusual_login_locations(max_events=3)
        assert result.details["statistics"]["total_events"] == 3
        assert ct.lookup_events.call_count == 2

    def test_stops_on_empty_batch_even_with_next_token(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {"Events": [], "NextToken": "tok"}
        services = make_services()
        services.cloudtrail = ct

        result = AwsIRHunt(services, DredgeConfig()).hunt_unusual_login_locations(max_events=100)
        assert result.success is True
        assert ct.lookup_events.call_count == 1
        assert result.details["statistics"]["total_events"] == 0

    def test_client_error_records_failure(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = make_client_error()
        services = make_services()
        services.cloudtrail = ct

        result = AwsIRHunt(services, DredgeConfig()).hunt_unusual_login_locations()
        assert result.success is False
        assert result.errors


class TestListPublicSnapshots:
    def test_happy_path(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"Snapshots": [{
                "SnapshotId": "snap-1",
                "VolumeId": "vol-1",
                "OwnerId": "123456789012",
                "StartTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "VolumeSize": 8,
                "Description": "test",
                "Encrypted": False,
                "Tags": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_public_snapshots()
        assert result.success is True
        assert result.details["snapshots"][0]["snapshot_id"] == "snap-1"
        assert result.details["snapshots"][0]["start_time"] is not None
        call_kwargs = ec2.get_paginator.return_value.paginate.call_args[1]
        assert call_kwargs["RestorableByUserIds"] == ["all"]
        assert "OwnerIds" not in call_kwargs

    def test_owner_id_filters(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([{"Snapshots": []}])
        services = make_services()
        services.ec2 = ec2

        AwsIRHunt(services, DredgeConfig()).list_public_snapshots(owner_id="123456789012")
        call_kwargs = ec2.get_paginator.return_value.paginate.call_args[1]
        assert call_kwargs["OwnerIds"] == ["123456789012"]

    def test_missing_start_time_handled(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"Snapshots": [{"SnapshotId": "snap-2", "VolumeId": "vol-2", "OwnerId": "o"}]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_public_snapshots()
        assert result.details["snapshots"][0]["start_time"] is None

    def test_api_error_records_failure(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_public_snapshots()
        assert result.success is False
        assert result.errors


class TestHuntLambdaEnvSecrets:
    def test_happy_path_flags_suspect_vars(self):
        lambda_ = MagicMock()
        lambda_.get_paginator.return_value = _make_paginator([
            {"Functions": [{
                "FunctionName": "fn-1",
                "Runtime": "python3.13",
                "Environment": {"Variables": {"DB_PASSWORD": "x", "REGION": "us-east-1"}},
            }]}
        ])
        services = make_services()
        services.lambda_ = lambda_

        result = AwsIRHunt(services, DredgeConfig()).hunt_lambda_env_secrets()
        assert result.success is True
        assert result.details["flagged"][0]["function"] == "fn-1"
        assert result.details["flagged"][0]["flagged_vars"] == ["DB_PASSWORD"]

    def test_no_suspect_vars_not_flagged(self):
        lambda_ = MagicMock()
        lambda_.get_paginator.return_value = _make_paginator([
            {"Functions": [{
                "FunctionName": "fn-2",
                "Runtime": "python3.13",
                "Environment": {"Variables": {"REGION": "us-east-1"}},
            }]}
        ])
        services = make_services()
        services.lambda_ = lambda_

        result = AwsIRHunt(services, DredgeConfig()).hunt_lambda_env_secrets()
        assert result.details["flagged"] == []

    def test_custom_patterns_extend_defaults(self):
        lambda_ = MagicMock()
        lambda_.get_paginator.return_value = _make_paginator([
            {"Functions": [{
                "FunctionName": "fn-3",
                "Runtime": "python3.13",
                "Environment": {"Variables": {"CUSTOM_FLAG": "x"}},
            }]}
        ])
        services = make_services()
        services.lambda_ = lambda_

        result = AwsIRHunt(services, DredgeConfig()).hunt_lambda_env_secrets(patterns=["CUSTOM_FLAG"])
        assert result.details["flagged"][0]["flagged_vars"] == ["CUSTOM_FLAG"]

    def test_max_functions_cutoff(self):
        lambda_ = MagicMock()
        lambda_.get_paginator.return_value = _make_paginator([
            {"Functions": [
                {"FunctionName": f"fn-{i}", "Environment": {"Variables": {}}} for i in range(5)
            ]}
        ])
        services = make_services()
        services.lambda_ = lambda_

        result = AwsIRHunt(services, DredgeConfig()).hunt_lambda_env_secrets(max_functions=2)
        assert result.details["statistics"]["functions_scanned"] == 2

    def test_api_error_records_failure(self):
        lambda_ = MagicMock()
        lambda_.get_paginator.return_value.paginate.side_effect = make_client_error()
        services = make_services()
        services.lambda_ = lambda_

        result = AwsIRHunt(services, DredgeConfig()).hunt_lambda_env_secrets()
        assert result.success is False
        assert result.errors


class TestListOpenSecurityGroups:
    def test_open_ipv4_cidr_flagged(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-1",
                "GroupName": "open-sg",
                "VpcId": "vpc-1",
                "Description": "test",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups()
        assert result.success is True
        assert result.details["open_groups"][0]["group_id"] == "sg-1"
        assert result.details["open_groups"][0]["open_rules"][0]["open_cidrs"] == ["0.0.0.0/0"]

    def test_open_ipv6_cidr_flagged(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-2",
                "GroupName": "open-sg-v6",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups()
        assert result.details["open_groups"][0]["open_rules"][0]["open_cidrs"] == ["::/0"]

    def test_non_public_cidr_not_flagged(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-3",
                "GroupName": "closed-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups()
        assert result.details["open_groups"] == []

    def test_ports_filter_excludes_non_matching_rules(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-4",
                "GroupName": "sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups(ports=[22])
        assert result.details["open_groups"] == []

    def test_ports_filter_includes_matching_rule(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-5",
                "GroupName": "sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups(ports=[22])
        assert result.details["open_groups"] != []

    def test_max_groups_cutoff(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [
                {"GroupId": f"sg-{i}", "GroupName": "sg", "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
                }]} for i in range(5)
            ]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups(max_groups=2)
        assert result.details["statistics"]["groups_scanned"] == 2

    def test_api_error_records_failure(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).list_open_security_groups()
        assert result.success is False
        assert result.errors
