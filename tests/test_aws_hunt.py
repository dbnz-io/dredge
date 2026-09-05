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

    def test_source_ip_alone_allowed_with_allow_full_scan(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail
        # Should not raise
        result = AwsIRHunt(services, DredgeConfig()).lookup_events(
            source_ip="1.2.3.4", allow_full_scan=True,
        )
        assert result.success is True

    def test_truncated_true_when_max_events_hit_with_more_pages(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {
            "Events": [make_event(), make_event()], "NextToken": "more",
        }
        services = make_services()
        services.cloudtrail = cloudtrail
        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice", max_events=1)
        assert result.details["statistics"]["truncated"] is True

    def test_truncated_false_when_all_events_consumed(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [make_event()], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail
        result = AwsIRHunt(services, DredgeConfig()).lookup_events(user_name="alice")
        assert result.details["statistics"]["truncated"] is False


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

    def _paginated_cloudtrail(self, total_events, page_size=50):
        pages = []
        for i in range(0, total_events, page_size):
            chunk = [make_event(f"Ev{j}") for j in range(i, min(i + page_size, total_events))]
            next_token = f"tok-{i}" if i + page_size < total_events else None
            pages.append({"Events": chunk, "NextToken": next_token})
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = pages
        return cloudtrail

    @pytest.mark.parametrize("unlimited_value", [0, None, -1])
    def test_max_events_unlimited_returns_more_than_the_old_default_cap(self, unlimited_value):
        services = make_services()
        services.cloudtrail = self._paginated_cloudtrail(total_events=1200)

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(
            user_name="alice", max_events=unlimited_value,
        )
        assert len(result.details["events"]) == 1200
        assert result.details["statistics"]["truncated"] is False

    def test_max_events_positive_still_caps_across_pages(self):
        services = make_services()
        services.cloudtrail = self._paginated_cloudtrail(total_events=1200)

        result = AwsIRHunt(services, DredgeConfig()).lookup_events(
            user_name="alice", max_events=700,
        )
        assert len(result.details["events"]) == 700
        assert result.details["statistics"]["truncated"] is True

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


class TestLookupEventsMultiRegion:
    def _regional_services(self, events_by_region):
        services = make_services()
        clients = {}
        for region, evs in events_by_region.items():
            c = MagicMock()
            c.lookup_events.return_value = {"Events": evs, "NextToken": None}
            clients[region] = c
        services.cloudtrail_for_region.side_effect = lambda r: clients[r]
        services.resolve_enabled_regions.return_value = sorted(events_by_region)
        return services

    def test_all_regions_resolves_and_merges_time_sorted(self):
        e_new = make_event(username="newer"); e_new["EventTime"] = datetime(2024, 6, 1, tzinfo=timezone.utc)
        e_old = make_event(username="older"); e_old["EventTime"] = datetime(2024, 1, 1, tzinfo=timezone.utc)
        services = self._regional_services({"us-east-1": [e_new], "eu-west-1": [e_old]})

        res = AwsIRHunt(services, DredgeConfig()).lookup_events_multi_region(user_name="x")

        assert res.success is True
        services.resolve_enabled_regions.assert_called_once()
        assert res.details["statistics"]["regions_queried"] == 2
        assert res.details["statistics"]["total_events"] == 2
        # merged across regions and sorted by event_time ascending
        assert [e["username"] for e in res.details["events"]] == ["older", "newer"]
        assert set(res.details["by_region"]) == {"us-east-1", "eu-west-1"}

    def test_explicit_region_list_does_not_resolve_all(self):
        services = self._regional_services(
            {"us-east-1": [make_event()], "eu-west-1": [make_event()], "ap-south-1": [make_event()]}
        )
        res = AwsIRHunt(services, DredgeConfig()).lookup_events_multi_region(
            regions=["us-east-1", "eu-west-1"], user_name="x",
        )
        assert res.details["statistics"]["regions_queried"] == 2
        services.resolve_enabled_regions.assert_not_called()

    def test_per_region_error_recorded_others_still_return(self):
        c_good = MagicMock(); c_good.lookup_events.return_value = {"Events": [make_event()], "NextToken": None}
        c_bad = MagicMock(); c_bad.lookup_events.side_effect = make_client_error()
        services = make_services()
        services.cloudtrail_for_region.side_effect = lambda r: {"us-east-1": c_good, "bad-1": c_bad}[r]

        res = AwsIRHunt(services, DredgeConfig()).lookup_events_multi_region(
            regions=["us-east-1", "bad-1"], user_name="x",
        )

        assert res.success is False
        assert "error" in res.details["by_region"]["bad-1"]
        assert "error" not in res.details["by_region"]["us-east-1"]
        assert res.details["statistics"]["regions_failed"] == 1
        assert res.details["statistics"]["regions_succeeded"] == 1
        # the healthy region's event is still returned
        assert len(res.details["events"]) == 1

    def test_regions_are_deduped(self):
        c = MagicMock(); c.lookup_events.return_value = {"Events": [], "NextToken": None}
        services = make_services()
        services.cloudtrail_for_region.side_effect = lambda r: c
        res = AwsIRHunt(services, DredgeConfig()).lookup_events_multi_region(
            regions=["us-east-1", "us-east-1"], user_name="x",
        )
        assert res.details["statistics"]["regions_queried"] == 1

    def test_source_ip_sole_filter_raises(self):
        with pytest.raises(ValueError):
            AwsIRHunt(make_services(), DredgeConfig()).lookup_events_multi_region(
                regions=["us-east-1"], source_ip="1.2.3.4",
            )

    def test_no_enabled_regions_raises(self):
        services = make_services()
        services.resolve_enabled_regions.return_value = []
        with pytest.raises(ValueError):
            AwsIRHunt(services, DredgeConfig()).lookup_events_multi_region(regions="all", user_name="x")


class TestHuntCloudtrailMultiUser:
    def test_per_user_mode_groups_results_by_user_without_merging(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [
            {"Events": [make_event(username="alice")], "NextToken": None},
            {"Events": [make_event(username="bob")], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(["alice", "bob"])

        assert result.success is True
        assert set(result.details["per_user"].keys()) == {"alice", "bob"}
        assert result.details["per_user"]["alice"]["events"][0]["username"] == "alice"
        assert "events" not in result.details
        assert result.details["statistics"] == {
            "users_requested": 2,
            "users_completed": 2,
            "users_succeeded": 2,
            "users_failed": 0,
            "total_events": 2,
        }

    def test_batch_mode_merges_events_sorted_by_time(self):
        older = make_event(username="bob")
        older["EventTime"] = datetime(2024, 1, 1, tzinfo=timezone.utc)
        newer = make_event(username="alice")
        newer["EventTime"] = datetime(2024, 6, 1, tzinfo=timezone.utc)
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [
            {"Events": [newer], "NextToken": None},
            {"Events": [older], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(
            ["alice", "bob"], mode="batch",
        )

        usernames = [e["username"] for e in result.details["events"]]
        assert usernames == ["bob", "alice"]

    def test_continues_past_a_failed_user_by_default(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [
            make_client_error(),
            {"Events": [make_event(username="bob")], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(["alice", "bob"])

        assert result.success is False
        assert result.details["per_user"]["alice"]["success"] is False
        assert result.details["per_user"]["bob"]["success"] is True
        assert result.details["statistics"]["users_failed"] == 1

    def test_stop_on_error_halts_remaining_users(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [make_client_error()]
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(
            ["alice", "bob"], stop_on_error=True,
        )

        assert list(result.details["per_user"].keys()) == ["alice"]
        assert cloudtrail.lookup_events.call_count == 1

    def test_empty_users_list_raises(self):
        with pytest.raises(ValueError):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_cloudtrail_multi_user([])

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_cloudtrail_multi_user(["alice"], mode="bogus")

    def test_output_path_streams_one_jsonl_record_per_user(self, tmp_path):
        out = tmp_path / "progress.jsonl"
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = [
            {"Events": [make_event(username="alice")], "NextToken": None},
            {"Events": [make_event(username="bob")], "NextToken": None},
        ]
        services = make_services()
        services.cloudtrail = cloudtrail

        AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(
            ["alice", "bob"], output_path=str(out),
        )

        lines = out.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["user"] == "alice"
        assert json.loads(lines[1])["user"] == "bob"

    def test_output_path_creates_missing_parent_directories(self, tmp_path):
        out = tmp_path / "nested" / "dir" / "progress.jsonl"
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [make_event()], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        AwsIRHunt(services, DredgeConfig()).hunt_cloudtrail_multi_user(
            ["alice"], output_path=str(out),
        )

        assert out.exists()


class TestHuntUserActivityByIp:
    def test_classifies_events_into_expected_and_unexpected(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {
            "Events": [
                make_event(source_ip="10.0.0.5"),
                make_event(source_ip="8.8.8.8"),
            ],
            "NextToken": None,
        }
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_user_activity_by_ip(
            "alice", ["10.0.0.0/8"],
        )

        assert result.success is True
        assert len(result.details["expected_events"]) == 1
        assert result.details["expected_events"][0]["source_ip_address"] == "10.0.0.5"
        assert len(result.details["unexpected_events"]) == 1
        assert result.details["unexpected_events"][0]["source_ip_address"] == "8.8.8.8"
        assert result.details["unexpected_events"][0]["ip_allowlist_status"] == "unexpected"
        assert result.details["statistics"]["expected_count"] == 1
        assert result.details["statistics"]["unexpected_count"] == 1

    def test_non_ip_source_is_unparseable_not_unexpected(self):
        ev = make_event(source_ip="cloudtrail.amazonaws.com")
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [ev], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_user_activity_by_ip(
            "alice", ["10.0.0.0/8"],
        )

        assert result.details["unparseable_source_ip_events"][0]["source_ip_address"] == "cloudtrail.amazonaws.com"
        assert result.details["expected_events"] == []
        assert result.details["unexpected_events"] == []

    def test_missing_source_ip_is_unparseable(self):
        ev = make_event()
        ev["SourceIPAddress"] = None
        ev["CloudTrailEvent"] = json.dumps({})
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {"Events": [ev], "NextToken": None}
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_user_activity_by_ip(
            "alice", ["10.0.0.0/8"],
        )

        assert len(result.details["unparseable_source_ip_events"]) == 1

    def test_single_ip_allowlist_entry_matches_exactly(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.return_value = {
            "Events": [make_event(source_ip="1.2.3.4")], "NextToken": None,
        }
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_user_activity_by_ip(
            "alice", ["1.2.3.4"],
        )

        assert len(result.details["expected_events"]) == 1

    def test_empty_allowlist_raises(self):
        with pytest.raises(ValueError):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_user_activity_by_ip("alice", [])

    def test_invalid_allowlist_entry_raises(self):
        with pytest.raises(ValueError):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_user_activity_by_ip(
                "alice", ["not-an-ip"],
            )

    def test_underlying_lookup_errors_propagate(self):
        cloudtrail = MagicMock()
        cloudtrail.lookup_events.side_effect = make_client_error()
        services = make_services()
        services.cloudtrail = cloudtrail

        result = AwsIRHunt(services, DredgeConfig()).hunt_user_activity_by_ip(
            "alice", ["10.0.0.0/8"],
        )

        assert result.success is False
        assert result.errors


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


class TestHuntSecurityGroupsByIp:
    def test_no_ips_raises_value_error(self):
        with pytest.raises(ValueError, match="At least one IP"):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_security_groups_by_ip([])

    def test_invalid_ip_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid IP or CIDR"):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_security_groups_by_ip(["not-an-ip"])

    def test_exact_ip_in_narrow_cidr_matches(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-1",
                "GroupName": "web",
                "VpcId": "vpc-1",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "1.2.3.4/32", "Description": "bastion"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        assert result.success is True
        assert result.details["matches"][0]["group_id"] == "sg-1"
        rule = result.details["matches"][0]["matched_rules"][0]
        assert rule["direction"] == "ingress"
        assert rule["cidr"] == "1.2.3.4/32"
        assert rule["matched_targets"] == ["1.2.3.4/32"]
        assert rule["match_type"] == "explicit"

    def test_ip_covered_by_wider_cidr_matches(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-2",
                "GroupName": "internal",
                "IpPermissions": [{
                    "IpProtocol": "-1", "FromPort": None, "ToPort": None,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["10.1.2.3"])
        assert result.details["matches"][0]["group_id"] == "sg-2"

    def test_non_matching_cidr_not_flagged(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-3",
                "GroupName": "other",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "192.168.1.0/24"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        assert result.details["matches"] == []

    def test_egress_rules_are_checked(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-4",
                "GroupName": "egress-only",
                "IpPermissions": [],
                "IpPermissionsEgress": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "1.2.3.4/32"}],
                    "Ipv6Ranges": [],
                }],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        assert result.details["matches"][0]["matched_rules"][0]["direction"] == "egress"

    def test_invalid_direction_raises_value_error(self):
        with pytest.raises(ValueError, match="direction must be"):
            AwsIRHunt(make_services(), DredgeConfig()).hunt_security_groups_by_ip(
                ["1.2.3.4"], direction="sideways",
            )

    def test_ipv4_wildcard_cidr_flagged_as_wildcard(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-open",
                "GroupName": "open",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        rule = result.details["matches"][0]["matched_rules"][0]
        assert rule["match_type"] == "wildcard"

    def test_ipv6_wildcard_cidr_flagged_as_wildcard(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-open6",
                "GroupName": "open6",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["::1"])
        rule = result.details["matches"][0]["matched_rules"][0]
        assert rule["match_type"] == "wildcard"

    def test_narrower_cidr_flagged_as_explicit_not_wildcard(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-2",
                "GroupName": "internal",
                "IpPermissions": [{
                    "IpProtocol": "-1", "FromPort": None, "ToPort": None,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["10.1.2.3"])
        rule = result.details["matches"][0]["matched_rules"][0]
        assert rule["match_type"] == "explicit"

    def _sg_with_both_directions(self):
        return {"SecurityGroups": [{
            "GroupId": "sg-7",
            "GroupName": "both",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "1.2.3.4/32"}], "Ipv6Ranges": [],
            }],
            "IpPermissionsEgress": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "IpRanges": [{"CidrIp": "1.2.3.4/32"}], "Ipv6Ranges": [],
            }],
        }]}

    def test_direction_ingress_only_skips_egress(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([self._sg_with_both_directions()])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(
            ["1.2.3.4"], direction="ingress",
        )
        directions = {r["direction"] for r in result.details["matches"][0]["matched_rules"]}
        assert directions == {"ingress"}

    def test_direction_egress_only_skips_ingress(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([self._sg_with_both_directions()])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(
            ["1.2.3.4"], direction="egress",
        )
        directions = {r["direction"] for r in result.details["matches"][0]["matched_rules"]}
        assert directions == {"egress"}

    def test_direction_both_includes_ingress_and_egress(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([self._sg_with_both_directions()])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(
            ["1.2.3.4"], direction="both",
        )
        directions = {r["direction"] for r in result.details["matches"][0]["matched_rules"]}
        assert directions == {"ingress", "egress"}

    def test_ipv4_target_does_not_match_ipv6_rule(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-5",
                "GroupName": "v6",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        assert result.details["matches"] == []

    def test_cidr_input_matches_overlapping_rule(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [{
                "GroupId": "sg-6",
                "GroupName": "sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "1.2.3.0/24"}],
                    "Ipv6Ranges": [],
                }],
                "IpPermissionsEgress": [],
            }]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.0/28"])
        assert result.details["matches"][0]["group_id"] == "sg-6"

    def test_max_groups_cutoff(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"SecurityGroups": [
                {"GroupId": f"sg-{i}", "GroupName": "sg", "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "1.2.3.4/32"}], "Ipv6Ranges": [],
                }], "IpPermissionsEgress": []} for i in range(5)
            ]}
        ])
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(
            ["1.2.3.4"], max_groups=2
        )
        assert result.details["statistics"]["groups_scanned"] == 2

    def test_api_error_records_failure(self):
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.side_effect = make_client_error()
        services = make_services()
        services.ec2 = ec2

        result = AwsIRHunt(services, DredgeConfig()).hunt_security_groups_by_ip(["1.2.3.4"])
        assert result.success is False
        assert result.errors


def _empty_paginator():
    p = MagicMock()
    p.paginate.return_value = []
    return p


def _make_hunt_with_empty_services():
    services = make_services()
    for attr in ("lambda_", "ecs", "ssm", "ec2", "codebuild"):
        client = MagicMock()
        client.get_paginator.return_value = _empty_paginator()
        setattr(services, attr, client)
    return AwsIRHunt(services, DredgeConfig())


class TestHuntExposedSecrets:
    def test_unknown_scanner_raises_value_error(self):
        hunt = _make_hunt_with_empty_services()
        with pytest.raises(ValueError, match="Unknown scanner"):
            hunt.hunt_exposed_secrets(include=["not-a-scanner"])

    def test_no_findings_on_clean_environment(self):
        hunt = _make_hunt_with_empty_services()
        result = hunt.hunt_exposed_secrets()
        assert result.success is True
        assert result.details["credentials"] == []
        assert result.details["statistics"]["scanned"] == {
            "lambda": 0, "ecs": 0, "ssm": 0, "ec2_user_data": 0, "codebuild": 0,
        }

    def test_lambda_akia_sak_pair_detected(self):
        services = make_services()
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator([
            {"Functions": [{
                "FunctionName": "fn-1",
                "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:fn-1",
                "Environment": {"Variables": {
                    "AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP",
                    "AWS_SECRET_ACCESS_KEY": "a" * 40,
                    "SAFE_VAR": "just-some-config",
                }},
            }]}
        ])
        services.lambda_ = lam
        for attr in ("ecs", "ssm", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["lambda"])
        assert result.success is True
        categories = {c["category"] for c in result.details["credentials"]}
        assert categories == {"AWS Access Key", "AWS Secret Access Key"}
        for c in result.details["credentials"]:
            assert c["sources"][0]["location_type"] == "lambda_env"
            assert c["sources"][0]["resource_id"] == "fn-1"
        assert "raw_values" not in result.details

    def test_ssm_generic_secret_via_key_name_heuristic(self):
        services = make_services()
        ssm = MagicMock()
        ssm.get_paginator.return_value = _make_paginator([
            {"Parameters": [{"Name": "/app/db_password", "ARN": "arn:aws:ssm:::parameter/app/db_password"}]}
        ])
        ssm.get_parameters.return_value = {
            "Parameters": [{"Name": "/app/db_password", "Value": "sup3r-s3cret-value-123"}]
        }
        services.ssm = ssm
        for attr in ("lambda_", "ecs", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ssm"])
        assert len(result.details["credentials"]) == 1
        finding = result.details["credentials"][0]
        assert finding["category"] == "Generic Secret"
        assert finding["detection_method"] == "key_name_heuristic"
        assert finding["sources"][0]["location_type"] == "ssm_parameter"

    def test_keep_raw_returns_plaintext(self):
        services = make_services()
        ssm = MagicMock()
        ssm.get_paginator.return_value = _make_paginator([
            {"Parameters": [{"Name": "/app/api_key", "ARN": "arn"}]}
        ])
        ssm.get_parameters.return_value = {
            "Parameters": [{"Name": "/app/api_key", "Value": "sup3r-s3cret-value-123"}]
        }
        services.ssm = ssm
        for attr in ("lambda_", "ecs", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(
            include=["ssm"], keep_raw=True,
        )
        h = result.details["credentials"][0]["hash"]
        assert result.details["raw_values"][h] == "sup3r-s3cret-value-123"

    def test_placeholder_value_not_flagged(self):
        services = make_services()
        ssm = MagicMock()
        ssm.get_paginator.return_value = _make_paginator([
            {"Parameters": [{"Name": "/app/password", "ARN": "arn"}]}
        ])
        ssm.get_parameters.return_value = {
            "Parameters": [{"Name": "/app/password", "Value": "changeme"}]
        }
        services.ssm = ssm
        for attr in ("lambda_", "ecs", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ssm"])
        assert result.details["credentials"] == []

    def test_ec2_user_data_scanned_line_by_line(self):
        import base64

        services = make_services()
        ec2 = MagicMock()
        ec2.get_paginator.return_value = _make_paginator([
            {"Reservations": [{"Instances": [{"InstanceId": "i-123"}]}]}
        ])
        script = "#!/bin/bash\nexport GITHUB_TOKEN=" + "gh" + "p_" + "x" * 36
        ec2.describe_instance_attribute.return_value = {
            "UserData": {"Value": base64.b64encode(script.encode()).decode()}
        }
        services.ec2 = ec2
        for attr in ("lambda_", "ecs", "ssm", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ec2_user_data"])
        assert len(result.details["credentials"]) == 1
        assert result.details["credentials"][0]["category"] == "GitHub Token"
        assert result.details["credentials"][0]["sources"][0]["resource_id"] == "i-123"

    def test_scan_error_recorded_but_does_not_abort(self):
        services = make_services()
        lam = MagicMock()
        lam.get_paginator.return_value.paginate.side_effect = make_client_error()
        services.lambda_ = lam
        for attr in ("ecs", "ssm", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets()
        assert result.success is False
        assert result.details["scan_errors"]
        assert result.details["credentials"] == []

    def test_test_pairs_attaches_live_result(self):
        services = make_services()
        lam = MagicMock()
        lam.get_paginator.return_value = _make_paginator([
            {"Functions": [{
                "FunctionName": "fn-1",
                "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:fn-1",
                "Environment": {"Variables": {
                    "AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP",
                    "AWS_SECRET_ACCESS_KEY": "a" * 40,
                }},
            }]}
        ])
        services.lambda_ = lam
        for attr in ("ecs", "ssm", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        fake_result = {"status": "live", "tested_at": "now", "caller_arn": "arn:aws:iam::111111111111:user/leaked"}
        with patch("dredge.aws_ir.hunt.verify_aws_key_pair", return_value=fake_result) as mock_verify:
            result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(
                include=["lambda"], test_pairs=True,
            )

        mock_verify.assert_called_once_with("AKIAABCDEFGHIJKLMNOP", "a" * 40)
        for c in result.details["credentials"]:
            assert c["live_test_result"] == fake_result
        # test_pairs implicitly needs raw values in-flight but shouldn't leak them out
        assert "raw_values" not in result.details

    def test_ecs_task_env_akia_sak_pair_detected(self):
        services = make_services()
        ecs = MagicMock()
        ecs.get_paginator.return_value = _make_paginator([
            {"taskDefinitionArns": ["arn:aws:ecs:us-east-1:1:task-definition/app:3"]}
        ])
        ecs.describe_task_definition.return_value = {
            "taskDefinition": {
                "containerDefinitions": [{
                    "name": "web",
                    "environment": [
                        {"name": "AWS_ACCESS_KEY_ID", "value": "AKIAABCDEFGHIJKLMNOP"},
                        {"name": "AWS_SECRET_ACCESS_KEY", "value": "b" * 40},
                    ],
                }],
            }
        }
        services.ecs = ecs
        for attr in ("lambda_", "ssm", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ecs"])
        assert result.details["statistics"]["scanned"]["ecs"] == 1
        categories = {c["category"] for c in result.details["credentials"]}
        assert categories == {"AWS Access Key", "AWS Secret Access Key"}
        for c in result.details["credentials"]:
            assert c["sources"][0]["location_type"] == "ecs_task_env"
            assert c["sources"][0]["resource_id"] == "arn:aws:ecs:us-east-1:1:task-definition/app:3::web"

    def test_ecs_collapses_to_latest_revision_per_family(self):
        services = make_services()
        ecs = MagicMock()
        ecs.get_paginator.return_value = _make_paginator([
            {"taskDefinitionArns": [
                "arn:aws:ecs:us-east-1:1:task-definition/app:1",
                "arn:aws:ecs:us-east-1:1:task-definition/app:2",
            ]}
        ])
        ecs.describe_task_definition.return_value = {"taskDefinition": {"containerDefinitions": []}}
        services.ecs = ecs
        for attr in ("lambda_", "ssm", "ec2", "codebuild"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ecs"])
        ecs.describe_task_definition.assert_called_once_with(
            taskDefinition="arn:aws:ecs:us-east-1:1:task-definition/app:2"
        )

    def test_codebuild_plaintext_env_secret_detected(self):
        services = make_services()
        cb = MagicMock()
        cb.get_paginator.return_value = _make_paginator([{"projects": ["proj-1"]}])
        cb.batch_get_projects.return_value = {
            "projects": [{
                "name": "proj-1",
                "arn": "arn:aws:codebuild:us-east-1:1:project/proj-1",
                "environment": {"environmentVariables": [
                    {"name": "DEPLOY_TOKEN", "value": "gh" + "p_" + "y" * 36, "type": "PLAINTEXT"},
                    {"name": "SKIP_ME", "value": "sk_live_" + "z" * 24, "type": "PARAMETER_STORE"},
                ]},
            }]
        }
        services.codebuild = cb
        for attr in ("lambda_", "ecs", "ssm", "ec2"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["codebuild"])
        assert len(result.details["credentials"]) == 1
        finding = result.details["credentials"][0]
        assert finding["category"] == "GitHub Token"
        assert finding["sources"][0]["location_type"] == "codebuild_env"
        assert finding["sources"][0]["resource_id"] == "proj-1"

    def test_ecs_and_codebuild_api_errors_recorded(self):
        services = make_services()
        ecs = MagicMock()
        ecs.get_paginator.return_value.paginate.side_effect = make_client_error()
        cb = MagicMock()
        cb.get_paginator.return_value.paginate.side_effect = make_client_error()
        services.ecs = ecs
        services.codebuild = cb
        for attr in ("lambda_", "ssm", "ec2"):
            client = MagicMock()
            client.get_paginator.return_value = _empty_paginator()
            setattr(services, attr, client)

        result = AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(include=["ecs", "codebuild"])
        assert result.success is False
        assert any("ecs:" in e for e in result.details["scan_errors"])
        assert any("codebuild:" in e for e in result.details["scan_errors"])


def _write_json(path, obj):
    import json as _json
    path.write_text(_json.dumps(obj))


def _make_ct_record(**overrides):
    record = {
        "eventTime": "2026-08-25T12:00:00Z",
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "185.69.122.229",
        "userAgent": "aws-cli",
        "recipientAccountId": "111111111111",
        "userIdentity": {
            "accountId": "111111111111",
            "arn": "arn:aws:sts::111111111111:assumed-role/Admin/bob",
            "accessKeyId": "AKIAABCDEFGHIJKLMNOP",
        },
    }
    record.update(overrides)
    return record


class TestQueryLocalCloudtrailLogs:
    def test_no_matching_files_records_error(self, tmp_path):
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        assert result.success is False
        assert result.details["events"] == []

    def test_single_file_path_accepted(self, tmp_path):
        f = tmp_path / "file1.json"
        _write_json(f, {"Records": [_make_ct_record()]})

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(f))
        assert result.success is True
        assert len(result.details["events"]) == 1

    def test_default_fields_projected(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [_make_ct_record()]})

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        ev = result.details["events"][0]
        assert set(ev.keys()) == set(AwsIRHunt._DEFAULT_QUERY_FIELDS)
        assert ev["userIdentity.accountId"] == "111111111111"
        assert ev["userIdentity.arn"] == "arn:aws:sts::111111111111:assumed-role/Admin/bob"

    def test_custom_fields_projected(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [_make_ct_record()]})

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), fields=["eventName", "sourceIPAddress"],
        )
        assert result.details["events"][0] == {
            "eventName": "GetObject", "sourceIPAddress": "185.69.122.229",
        }

    def test_bare_list_shape_accepted(self, tmp_path):
        _write_json(tmp_path / "file1.json", [_make_ct_record()])

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        assert len(result.details["events"]) == 1

    def test_single_record_dict_shape_accepted(self, tmp_path):
        _write_json(tmp_path / "file1.json", _make_ct_record())

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        assert len(result.details["events"]) == 1

    def test_gzip_file_read(self, tmp_path):
        import gzip

        payload = json.dumps({"Records": [_make_ct_record()]}).encode()
        with gzip.open(tmp_path / "file1.json.gz", "wb") as fh:
            fh.write(payload)

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        assert len(result.details["events"]) == 1

    def test_malformed_file_recorded_but_others_still_scanned(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json{{{")
        _write_json(tmp_path / "good.json", {"Records": [_make_ct_record()]})

        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        assert result.success is False
        assert len(result.details["events"]) == 1
        assert any("bad.json" in f for f in result.details["failed_files"])

    def test_source_ip_filter(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(sourceIPAddress="1.1.1.1"),
            _make_ct_record(sourceIPAddress="2.2.2.2"),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), source_ip="2.2.2.2",
        )
        assert len(result.details["events"]) == 1

    def test_event_name_and_event_source_and_region_filters(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(eventName="PutObject", eventSource="s3.amazonaws.com", awsRegion="us-east-1"),
            _make_ct_record(eventName="GetObject", eventSource="s3.amazonaws.com", awsRegion="eu-west-1"),
        ]})
        hunt = AwsIRHunt(make_services(), DredgeConfig())

        r1 = hunt.query_local_cloudtrail_logs(str(tmp_path), event_name="PutObject")
        assert len(r1.details["events"]) == 1

        r2 = hunt.query_local_cloudtrail_logs(str(tmp_path), aws_region="eu-west-1")
        assert len(r2.details["events"]) == 1

    def test_access_key_id_filter(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(userIdentity={"accessKeyId": "AKIA1"}),
            _make_ct_record(userIdentity={"accessKeyId": "AKIA2"}),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), access_key_id="AKIA2",
        )
        assert len(result.details["events"]) == 1

    def test_user_name_matches_exact_username(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(userIdentity={"userName": "alice", "arn": "arn:aws:iam::1:user/alice"}),
            _make_ct_record(userIdentity={"userName": "bob", "arn": "arn:aws:iam::1:user/bob"}),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), user_name="alice",
        )
        assert len(result.details["events"]) == 1

    def test_user_name_matches_substring_of_assumed_role_arn(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(userIdentity={"arn": "arn:aws:sts::1:assumed-role/Admin/bob"}),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), user_name="bob",
        )
        assert len(result.details["events"]) == 1

    def test_account_id_matches_recipient_account_id_fallback(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(userIdentity={}, recipientAccountId="222222222222"),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), account_id="222222222222",
        )
        assert len(result.details["events"]) == 1

    def test_time_range_filter(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(eventTime="2026-08-25T10:00:00Z"),
            _make_ct_record(eventTime="2026-08-25T14:00:00Z"),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path),
            start_time=datetime(2026, 8, 25, 12, tzinfo=timezone.utc),
        )
        assert len(result.details["events"]) == 1
        assert result.details["events"][0]["eventTime"] == "2026-08-25T14:00:00Z"

    def test_results_sorted_by_event_time_ascending(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(eventTime="2026-08-25T14:00:00Z", eventName="Later"),
            _make_ct_record(eventTime="2026-08-25T10:00:00Z", eventName="Earlier"),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(str(tmp_path))
        names = [e["eventName"] for e in result.details["events"]]
        assert names == ["Earlier", "Later"]

    def test_max_events_caps_results(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [_make_ct_record() for _ in range(5)]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), max_events=2,
        )
        assert len(result.details["events"]) == 2
        assert result.details["statistics"]["records_matched"] == 2

    def test_ir_filter_keeps_only_dangerous_events(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(eventName="GetObject"),            # benign, dropped
            _make_ct_record(eventName="StopLogging"),          # anti-forensics
            _make_ct_record(eventName="CreateAccessKey"),      # persistence
            _make_ct_record(eventName="DescribeInstances"),    # benign, dropped
            _make_ct_record(eventName="GetSecretValue"),       # credential access
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), ir=True,
        )
        names = sorted(ev["eventName"] for ev in result.details["events"])
        assert names == ["CreateAccessKey", "GetSecretValue", "StopLogging"]
        assert result.details["statistics"]["records_scanned"] == 5

    def test_ir_filter_combines_with_other_filters(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [
            _make_ct_record(eventName="StopLogging", sourceIPAddress="1.1.1.1"),
            _make_ct_record(eventName="CreateAccessKey", sourceIPAddress="2.2.2.2"),
        ]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), ir=True, source_ip="2.2.2.2",
        )
        assert [ev["eventName"] for ev in result.details["events"]] == ["CreateAccessKey"]

    def test_ir_flag_recorded_in_target(self, tmp_path):
        _write_json(tmp_path / "file1.json", {"Records": [_make_ct_record(eventName="StopLogging")]})
        result = AwsIRHunt(make_services(), DredgeConfig()).query_local_cloudtrail_logs(
            str(tmp_path), ir=True,
        )
        assert "ir=true" in result.target

    def test_ir_dangerous_event_set_is_curated_and_bounded(self):
        names = AwsIRHunt._IR_DANGEROUS_EVENT_NAMES
        # "top 50" -- keep the list tight and high-signal.
        assert 0 < len(names) <= 50
        # No duplicates across categories.
        flat = [n for names_ in AwsIRHunt._IR_DANGEROUS_EVENTS.values() for n in names_]
        assert len(flat) == len(set(flat))
        assert len(names) == len(flat)


class TestIncidentLocalCloudtrailLogs:
    def _hunt(self):
        return AwsIRHunt(make_services(), DredgeConfig())

    def test_no_matching_files_records_error(self, tmp_path):
        result = self._hunt().incident_local_cloudtrail_logs(str(tmp_path))
        assert result.success is False
        assert result.details["findings"] == []
        assert result.details["severity_counts"] == {}

    def test_dangerous_only_ranked_by_category_severity(self, tmp_path):
        # No IOCs: only the curated dangerous events, ranked by base severity.
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="GetObject"),          # benign -> dropped
            _make_ct_record(eventName="GetSecretValue"),     # credential-access 70
            _make_ct_record(eventName="StopLogging"),        # anti-forensics 90
            _make_ct_record(eventName="CreateAccessKey"),    # persistence 80
            _make_ct_record(eventName="GetCallerIdentity"),  # discovery 30
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(str(tmp_path))
        findings = result.details["findings"]
        # Benign non-dangerous, non-IOC record is not surfaced.
        assert [f["eventName"] for f in findings] == [
            "StopLogging", "CreateAccessKey", "GetSecretValue", "GetCallerIdentity",
        ]
        assert [f["severity_score"] for f in findings] == [90, 80, 70, 30]
        assert [f["severity"] for f in findings] == ["HIGH", "HIGH", "HIGH", "LOW"]
        assert all(f["ioc_match"] is False for f in findings)
        assert result.details["statistics"]["records_scanned"] == 5

    def test_ioc_overlap_outranks_plain_dangerous_event(self, tmp_path):
        # The user's example: CreateAccessKey from a flagged IP must outrank a
        # GetSecretValue by an unremarkable role -- both reported, ranked.
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="GetSecretValue", sourceIPAddress="10.0.0.9",
                            userIdentity={"arn": "arn:aws:sts::111:assumed-role/eks/pod"}),
            _make_ct_record(eventName="CreateAccessKey", sourceIPAddress="1.2.3.4",
                            userIdentity={"arn": "arn:aws:iam::111:user/mallory",
                                          "userName": "mallory"}),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_ips=["1.2.3.4"],
        )
        findings = result.details["findings"]
        assert findings[0]["eventName"] == "CreateAccessKey"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["ioc_match"] is True
        assert findings[0]["severity_score"] == 180  # 80 + 100 overlap boost
        assert findings[1]["eventName"] == "GetSecretValue"
        assert findings[1]["severity"] == "HIGH"
        assert findings[1]["ioc_match"] is False

    def test_ioc_only_non_dangerous_event_surfaced_as_context(self, tmp_path):
        # A non-dangerous call by an IOC is still reported, at low priority.
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="DescribeInstances", sourceIPAddress="1.2.3.4"),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_ips=["1.2.3.4"],
        )
        findings = result.details["findings"]
        assert len(findings) == 1
        assert findings[0]["eventName"] == "DescribeInstances"
        assert findings[0]["category"] == "ioc-related"
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["severity_score"] == 40

    def test_non_dangerous_non_ioc_record_dropped(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="GetObject", sourceIPAddress="8.8.8.8"),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_ips=["1.2.3.4"],
        )
        assert result.details["findings"] == []
        assert result.details["statistics"]["records_scanned"] == 1

    def test_ioc_ip_cidr_match(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="CreateAccessKey", sourceIPAddress="1.2.3.55"),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_ips=["1.2.3.0/24"],
        )
        assert result.details["findings"][0]["ioc_match"] is True
        assert "ioc-ip:1.2.3.55" in result.details["findings"][0]["reasons"]

    def test_ioc_user_matches_arn_substring(self, tmp_path):
        # Assumed-role sessions have no userName; match on the ARN substring.
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="RunInstances",
                            userIdentity={"arn": "arn:aws:sts::111:assumed-role/eks-workload/pod"}),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_users=["eks-workload"],
        )
        f = result.details["findings"][0]
        assert f["ioc_match"] is True
        assert "ioc-user:eks-workload" in f["reasons"]

    def test_ioc_user_matches_access_key_id(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="GetSecretValue",
                            userIdentity={"accessKeyId": "AKIACOMPROMISED"}),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_users=["AKIACOMPROMISED"],
        )
        assert result.details["findings"][0]["ioc_match"] is True

    def test_time_window_bounds_records(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="StopLogging", eventTime="2026-08-25T10:00:00Z"),
            _make_ct_record(eventName="StopLogging", eventTime="2026-08-25T20:00:00Z"),
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path),
            start_time=datetime(2026, 8, 25, 15, 0, tzinfo=timezone.utc),
        )
        assert len(result.details["findings"]) == 1
        assert result.details["findings"][0]["eventTime"] == "2026-08-25T20:00:00Z"

    def test_max_findings_keeps_highest_severity(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="GetCallerIdentity"),  # 30
            _make_ct_record(eventName="StopLogging"),        # 90
            _make_ct_record(eventName="GetSecretValue"),     # 70
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), max_findings=2,
        )
        findings = result.details["findings"]
        assert [f["eventName"] for f in findings] == ["StopLogging", "GetSecretValue"]

    def test_severity_counts_and_iocs_recorded(self, tmp_path):
        _write_json(tmp_path / "f.json", {"Records": [
            _make_ct_record(eventName="StopLogging", sourceIPAddress="1.2.3.4"),  # CRITICAL
            _make_ct_record(eventName="GetSecretValue"),                          # HIGH
        ]})
        result = self._hunt().incident_local_cloudtrail_logs(
            str(tmp_path), ioc_ips=["1.2.3.4"], ioc_users=["nobody"],
        )
        assert result.details["severity_counts"] == {"CRITICAL": 1, "HIGH": 1}
        assert result.details["iocs"] == {"ips": ["1.2.3.4"], "users": ["nobody"]}

    def test_severity_label_thresholds(self):
        label = AwsIRHunt._severity_label
        assert label(190) == "CRITICAL"
        assert label(150) == "CRITICAL"
        assert label(90) == "HIGH"
        assert label(70) == "HIGH"
        assert label(40) == "MEDIUM"
        assert label(30) == "LOW"
        assert label(0) == "LOW"
