"""Secret-source coverage, opt-in boundaries, and aggregate content budgets."""
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from dredge.aws_ir.hunt import AwsIRHunt
from dredge.aws_ir.secret_sources import CONFIG_SCANNERS
from dredge.config import DredgeConfig

TOKEN = "ghp_" + "aB7" * 12
OTHER_TOKEN = "ghp_" + "cD9" * 12
PAIR = {"AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP", "AWS_SECRET_ACCESS_KEY": "aB7/" * 10}
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOW = {"start_time": START, "end_time": START + timedelta(hours=1)}


@pytest.fixture
def services():
    result = MagicMock()
    for name in ("lambda_", "ecs", "ssm", "ec2", "codebuild", *CONFIG_SCANNERS):
        getattr(result, name).get_paginator.return_value.paginate.return_value = []
    result.apprunner.list_services.return_value = {}
    return result


def hunt(services, **kwargs):
    return AwsIRHunt(services, DredgeConfig()).hunt_exposed_secrets(**kwargs)


def denied():
    return ClientError({"Error": {"Code": "AccessDenied", "Message": TOKEN}}, "Scan")


def pages(client, *responses):
    client.get_paginator.return_value.paginate.return_value = list(responses)


def credentials(result):
    assert TOKEN not in json.dumps(result.details)
    return result.details["credentials"]


def test_defaults_include_new_configs_without_touching_content(services):
    result = hunt(services)
    assert result.success
    assert set(CONFIG_SCANNERS) <= result.details["statistics"]["scanned"].keys()
    assert services.s3.mock_calls == []
    assert services.logs.mock_calls == []


def test_beanstalk_pagination_pairs_and_secret_references(services):
    pages(services.elasticbeanstalk,
          {"Environments": [{"ApplicationName": "app", "EnvironmentName": "bad"}]},
          {"Environments": [{"ApplicationName": "app", "EnvironmentName": "prod"}]})
    services.elasticbeanstalk.describe_configuration_settings.side_effect = [denied(), {
        "ConfigurationSettings": [{"OptionSettings": [
            {"Namespace": "aws:elasticbeanstalk:application:environment", "OptionName": k, "Value": v}
            for k, v in PAIR.items()
        ] + [{"Namespace": "aws:elasticbeanstalk:application:environmentsecrets",
              "OptionName": "TOKEN", "Value": TOKEN}]}]}]
    result = hunt(services, include=["elasticbeanstalk"])
    assert not result.success
    assert result.details["scan_errors"] == ["elasticbeanstalk: AccessDenied"]
    assert len(credentials(result)) == 2
    assert result.details["statistics"]["scanned"] == {"elasticbeanstalk": 1}
    services.elasticbeanstalk.get_paginator.return_value.paginate.assert_called_once_with(IncludeDeleted=False)


def test_apprunner_image_and_code_paginate_and_skip_references(services):
    services.apprunner.list_services.side_effect = [
        {"ServiceSummaryList": [{"ServiceArn": "image"}], "NextToken": "next"},
        {"ServiceSummaryList": [{"ServiceArn": "code"}]},
    ]
    services.apprunner.describe_service.side_effect = [
        {"Service": {"SourceConfiguration": {"ImageRepository": {"ImageConfiguration": {
            "RuntimeEnvironmentVariables": {"TOKEN": TOKEN}, "RuntimeEnvironmentSecrets": {"TOKEN": OTHER_TOKEN},
        }}}}},
        {"Service": {"SourceConfiguration": {"CodeRepository": {"CodeConfiguration": {
            "CodeConfigurationValues": {"RuntimeEnvironmentVariables": {"TOKEN": TOKEN}},
        }}}}},
    ]
    result = hunt(services, include=["apprunner"])
    assert result.success
    assert len(credentials(result)) == 1
    assert len(credentials(result)[0]["sources"]) == 2
    assert result.details["statistics"]["scanned"]["apprunner"] == 2
    assert services.apprunner.list_services.call_args.kwargs == {"NextToken": "next"}


def test_apprunner_recovers_from_one_service_failure(services):
    services.apprunner.list_services.return_value = {"ServiceSummaryList": [{"ServiceArn": "bad"}, {"ServiceArn": "ok"}]}
    services.apprunner.describe_service.side_effect = [denied(), {"Service": {}}]
    result = hunt(services, include=["apprunner"])
    assert not result.success
    assert result.details["statistics"]["scanned"]["apprunner"] == 1


@pytest.mark.parametrize("properties", [
    {"containerProperties": {"environment": [{"name": "TOKEN", "value": TOKEN}]}},
    {"nodeProperties": {"nodeRangeProperties": [{"container": {"environment": [{"name": "TOKEN", "value": TOKEN}]}}]}},
    {"ecsProperties": {"taskProperties": [{"containers": [{"environment": [{"name": "TOKEN", "value": TOKEN}]}]}]}},
    {"eksProperties": {"podProperties": {"containers": [{"env": [{"name": "TOKEN", "value": TOKEN}]}],
                                        "initContainers": [{"env": [{"name": "REF", "valueFrom": {"secretKeyRef": "reference"}}]}]}}},
    {"parameters": {"TOKEN": TOKEN}},
])
def test_batch_all_job_definition_shapes(services, properties):
    pages(services.batch, {"jobDefinitions": [{"jobDefinitionArn": "job:1", **properties}]},
          {"jobDefinitions": [{"jobDefinitionArn": "job:2", "containerProperties": {"secrets": [{"name": "TOKEN", "valueFrom": OTHER_TOKEN}]}}]})
    result = hunt(services, include=["batch"])
    assert len(credentials(result)) == 1
    assert result.details["statistics"]["scanned"]["batch"] == 2
    services.batch.get_paginator.return_value.paginate.assert_called_once_with(status="ACTIVE")


def test_glue_checks_both_argument_maps(services):
    pages(services.glue, {"Jobs": [{"Name": "job", "DefaultArguments": {"--token": TOKEN},
                                   "NonOverridableArguments": {"--token": OTHER_TOKEN}}]})
    result = hunt(services, include=["glue"])
    assert len(credentials(result)) == 2
    assert {c["sources"][0]["scope"] for c in credentials(result)} == {"DefaultArguments", "NonOverridableArguments"}


def test_amplify_app_auto_branch_and_branches_with_partial_failure(services):
    apps = services.amplify.get_paginator.return_value
    apps.paginate.side_effect = [
        [{"apps": [{"appId": "bad", "environmentVariables": {"TOKEN": TOKEN}},
                   {"appId": "good", "autoBranchCreationConfig": {"environmentVariables": {"TOKEN": TOKEN}}}]}],
        denied(),
        [{"branches": [{"branchName": "main", "environmentVariables": {"TOKEN": TOKEN}}]}, {"branches": []}],
    ]
    result = hunt(services, include=["amplify"])
    assert not result.success
    assert len(credentials(result)) == 1
    assert len(credentials(result)[0]["sources"]) == 3
    assert result.details["statistics"]["scanned"]["amplify"] == 3


@pytest.mark.parametrize("name", CONFIG_SCANNERS)
@pytest.mark.parametrize("exc", [denied(), EndpointConnectionError(endpoint_url="https://example.invalid")])
def test_configuration_list_failure_isolated(services, name, exc):
    client = getattr(services, name)
    client.get_paginator.return_value.paginate.side_effect = exc
    client.list_services.side_effect = exc
    result = hunt(services, include=[name])
    assert not result.success
    assert len(result.details["scan_errors"]) == 1
    credentials(result)


def s3_object(key="config/.env", data=None, **extra):
    data = data if data is not None else f"TOKEN={TOKEN}".encode()
    return {"Key": key, "Size": len(data), "ETag": '"etag"', **extra}


def s3_scan(services, **kwargs):
    return hunt(services, include=[], scan_s3=["s3://bucket/config/"], **kwargs)


def test_s3_prefix_range_close_redaction_and_json_pair(services):
    data = json.dumps({"auth": PAIR, "nested": [{"token": TOKEN}]}).encode()
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object(data=data)]}
    body = io.BytesIO(data)
    services.s3.get_object.return_value = {"Body": body}
    result = s3_scan(services)
    assert result.success
    assert len(credentials(result)) == 3
    assert body.closed
    services.s3.list_objects_v2.assert_called_once_with(Bucket="bucket", Prefix="config/", MaxKeys=100)
    services.s3.get_object.assert_called_once_with(Bucket="bucket", Key="config/.env",
                                                  Range=f"bytes=0-{len(data)-1}", IfMatch='"etag"')
    assert result.details["content_scans"]["s3"]["bytes_read"] == len(data)
    assert result.details["statistics"]["scanned"] == {"s3": 1}


def test_s3_object_cap_includes_skipped_objects_and_stops_pagination(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object(Size=2000000)],
                                               "IsTruncated": True, "NextContinuationToken": "more"}
    result = s3_scan(services, s3_max_objects=1)
    summary = result.details["content_scans"]["s3"]
    assert summary["stop_reasons"] == ["max_objects"]
    assert summary["skipped"] == 1
    services.s3.get_object.assert_not_called()
    assert services.s3.list_objects_v2.call_count == 1


def test_s3_byte_budget_prevents_get(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object()]}
    result = s3_scan(services, content_max_bytes=10)
    assert result.details["content_scans"]["s3"]["stop_reasons"] == ["max_bytes"]
    services.s3.get_object.assert_not_called()


def test_s3_pagination_and_failed_download_do_not_lose_findings(services):
    data = f"TOKEN={TOKEN}".encode()
    services.s3.list_objects_v2.side_effect = [
        {"Contents": [s3_object("config/bad")], "IsTruncated": True, "NextContinuationToken": "more"},
        {"Contents": [s3_object("config/good")]},
    ]
    services.s3.get_object.side_effect = [denied(), {"Body": io.BytesIO(data)}]
    result = s3_scan(services)
    assert not result.success
    assert len(credentials(result)) == 1
    assert services.s3.list_objects_v2.call_args.kwargs["ContinuationToken"] == "more"


@pytest.mark.parametrize("data,extra", [(b"\xff\xfe", {}), (b"a\x00b", {}), (b"compressed", {"ContentEncoding": "gzip"})])
def test_s3_non_text_skipped_and_body_closed(services, data, extra):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object(data=data)]}
    body = io.BytesIO(data)
    services.s3.get_object.return_value = {"Body": body, **extra}
    result = s3_scan(services)
    assert body.closed
    assert result.details["content_scans"]["s3"]["skipped"] == 1
    assert credentials(result) == []


def test_s3_archive_skipped_without_restore(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object(StorageClass="GLACIER")]}
    s3_scan(services)
    services.s3.get_object.assert_not_called()
    services.s3.restore_object.assert_not_called()


def test_s3_aggregate_cap_applies_across_targets(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object(Size=0)]}
    result = hunt(services, include=[], scan_s3=["s3://bucket/a", "s3://bucket/b"], s3_max_objects=1)
    assert services.s3.list_objects_v2.call_count == 1
    assert result.details["content_scans"]["s3"]["truncated"]


def log_event(message=TOKEN, event_id="event"):
    return {"message": message, "eventId": event_id, "timestamp": int(START.timestamp()*1000), "logStreamName": "stream"}


def cloudwatch_scan(services, **kwargs):
    return hunt(services, include=[], scan_cloudwatch=["/aws/app"], **WINDOW, **kwargs)


def test_cloudwatch_empty_pages_continue_and_limits_are_server_side(services):
    services.logs.filter_log_events.side_effect = [
        {"events": [], "nextToken": "next"},
        {"events": [log_event(f"logged token: {TOKEN}")]},
    ]
    result = cloudwatch_scan(services, cloudwatch_stream_prefix="prod/")
    assert result.success
    assert len(credentials(result)) == 1
    request = services.logs.filter_log_events.call_args.kwargs
    assert request == {"logGroupName": "/aws/app", "startTime": int(START.timestamp()*1000),
                       "endTime": int((START+timedelta(hours=1)).timestamp()*1000),
                       "logStreamNamePrefix": "prod/", "limit": 1000, "nextToken": "next"}
    assert "message" not in credentials(result)[0]["sources"][0]
    services.logs.start_query.assert_not_called()
    services.logs.describe_log_groups.assert_not_called()


def test_cloudwatch_event_limit_stops_further_pages(services):
    services.logs.filter_log_events.return_value = {"events": [log_event()], "nextToken": "next"}
    result = cloudwatch_scan(services, cloudwatch_max_events=1)
    assert services.logs.filter_log_events.call_count == 1
    assert services.logs.filter_log_events.call_args.kwargs["limit"] == 1
    assert result.details["content_scans"]["cloudwatch"]["stop_reasons"] == ["max_events"]


def test_cloudwatch_does_not_combine_credentials_from_different_events(services):
    services.logs.filter_log_events.return_value = {"events": [
        log_event(json.dumps({"AWS_ACCESS_KEY_ID": PAIR["AWS_ACCESS_KEY_ID"]}), "first"),
        log_event(json.dumps({"AWS_SECRET_ACCESS_KEY": PAIR["AWS_SECRET_ACCESS_KEY"]}), "second"),
    ]}
    with patch("dredge.aws_ir.hunt.verify_aws_key_pair") as verify:
        cloudwatch_scan(services, test_pairs=True)
    verify.assert_not_called()


def test_cloudwatch_api_cap_counts_empty_pages(services):
    services.logs.filter_log_events.return_value = {"events": [], "nextToken": "next"}
    result = cloudwatch_scan(services, content_max_api_calls=1)
    assert result.details["content_scans"]["cloudwatch"]["stop_reasons"] == ["max_api_calls"]
    assert services.logs.filter_log_events.call_count == 1


def test_cloudwatch_byte_cap(services):
    services.logs.filter_log_events.return_value = {"events": [log_event()]}
    result = cloudwatch_scan(services, content_max_bytes=2)
    assert result.details["content_scans"]["cloudwatch"]["stop_reasons"] == ["max_bytes"]
    assert credentials(result) == []


@pytest.mark.parametrize("source", ["s3", "cloudwatch"])
def test_repeated_tokens_stop_without_spinning(services, source):
    if source == "s3":
        services.s3.list_objects_v2.return_value = {"Contents": [], "IsTruncated": True, "NextContinuationToken": "again"}
        result = s3_scan(services)
    else:
        services.logs.filter_log_events.return_value = {"events": [], "nextToken": "again"}
        result = cloudwatch_scan(services)
    assert result.details["content_scans"][source]["stop_reasons"] == ["pagination_stalled"]
    assert result.details["content_scans"][source]["api_calls"] == 2


@pytest.mark.parametrize("source", ["s3", "cloudwatch"])
def test_elapsed_budget_stops_requests(services, source):
    with patch("dredge.aws_ir.secret_sources.time.monotonic", return_value=1e20):
        result = s3_scan(services) if source == "s3" else cloudwatch_scan(services)
    assert result.details["content_scans"][source]["stop_reasons"] == ["max_seconds"]
    assert services.s3.mock_calls == []
    assert services.logs.mock_calls == []


@pytest.mark.parametrize("options", [
    {"scan_s3": ["s3://bucket/"]}, {"scan_s3": ["s3://bucket"]},
    {"scan_s3": ["s3://bucket/*"]}, {"scan_s3": "s3://bucket/path"},
    {"scan_cloudwatch": ["*"]}, {"scan_cloudwatch": ["/aws/app"]},
    {"scan_cloudwatch": ["/aws/app"], "start_time": START, "end_time": START},
    {"scan_cloudwatch": ["/aws/app"], "start_time": START, "end_time": START+timedelta(days=2)},
    {"scan_cloudwatch": ["/aws/app"], "start_time": START.replace(tzinfo=None), "end_time": START},
    {"start_time": START}, {"cloudwatch_stream_prefix": "prod/"},
    *[{name: 0} for name in ("s3_max_objects", "s3_max_object_bytes", "cloudwatch_max_events",
                            "content_max_bytes", "content_max_api_calls", "content_max_seconds")],
])
def test_invalid_content_options_rejected_before_any_aws_calls(services, options):
    with pytest.raises(ValueError):
        hunt(services, **options)
    assert services.mock_calls == []


def test_target_errors_preserve_other_content_sources(services):
    services.s3.list_objects_v2.side_effect = denied()
    services.logs.filter_log_events.return_value = {"events": [log_event()]}
    result = hunt(services, include=[], scan_s3=["s3://bucket/config/"], scan_cloudwatch=["/aws/app"], **WINDOW)
    assert not result.success
    assert len(credentials(result)) == 1
    assert result.details["statistics"]["scanned"] == {"s3": 0, "cloudwatch": 1}


def test_content_raw_values_and_live_pair_check_are_explicit(services):
    services.logs.filter_log_events.return_value = {"events": [log_event(json.dumps(PAIR))]}
    with patch("dredge.aws_ir.hunt.verify_aws_key_pair", return_value={"status": "live"}) as verify:
        result = cloudwatch_scan(services, test_pairs=True, keep_raw=True)
    verify.assert_called_once_with(PAIR["AWS_ACCESS_KEY_ID"], PAIR["AWS_SECRET_ACCESS_KEY"])
    assert set(result.details["raw_values"].values()) == set(PAIR.values())
    assert all(c["live_test_result"] == {"status": "live"} for c in result.details["credentials"])


def test_pair_checks_do_not_cross_batch_containers(services):
    env = lambda bag: [{"name": k, "value": v} for k, v in bag.items()]
    second_pair = {"AWS_ACCESS_KEY_ID": "AKIAQRSTUVWXYZABCDEF", "AWS_SECRET_ACCESS_KEY": "cD9/" * 10}
    pages(services.batch, {"jobDefinitions": [{"jobDefinitionArn": "job:1", "ecsProperties": {
        "taskProperties": [{"containers": [{"environment": env(PAIR)}, {"environment": env(second_pair)}]}],
    }}]})
    with patch("dredge.aws_ir.hunt.verify_aws_key_pair", return_value={"status": "live"}) as verify:
        hunt(services, include=["batch"], test_pairs=True)
    assert {c.args for c in verify.call_args_list} == {tuple(PAIR.values()), tuple(second_pair.values())}


def test_content_extracts_multiple_tokens_and_full_pem(services):
    pem = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
    services.logs.filter_log_events.return_value = {"events": [log_event(f"{TOKEN} {OTHER_TOKEN}\n{pem}")]}
    result = cloudwatch_scan(services, keep_raw=True)
    assert set(result.details["raw_values"].values()) == {TOKEN, OTHER_TOKEN, pem}


def test_s3_incomplete_body_is_failure_and_is_closed(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object()]}
    body = io.BytesIO(b"short")
    services.s3.get_object.return_value = {"Body": body}
    result = s3_scan(services)
    assert not result.success
    assert body.closed
    assert result.details["scan_errors"] == ["s3: incomplete object body"]


def test_cloudwatch_failure_in_one_group_does_not_stop_next_group(services):
    services.logs.filter_log_events.side_effect = [denied(), {"events": [log_event()]}]
    result = hunt(services, include=[], scan_cloudwatch=["bad", "good"], **WINDOW)
    assert not result.success
    assert len(credentials(result)) == 1


def test_s3_overlapping_prefixes_do_not_download_twice(services):
    services.s3.list_objects_v2.return_value = {"Contents": [s3_object()]}
    services.s3.get_object.return_value = {"Body": io.BytesIO(f"TOKEN={TOKEN}".encode())}
    result = hunt(services, include=[], scan_s3=["s3://bucket/config", "s3://bucket/config/"])
    assert services.s3.get_object.call_count == 1
    assert result.details["content_scans"]["s3"]["skipped"] == 1


def test_apprunner_stalled_pagination_reports_failure(services):
    services.apprunner.list_services.return_value = {"NextToken": "again"}
    result = hunt(services, include=["apprunner"])
    assert not result.success
    assert services.apprunner.list_services.call_count == 2


@pytest.mark.parametrize("value", [f"https://{TOKEN}@api.example.com/path", f"arn:aws:service:region:123:{TOKEN}"])
def test_structured_content_never_preserves_token_in_url_or_arn_prefix(services, value):
    services.logs.filter_log_events.return_value = {"events": [log_event(json.dumps({"value": value}))]}
    result = cloudwatch_scan(services)
    assert credentials(result)
