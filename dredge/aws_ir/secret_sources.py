"""Additional secret sources; detectors are supplied by AwsIRHunt.

Content sources never discover buckets or log groups. Budgets apply across all
explicit targets in a source, including failed requests and empty result pages.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

AWS_ERRORS = (ClientError, BotoCoreError)
CONFIG_SCANNERS = ("elasticbeanstalk", "apprunner", "batch", "glue", "amplify")


def _error(errors, source, exc):
    # Do not copy service error messages: they may echo sensitive request data.
    code = exc.response.get("Error", {}).get("Code", "ClientError") if isinstance(exc, ClientError) else type(exc).__name__
    errors.append(f"{source}: {code}")


class ConfigurationScanner:
    def __init__(self, client, emit, errors):
        self.client, self.emit, self.errors = client, emit, errors
        self.scanned = 0

    def scan(self, name):
        try:
            getattr(self, name)()
        except AWS_ERRORS as exc:
            _error(self.errors, name, exc)
        return self.scanned

    def items(self, method, key, **kwargs):
        for page in self.client.get_paginator(method).paginate(**kwargs):
            yield from page.get(key, [])

    def bag(self, values, location, resource, arn="", **extra):
        self.emit({k: str(v) for k, v in (values or {}).items()}, {
            "location_type": location, "resource_id": resource,
            "resource_arn": arn, **extra,
        })

    def elasticbeanstalk(self):
        for env in self.items("describe_environments", "Environments", IncludeDeleted=False):
            try:
                response = self.client.describe_configuration_settings(
                    ApplicationName=env["ApplicationName"], EnvironmentName=env["EnvironmentName"],
                )
                self.scanned += 1
                for config in response.get("ConfigurationSettings", []):
                    self.bag({o["OptionName"]: o.get("Value", "") for o in config.get("OptionSettings", [])
                              if o.get("Namespace") == "aws:elasticbeanstalk:application:environment"},
                             "elasticbeanstalk_env", env["EnvironmentName"], env.get("EnvironmentArn", ""))
            except AWS_ERRORS as exc:
                _error(self.errors, "elasticbeanstalk", exc)

    def apprunner(self):
        request, seen = {}, set()
        while True:
            page = self.client.list_services(**request)
            for summary in page.get("ServiceSummaryList", []):
                try:
                    service = self.client.describe_service(ServiceArn=summary["ServiceArn"])["Service"]
                    self.scanned += 1
                    source = service.get("SourceConfiguration", {})
                    image = source.get("ImageRepository", {}).get("ImageConfiguration", {})
                    code = source.get("CodeRepository", {}).get("CodeConfiguration", {}).get("CodeConfigurationValues", {})
                    for config in (image, code):
                        # RuntimeEnvironmentSecrets contains references, not plaintext.
                        self.bag(config.get("RuntimeEnvironmentVariables"), "apprunner_env",
                                 summary.get("ServiceName", summary["ServiceArn"]), summary["ServiceArn"])
                except AWS_ERRORS as exc:
                    _error(self.errors, "apprunner", exc)
            token = page.get("NextToken")
            if not token:
                break
            if token in seen:
                self.errors.append("apprunner: repeated pagination token")
                break
            seen.add(token)
            request = {"NextToken": token}

    def batch(self):
        def containers(value, path=""):
            # Covers legacy containers, multi-node, ECS taskProperties, and EKS
            # containers/initContainers without inspecting secret references.
            if isinstance(value, dict):
                env = value.get("environment", value.get("env"))
                if isinstance(env, list):
                    yield path, {e["name"]: e["value"] for e in env if "value" in e}
                for key, child in value.items():
                    if key not in ("environment", "env", "secrets", "secretOptions"):
                        yield from containers(child, f"{path}.{key}".lstrip("."))
            elif isinstance(value, list):
                for i, child in enumerate(value):
                    yield from containers(child, f"{path}[{i}]")

        for job in self.items("describe_job_definitions", "jobDefinitions", status="ACTIVE"):
            self.scanned += 1
            arn = job["jobDefinitionArn"]
            self.bag(job.get("parameters"), "batch_parameters", arn, arn)
            for path, env in containers(job):
                self.bag(env, "batch_env", f"{arn}::{path}", arn, scope=path)

    def glue(self):
        for job in self.items("get_jobs", "Jobs"):
            self.scanned += 1
            # Scan both maps so overridden but still exposed defaults are found.
            for field_name in ("DefaultArguments", "NonOverridableArguments"):
                self.bag(job.get(field_name), "glue_job_arguments", job["Name"], scope=field_name)

    def amplify(self):
        for app in self.items("list_apps", "apps"):
            self.scanned += 1
            self.bag(app.get("environmentVariables"), "amplify_app_env", app["appId"], app.get("appArn", ""))
            self.bag(app.get("autoBranchCreationConfig", {}).get("environmentVariables"),
                     "amplify_auto_branch_env", app["appId"], app.get("appArn", ""))
            try:
                for branch in self.items("list_branches", "branches", appId=app["appId"]):
                    self.scanned += 1
                    self.bag(branch.get("environmentVariables"), "amplify_branch_env",
                             f'{app["appId"]}/{branch["branchName"]}', branch.get("branchArn", ""))
            except AWS_ERRORS as exc:
                _error(self.errors, "amplify", exc)


def validate_content_options(s3_targets, log_groups, start, end, **limits):
    for name, value in limits.items():
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    for target in s3_targets:
        if not isinstance(target, str) or not re.fullmatch(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[^*?]+", target):
            raise ValueError("scan_s3 requires s3://bucket/nonempty-prefix (no wildcards)")
        if not target.split("/", 3)[3].strip("/ "):
            raise ValueError("scan_s3 requires a nonempty object prefix; bucket-wide scans are disabled")
    for group in log_groups:
        if not isinstance(group, str) or not re.fullmatch(r"[.\-_/#A-Za-z0-9]{1,512}", group):
            raise ValueError("scan_cloudwatch requires explicit log group names (no wildcards)")
    if log_groups:
        if not all(isinstance(t, datetime) and t.utcoffset() is not None for t in (start, end)):
            raise ValueError("CloudWatch scanning requires timezone-aware start_time and end_time")
        if not timedelta(0) < end - start <= timedelta(hours=24):
            raise ValueError("CloudWatch scan window must be greater than zero and at most 24 hours")
    elif start is not None or end is not None:
        raise ValueError("start_time/end_time require scan_cloudwatch targets")


@dataclass
class ContentBudget:
    max_calls: int
    max_bytes: int
    max_seconds: int
    started: float = field(default_factory=time.monotonic)
    calls: int = 0
    bytes_read: int = 0
    bytes_reserved: int = 0
    scanned: int = 0
    examined: int = 0
    skipped: int = 0
    reasons: list = field(default_factory=list)

    def stop(self, reason):
        if reason not in self.reasons:
            self.reasons.append(reason)

    def request(self):
        if self.calls >= self.max_calls:
            self.stop("max_api_calls")
        if time.monotonic() - self.started >= self.max_seconds:
            self.stop("max_seconds")
        if self.bytes_reserved >= self.max_bytes:
            self.stop("max_bytes")
        if self.reasons:
            return False
        self.calls += 1
        return True

    def summary(self):
        return {
            "scanned": self.scanned, "examined": self.examined, "skipped": self.skipped,
            "api_calls": self.calls, "bytes_read": self.bytes_read,
            "bytes_budgeted": self.bytes_reserved, "truncated": bool(self.reasons),
            "stop_reasons": self.reasons,
            "limits": {"max_api_calls": self.max_calls, "max_bytes": self.max_bytes,
                       "max_seconds": self.max_seconds},
        }


def scan_s3(client, targets, emit_text, errors, budget, max_objects, max_object_bytes):
    seen_objects = set()
    for target in dict.fromkeys(targets):
        bucket_name, prefix = target[5:].split("/", 1)
        request = {"Bucket": bucket_name, "Prefix": prefix}
        seen_tokens = set()
        while True:
            if budget.examined >= max_objects:
                budget.stop("max_objects")
                return
            if not budget.request():
                return
            try:
                page = client.list_objects_v2(**request, MaxKeys=min(1000, max_objects - budget.examined))
            except AWS_ERRORS as exc:
                _error(errors, "s3", exc)
                break
            for obj in page.get("Contents", []):
                if budget.examined >= max_objects:
                    budget.stop("max_objects")
                    return
                budget.examined += 1
                key, size = obj["Key"], obj.get("Size", 0)
                identity = (bucket_name, key)
                if identity in seen_objects:
                    budget.skipped += 1
                    continue
                seen_objects.add(identity)
                # No archive restores or decompression; only complete small text
                # objects. Oversized objects aren't silently treated as clean.
                if size <= 0 or size > max_object_bytes or obj.get("StorageClass") in {"GLACIER", "DEEP_ARCHIVE"}:
                    budget.skipped += 1
                    continue
                if size > budget.max_bytes - budget.bytes_reserved:
                    budget.stop("max_bytes")
                    return
                if not budget.request():
                    return
                budget.bytes_reserved += size
                try:
                    response = client.get_object(Bucket=bucket_name, Key=key, Range=f"bytes=0-{size - 1}",
                                                 **({"IfMatch": obj["ETag"]} if obj.get("ETag") else {}))
                    body = response["Body"]
                    try:
                        data = body.read(size)
                    finally:
                        body.close()
                    budget.bytes_read += len(data)
                    if len(data) != size:
                        errors.append("s3: incomplete object body")
                        continue
                    if response.get("ContentEncoding") not in (None, "", "identity") or b"\x00" in data:
                        budget.skipped += 1
                        continue
                    try:
                        content = data.decode("utf-8")
                    except UnicodeDecodeError:
                        budget.skipped += 1
                        continue
                    emit_text(content, {"location_type": "s3_object", "resource_id": f"s3://{bucket_name}/{key}"})
                    budget.scanned += 1
                except (ClientError, BotoCoreError, OSError) as exc:
                    _error(errors, "s3", exc)
            token = page.get("NextContinuationToken")
            if not page.get("IsTruncated"):
                break
            if not token or token in seen_tokens:
                budget.stop("pagination_stalled")
                return
            seen_tokens.add(token)
            request["ContinuationToken"] = token


def scan_cloudwatch(client, groups, start, end, stream_prefix, emit_text, errors, budget, max_events):
    for group in dict.fromkeys(groups):
        request = {"logGroupName": group, "startTime": int(start.timestamp() * 1000),
                   "endTime": int(end.timestamp() * 1000)}
        if stream_prefix:
            request["logStreamNamePrefix"] = stream_prefix
        seen_tokens = set()
        while True:
            if budget.examined >= max_events:
                budget.stop("max_events")
                return
            if not budget.request():
                return
            try:
                page = client.filter_log_events(**request, limit=min(1000, max_events - budget.examined))
            except AWS_ERRORS as exc:
                _error(errors, "cloudwatch", exc)
                break
            for event in page.get("events", []):
                if budget.examined >= max_events:
                    budget.stop("max_events")
                    return
                budget.examined += 1
                message = event.get("message", "")
                size = len(message.encode("utf-8"))
                if size > budget.max_bytes - budget.bytes_reserved:
                    budget.stop("max_bytes")
                    return
                budget.bytes_reserved += size
                budget.bytes_read += size
                emit_text(message, {
                    "location_type": "cloudwatch_log_event",
                    "resource_id": f'{group}::{event.get("logStreamName", "")}::{event.get("eventId", budget.examined)}',
                    "log_group": group, "log_stream": event.get("logStreamName", ""),
                    "timestamp": event.get("timestamp"), "event_id": event.get("eventId", ""),
                })
                budget.scanned += 1
            token = page.get("nextToken")
            if not token:
                break
            if token in seen_tokens:
                budget.stop("pagination_stalled")
                return
            seen_tokens.add(token)
            request["nextToken"] = token
