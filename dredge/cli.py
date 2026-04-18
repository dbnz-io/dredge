#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import csv
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from typing import Optional

# Library imports – adjust if your package paths differ
from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig
from dredge.github_ir.config import GitHubIRConfig

from importlib.metadata import version, PackageNotFoundError
# ------------- helpers -------------


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    # Allow 'Z' suffix
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime format: {value}. Use ISO 8601, e.g. 2025-01-01T12:00:00+00:00"
        )


def print_result(result, output: str = "json") -> None:
    """
    Print an OperationResult in the desired format.

    output: "json" (default) or "csv"
    """
    # Normalise to a dict first
    try:
        data = asdict(result)
    except TypeError:
        data = result

    if output == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    if output == "csv":
        # Try to find a list-like payload to tabularise
        details = data.get("details", {}) if isinstance(data, dict) else {}
        events = None

        # Common hunt payload keys
        for key in ("events", "entries", "results"):
            if isinstance(details.get(key), list):
                events = details[key]
                break

        # If we don't have a sensible list, fall back to JSON
        if not events:
            print(json.dumps(data, indent=2, default=str))
            return

        # Collect all fieldnames across events
        fieldnames = set()
        for ev in events:
            if isinstance(ev, dict):
                fieldnames.update(ev.keys())

        fieldnames = sorted(fieldnames)

        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            if isinstance(ev, dict):
                writer.writerow(ev)
            else:
                # Best effort: dump non-dict as a single 'value' column
                writer.writerow({"value": str(ev)})

        return

    # Fallback if an unknown output format sneaks in
    print(json.dumps(data, indent=2, default=str))



def build_aws_auth_from_args(args: argparse.Namespace) -> Optional[AwsAuthConfig]:
    # If nothing is set, return None (Dredge will use default AWS chain)
    if not any(
        [
            args.aws_profile,
            args.aws_access_key_id,
            args.aws_secret_access_key,
            args.aws_session_token,
            args.aws_role_arn,
        ]
    ):
        return None

    return AwsAuthConfig(
        access_key_id=args.aws_access_key_id,
        secret_access_key=args.aws_secret_access_key,
        session_token=args.aws_session_token,
        profile_name=args.aws_profile,
        role_arn=args.aws_role_arn,
        external_id=args.aws_external_id,
        region_name=args.aws_region,
    )


def build_github_config_from_args(args: argparse.Namespace) -> Optional[GitHubIRConfig]:
    if not args.github_org and not args.github_enterprise:
        return None

    return GitHubIRConfig(
        org=args.github_org,
        enterprise=args.github_enterprise,
        token=args.github_token or None,
    )


# ------------- AWS command handlers -------------


def handle_aws_disable_access_key(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_access_key(
        user_name=args.user,
        access_key_id=args.access_key_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_delete_access_key(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.delete_access_key(
        user_name=args.user,
        access_key_id=args.access_key_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_user(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_user(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_delete_user(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.delete_user(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_role(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_role(args.role)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_account(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_public_access(
        account_id=args.account_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_bucket(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_bucket_public_access(
        bucket_name=args.bucket,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_object(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_object_public_access(
        bucket_name=args.bucket,
        key=args.key,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_isolate_ec2(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.isolate_ec2_instances(
        instance_ids=args.instance_ids,
        vpc_id=args.vpc_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_cloudtrail(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    # Relative ranges
    if args.week_ago or args.month_ago:
        start, end = compute_relative_range(
            weeks_ago=args.week_ago,
            months_ago=args.month_ago,
        )
    else:
        if args.today:
            now = datetime.now(timezone.utc)
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        else:
            start = parse_iso_datetime(args.start_time)
            end = parse_iso_datetime(args.end_time)

    res = dredge.aws_ir.hunt.lookup_events(
        user_name=args.user,
        access_key_id=args.access_key_id,
        event_name=args.event_name,
        source_ip=args.source_ip,
        start_time=start,
        end_time=end,
        max_events=args.max_events,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_delete_mfa_devices(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.delete_mfa_devices(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_revoke_active_sessions(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.revoke_active_sessions(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_stop_ec2(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.stop_ec2_instances(args.instance_ids)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_terminate_ec2(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.terminate_ec2_instances(
        args.instance_ids,
        snapshot_first=args.snapshot_first,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_nacl_cidrs(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_nacl_cidrs(
        vpc_id=args.vpc_id,
        cidrs=args.cidrs,
        rule_number_start=args.rule_number_start,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_lambda(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_lambda_function(args.function_name)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_kms_key(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_kms_key(args.key_id)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_schedule_kms_deletion(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.schedule_kms_key_deletion(
        args.key_id,
        pending_window_days=args.pending_window_days,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_tag_resources(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    tags = dict(t.split("=", 1) for t in (args.tags_raw or []))
    res = dredge.aws_ir.response.tag_resources(
        resource_arns=args.resource_arns,
        tags=tags,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_guardduty(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.list_guardduty_findings(
        detector_id=args.detector_id,
        severity_min=args.severity_min,
        max_findings=args.max_findings,
        finding_types=args.finding_types or None,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_isolate_rds(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.isolate_rds_instance(args.db_instance_id)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_stop_ecs_service(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.stop_ecs_service(args.cluster, args.service)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_stop_ecs_task(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.stop_ecs_task(args.cluster, args.task_id)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_secret(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_secrets_manager_secret(
        args.secret_id,
        recovery_window_days=args.recovery_window_days,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_eventbridge_rule(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_eventbridge_rule(
        args.rule_name,
        event_bus_name=args.event_bus_name,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_terminate_ssm_sessions(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.terminate_ssm_sessions(args.instance_id)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_detach_iam_policy(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.detach_iam_policy(
        args.policy_arn,
        user_name=getattr(args, "user_name", None) or None,
        role_name=getattr(args, "role_name", None) or None,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_quarantine_s3_bucket(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.quarantine_s3_bucket(
        args.bucket_name,
        account_id=getattr(args, "account_id", None) or None,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_security_hub(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_security_hub_findings(
        severity_labels=args.severity_labels or None,
        workflow_status=args.workflow_status or None,
        product_name=getattr(args, "product_name", None) or None,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
        max_findings=args.max_findings,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_access_analyzer(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_access_analyzer_findings(
        args.analyzer_arn,
        status=getattr(args, "status", None) or None,
        resource_type=getattr(args, "resource_type", None) or None,
        max_findings=args.max_findings,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_config_history(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_config_resource_history(
        args.resource_type,
        args.resource_id,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
        max_items=args.max_items,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_iam_credential_report(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.get_iam_credential_report()
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_enable_vpc_flow_logs(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.forensics.enable_vpc_flow_logs(
        args.vpc_id,
        log_group_name=args.log_group_name,
        deliver_logs_permission_arn=getattr(args, "deliver_logs_permission_arn", None) or None,
        log_destination_type=args.log_destination_type,
        log_destination=getattr(args, "log_destination", None) or None,
        traffic_type=args.traffic_type,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_ssm_session_history(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.forensics.capture_ssm_session_history(
        instance_id=getattr(args, "instance_id", None) or None,
        owner=getattr(args, "owner", None) or None,
        max_sessions=args.max_sessions,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_cloudtrail_status(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.forensics.get_cloudtrail_status(
        include_shadow_trails=args.include_shadow_trails,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_cloudwatch_logs(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_cloudwatch_logs(
        log_group=args.log_group,
        query=args.query,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
        max_results=args.max_results,
        poll_interval=args.poll_interval,
        max_wait_seconds=args.max_wait_seconds,
    )
    print_result(res, output=getattr(args, "output", "json"))


# ------------- GitHub command handlers -------------


def handle_github_hunt_audit(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)  # optional; might be unused
    github_cfg = build_github_config_from_args(args)
    if github_cfg is None:
        raise SystemExit("You must provide --github-org or --github-enterprise")

    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
        github_config=github_cfg,
    )

    if dredge.github_ir is None:
        raise SystemExit("GitHub IR not configured")

    if args.today:
        start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        end = datetime.now(timezone.utc)

    elif args.week_ago or args.month_ago:
        start, end = compute_relative_range(
            weeks_ago=args.week_ago,
            months_ago=args.month_ago,
        )

    else:
        start = parse_iso_datetime(args.start_time)
        end = parse_iso_datetime(args.end_time)

    res = dredge.github_ir.hunt.search_audit_log(
        actor=args.actor,
        action=args.action,
        repo=args.repo,
        source_ip=args.source_ip,
        start_time=start,
        end_time=end,
        include=args.include,
        max_events=args.max_events,
    )

    print_result(res, output=getattr(args, "output", "json"))


# ------------- GitHub response/hunt/forensics handlers -------------


def _github_dredge(args: argparse.Namespace):
    """Build a Dredge instance with GitHub config, raising SystemExit if unconfigured."""
    github_cfg = build_github_config_from_args(args)
    if github_cfg is None:
        raise SystemExit("You must provide --github-org")
    auth = build_aws_auth_from_args(args)
    return Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
        github_config=github_cfg,
    )


def handle_github_block_org_member(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.block_org_member(args.username), output=getattr(args, "output", "json"))


def handle_github_remove_org_member(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.remove_org_member(args.username), output=getattr(args, "output", "json"))


def handle_github_remove_repo_collaborator(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.remove_repo_collaborator(args.repo, args.username), output=getattr(args, "output", "json"))


def handle_github_revoke_deploy_key(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.revoke_deploy_key(args.repo, args.key_id), output=getattr(args, "output", "json"))


def handle_github_delete_org_webhook(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.delete_org_webhook(args.hook_id), output=getattr(args, "output", "json"))


def handle_github_delete_repo_webhook(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.delete_repo_webhook(args.repo, args.hook_id), output=getattr(args, "output", "json"))


def handle_github_archive_repository(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.response.archive_repository(args.repo), output=getattr(args, "output", "json"))


def handle_github_hunt_secret_scanning(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.hunt.hunt_secret_scanning_alerts(
        getattr(args, "repo", None) or None,
        state=args.state,
        max_alerts=args.max_alerts,
    ), output=getattr(args, "output", "json"))


def handle_github_hunt_code_scanning(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.hunt.hunt_code_scanning_alerts(
        args.repo,
        state=args.state,
        max_alerts=args.max_alerts,
    ), output=getattr(args, "output", "json"))


def handle_github_list_org_members(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.hunt.list_org_members(
        role=getattr(args, "role", None) or None,
        max_members=args.max_members,
    ), output=getattr(args, "output", "json"))


def handle_github_list_outside_collaborators(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.hunt.list_outside_collaborators(
        max_items=args.max_items,
    ), output=getattr(args, "output", "json"))


def handle_github_list_deploy_keys(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.hunt.list_deploy_keys(
        args.repo,
        max_keys=args.max_keys,
    ), output=getattr(args, "output", "json"))


def handle_github_forensics_org_settings(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.get_org_settings(), output=getattr(args, "output", "json"))


def handle_github_forensics_repo_metadata(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.get_repo_metadata(args.repo), output=getattr(args, "output", "json"))


def handle_github_forensics_repo_collaborators(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.list_repo_collaborators(
        args.repo,
        max_items=args.max_items,
    ), output=getattr(args, "output", "json"))


def handle_github_forensics_branch_protection(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.get_branch_protection(args.repo, args.branch), output=getattr(args, "output", "json"))


def handle_github_forensics_org_webhooks(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.list_org_webhooks(), output=getattr(args, "output", "json"))


def handle_github_forensics_repo_webhooks(args: argparse.Namespace) -> None:
    d = _github_dredge(args)
    print_result(d.github_ir.forensics.list_repo_webhooks(args.repo), output=getattr(args, "output", "json"))


# ------------- argparse wiring -------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dredge-cli",
        description="Dredge incident response CLI (AWS + GitHub)",
    )

    # Global / AWS options
    parser.add_argument(
        "--aws-region", "--region",
        dest="aws_region",
        help="AWS region (e.g. us-east-1)",
        default=None,
    )    
    parser.add_argument("--aws-profile", help="AWS profile name", default=None)
    parser.add_argument("--aws-access-key-id", default=None)
    parser.add_argument("--aws-secret-access-key", default=None)
    parser.add_argument("--aws-session-token", default=None)
    parser.add_argument("--aws-role-arn", default=None)
    parser.add_argument("--aws-external-id", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not make changes, only simulate (where supported)",
    )

    # GitHub-global options (used when github subcommands are run)
    parser.add_argument("--github-org", default=None, help="GitHub organization slug")
    parser.add_argument("--github-enterprise", default=None, help="GitHub enterprise slug")
    parser.add_argument(
        "--github-token",
        default=None,
        help="GitHub token (otherwise uses env var configured in GitHubIRConfig)",
    )

    # --version flag
    try:
        dredge_version = version("dredge")
    except PackageNotFoundError:
        dredge_version = "development"

    parser.add_argument(
        "--version",
        action="version",
        version=f"dredge {dredge_version}",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- AWS response subcommands ---

    p = subparsers.add_parser("aws-disable-access-key", help="Disable an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_disable_access_key)

    p = subparsers.add_parser("aws-delete-access-key", help="Delete an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_delete_access_key)

    p = subparsers.add_parser("aws-disable-user", help="Disable an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_disable_user)

    p = subparsers.add_parser("aws-delete-user", help="Delete an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_delete_user)

    p = subparsers.add_parser("aws-disable-role", help="Disable an IAM role")
    p.add_argument("--role", required=True, help="IAM role name")
    p.set_defaults(func=handle_aws_disable_role)

    p = subparsers.add_parser(
        "aws-block-s3-account", help="Block S3 public access at account level"
    )
    p.add_argument("--account-id", required=True, help="AWS account ID")
    p.set_defaults(func=handle_aws_block_s3_account)

    p = subparsers.add_parser(
        "aws-block-s3-bucket", help="Make an S3 bucket private / block public access"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.set_defaults(func=handle_aws_block_s3_bucket)

    p = subparsers.add_parser(
        "aws-block-s3-object", help="Make a specific S3 object private"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.add_argument("--key", required=True, help="Object key")
    p.set_defaults(func=handle_aws_block_s3_object)

    p = subparsers.add_parser(
        "aws-isolate-ec2", help="Network-isolate EC2 instances (forensic SG)"
    )
    p.add_argument(
        "instance_ids",
        nargs="+",
        help="One or more EC2 instance IDs",
    )
    p.add_argument(
        "--vpc-id",
        default=None,
        help="Optional VPC ID (otherwise inferred from first instance)",
    )
    p.set_defaults(func=handle_aws_isolate_ec2)

    p = subparsers.add_parser("aws-delete-mfa-devices", help="Deactivate and delete MFA devices for a user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_delete_mfa_devices)

    p = subparsers.add_parser("aws-revoke-active-sessions", help="Invalidate active sessions for a user via deny policy")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_revoke_active_sessions)

    p = subparsers.add_parser("aws-stop-ec2", help="Stop EC2 instances (can be restarted)")
    p.add_argument("instance_ids", nargs="+", help="One or more EC2 instance IDs")
    p.set_defaults(func=handle_aws_stop_ec2)

    p = subparsers.add_parser("aws-terminate-ec2", help="Terminate EC2 instances (snapshot EBS volumes first by default)")
    p.add_argument("instance_ids", nargs="+", help="One or more EC2 instance IDs")
    p.add_argument(
        "--no-snapshot",
        dest="snapshot_first",
        action="store_false",
        help="Skip EBS snapshots before termination",
    )
    p.set_defaults(func=handle_aws_terminate_ec2, snapshot_first=True)

    p = subparsers.add_parser("aws-block-nacl-cidrs", help="Add DENY rules for CIDRs to all NACLs in a VPC")
    p.add_argument("--vpc-id", required=True, help="VPC ID")
    p.add_argument(
        "--cidr",
        dest="cidrs",
        action="append",
        required=True,
        help="CIDR to block (repeat for multiple, e.g. --cidr 1.2.3.4/32 --cidr 5.6.7.8/32)",
    )
    p.add_argument("--rule-number-start", type=int, default=1, help="Starting rule number (default 1)")
    p.set_defaults(func=handle_aws_block_nacl_cidrs)

    p = subparsers.add_parser("aws-disable-lambda", help="Throttle a Lambda function to zero concurrency")
    p.add_argument("--function-name", required=True, help="Lambda function name or ARN")
    p.set_defaults(func=handle_aws_disable_lambda)

    p = subparsers.add_parser("aws-disable-kms-key", help="Disable a KMS key")
    p.add_argument("--key-id", required=True, help="KMS key ID or ARN")
    p.set_defaults(func=handle_aws_disable_kms_key)

    p = subparsers.add_parser("aws-schedule-kms-deletion", help="Schedule a KMS key for deletion")
    p.add_argument("--key-id", required=True, help="KMS key ID or ARN")
    p.add_argument(
        "--pending-window-days",
        type=int,
        default=7,
        help="Days before deletion (7–30, default 7)",
    )
    p.set_defaults(func=handle_aws_schedule_kms_deletion)

    p = subparsers.add_parser("aws-tag-resources", help="Apply tags to AWS resources by ARN")
    p.add_argument(
        "--arn",
        dest="resource_arns",
        action="append",
        required=True,
        help="Resource ARN (repeat for multiple)",
    )
    p.add_argument(
        "--tag",
        dest="tags_raw",
        action="append",
        required=True,
        help="Tag in Key=Value format (repeat for multiple)",
    )
    p.set_defaults(func=handle_aws_tag_resources)

    p = subparsers.add_parser("aws-hunt-guardduty", help="List GuardDuty findings")
    p.add_argument("--detector-id", required=True, help="GuardDuty detector ID")
    p.add_argument("--severity-min", type=float, default=0.0, help="Minimum severity (0.0–8.9, default 0.0)")
    p.add_argument("--max-findings", type=int, default=100, help="Maximum findings to return")
    p.add_argument(
        "--finding-type",
        dest="finding_types",
        action="append",
        default=None,
        help="Filter by finding type (repeat for multiple)",
    )
    p.add_argument("--start-time", default=None, help="Filter updatedAt >= this time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="Filter updatedAt <= this time (ISO 8601)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_aws_hunt_guardduty)

    p = subparsers.add_parser("aws-isolate-rds", help="Isolate an RDS instance (empty SG, disable public access)")
    p.add_argument("db_instance_id", help="RDS DB instance identifier")
    p.set_defaults(func=handle_aws_isolate_rds)

    p = subparsers.add_parser("aws-stop-ecs-service", help="Scale an ECS service to 0 desired tasks")
    p.add_argument("cluster", help="ECS cluster name or ARN")
    p.add_argument("service", help="ECS service name or ARN")
    p.set_defaults(func=handle_aws_stop_ecs_service)

    p = subparsers.add_parser("aws-stop-ecs-task", help="Force-stop a running ECS task")
    p.add_argument("cluster", help="ECS cluster name or ARN")
    p.add_argument("task_id", help="ECS task ID or ARN")
    p.set_defaults(func=handle_aws_stop_ecs_task)

    p = subparsers.add_parser("aws-disable-secret", help="Schedule a Secrets Manager secret for deletion")
    p.add_argument("secret_id", help="Secret ID or ARN")
    p.add_argument("--recovery-window-days", type=int, default=7, dest="recovery_window_days",
                   help="Days before permanent deletion (7–30, default 7)")
    p.set_defaults(func=handle_aws_disable_secret)

    p = subparsers.add_parser("aws-disable-eventbridge-rule", help="Disable an EventBridge rule")
    p.add_argument("rule_name", help="EventBridge rule name")
    p.add_argument("--event-bus-name", default="default", dest="event_bus_name",
                   help="Event bus name (default: default)")
    p.set_defaults(func=handle_aws_disable_eventbridge_rule)

    p = subparsers.add_parser("aws-terminate-ssm-sessions", help="Terminate all active SSM sessions on an instance")
    p.add_argument("instance_id", help="EC2 instance ID")
    p.set_defaults(func=handle_aws_terminate_ssm_sessions)

    p = subparsers.add_parser("aws-detach-iam-policy", help="Detach a managed policy from a user or role")
    p.add_argument("policy_arn", help="Policy ARN to detach")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--user-name", dest="user_name", help="IAM user name")
    group.add_argument("--role-name", dest="role_name", help="IAM role name")
    p.set_defaults(func=handle_aws_detach_iam_policy)

    p = subparsers.add_parser("aws-quarantine-s3-bucket", help="Block public access and apply deny-all policy to an S3 bucket")
    p.add_argument("bucket_name", help="S3 bucket name")
    p.add_argument("--account-id", dest="account_id", help="AWS account ID (auto-detected if omitted)")
    p.set_defaults(func=handle_aws_quarantine_s3_bucket)

    p = subparsers.add_parser("aws-hunt-security-hub", help="Query Security Hub findings")
    p.add_argument("--severity-label", dest="severity_labels", action="append",
                   help="Severity label filter (e.g. HIGH, CRITICAL); repeatable")
    p.add_argument("--workflow-status", dest="workflow_status", action="append",
                   help="Workflow status filter (e.g. NEW, NOTIFIED); repeatable")
    p.add_argument("--product-name", dest="product_name", help="Product name filter (e.g. GuardDuty)")
    p.add_argument("--start-time", dest="start_time", help="ISO 8601 start time")
    p.add_argument("--end-time", dest="end_time", help="ISO 8601 end time")
    p.add_argument("--max-findings", type=int, default=100, dest="max_findings")
    p.set_defaults(func=handle_aws_hunt_security_hub)

    p = subparsers.add_parser("aws-hunt-access-analyzer", help="List IAM Access Analyzer findings")
    p.add_argument("analyzer_arn", help="Access Analyzer ARN")
    p.add_argument("--status", help="Finding status filter: ACTIVE, ARCHIVED, RESOLVED")
    p.add_argument("--resource-type", dest="resource_type", help="Resource type filter (e.g. AWS::S3::Bucket)")
    p.add_argument("--max-findings", type=int, default=100, dest="max_findings")
    p.set_defaults(func=handle_aws_hunt_access_analyzer)

    p = subparsers.add_parser("aws-hunt-config-history", help="Get AWS Config resource configuration history")
    p.add_argument("resource_type", help="Resource type (e.g. AWS::EC2::Instance)")
    p.add_argument("resource_id", help="Resource ID")
    p.add_argument("--start-time", dest="start_time", help="ISO 8601 start time")
    p.add_argument("--end-time", dest="end_time", help="ISO 8601 end time")
    p.add_argument("--max-items", type=int, default=100, dest="max_items")
    p.set_defaults(func=handle_aws_hunt_config_history)

    p = subparsers.add_parser("aws-iam-credential-report", help="Generate and retrieve IAM credential report")
    p.set_defaults(func=handle_aws_iam_credential_report)

    p = subparsers.add_parser("aws-enable-vpc-flow-logs", help="Enable VPC flow logs")
    p.add_argument("vpc_id", help="VPC ID")
    p.add_argument("--log-group-name", default="/aws/vpc/flowlogs", dest="log_group_name")
    p.add_argument("--deliver-logs-permission-arn", dest="deliver_logs_permission_arn",
                   help="IAM role ARN for CloudWatch Logs delivery")
    p.add_argument("--log-destination-type", default="cloud-watch-logs", dest="log_destination_type",
                   choices=["cloud-watch-logs", "s3"])
    p.add_argument("--log-destination", dest="log_destination", help="S3 bucket ARN (for s3 type)")
    p.add_argument("--traffic-type", default="ALL", dest="traffic_type", choices=["ALL", "ACCEPT", "REJECT"])
    p.set_defaults(func=handle_aws_enable_vpc_flow_logs)

    p = subparsers.add_parser("aws-ssm-session-history", help="Retrieve completed SSM session history")
    p.add_argument("--instance-id", dest="instance_id", help="Filter by EC2 instance ID")
    p.add_argument("--owner", help="Filter by session owner")
    p.add_argument("--max-sessions", type=int, default=100, dest="max_sessions")
    p.set_defaults(func=handle_aws_ssm_session_history)

    p = subparsers.add_parser("aws-cloudtrail-status", help="Check CloudTrail trail status and configuration")
    p.add_argument("--include-shadow-trails", action="store_true", dest="include_shadow_trails",
                   help="Include shadow trails from other regions")
    p.set_defaults(func=handle_aws_cloudtrail_status)

    p = subparsers.add_parser("aws-hunt-cloudwatch-logs", help="Run a CloudWatch Logs Insights query")
    p.add_argument("--log-group", required=True, help="Log group name")
    p.add_argument("--query", required=True, help="Logs Insights query string")
    p.add_argument("--start-time", default=None, help="Query window start (ISO 8601)")
    p.add_argument("--end-time", default=None, help="Query window end (ISO 8601)")
    p.add_argument("--max-results", type=int, default=1000, help="Maximum rows to return")
    p.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between status polls")
    p.add_argument("--max-wait-seconds", type=float, default=60.0, help="Maximum seconds to wait for completion")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_aws_hunt_cloudwatch_logs)

    # --- AWS hunt (CloudTrail) ---

    p = subparsers.add_parser(
        "aws-hunt-cloudtrail", help="Hunt CloudTrail events with simple filters"
    )
    p.add_argument("--user", default=None, help="CloudTrail Username")
    p.add_argument("--access-key-id", default=None, help="AccessKeyId")
    p.add_argument("--event-name", default=None, help="Event name (e.g. ConsoleLogin)")
    p.add_argument("--source-ip", default=None, help="Source IP address")
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return",
    )
    p.set_defaults(func=handle_aws_hunt_cloudtrail)
    p.add_argument(
        "--output",
        choices=["json", "csv"],
        default="json",
        help="Output format (json or csv, default json)",
    )
    p.add_argument(
        "--today",
        action="store_true",
        help="Search only today's CloudTrail events (UTC)",
    )   
    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")

    p.set_defaults(func=handle_aws_hunt_cloudtrail)

    # --- GitHub hunt ---

    p = subparsers.add_parser(
        "github-hunt-audit", help="Hunt GitHub org/enterprise audit logs"
    )
    p.add_argument("--actor", default=None, help="GitHub username (actor)")
    p.add_argument("--action", default=None, help="Audit action (e.g. repo.create)")
    p.add_argument("--repo", default=None, help="Repository (e.g. org/repo)")
    p.add_argument("--source-ip", default=None, help="Actor IP address")
    p.add_argument(
        "--include",
        default=None,
        help='Include filter: "web", "git", or "all" (default from config)',
    )
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return",
    )
    p.add_argument(
        "--output",
        choices=["json", "csv"],
        default="json",
        help="Output format (json or csv, default json)",
    )
    p.add_argument(
        "--today",
        action="store_true",
        help="Search only today's events",
    )

    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")
    
    p.set_defaults(func=handle_github_hunt_audit)

    # ---- GitHub response ----

    p = subparsers.add_parser("github-block-org-member", help="Block a user from interacting with the org")
    p.add_argument("--username", required=True, help="GitHub username to block")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_block_org_member)

    p = subparsers.add_parser("github-remove-org-member", help="Remove a user from the organization")
    p.add_argument("--username", required=True, help="GitHub username to remove")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_remove_org_member)

    p = subparsers.add_parser("github-remove-repo-collaborator", help="Remove a collaborator from a repository")
    p.add_argument("--repo", required=True, help="Repository name (without org prefix)")
    p.add_argument("--username", required=True, help="GitHub username to remove")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_remove_repo_collaborator)

    p = subparsers.add_parser("github-revoke-deploy-key", help="Revoke a repository deploy key")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--key-id", dest="key_id", type=int, required=True, help="Deploy key ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_revoke_deploy_key)

    p = subparsers.add_parser("github-delete-org-webhook", help="Delete an organization-level webhook")
    p.add_argument("--hook-id", dest="hook_id", type=int, required=True, help="Webhook ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_delete_org_webhook)

    p = subparsers.add_parser("github-delete-repo-webhook", help="Delete a repository-level webhook")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--hook-id", dest="hook_id", type=int, required=True, help="Webhook ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_delete_repo_webhook)

    p = subparsers.add_parser("github-archive-repository", help="Archive a repository (make read-only)")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_archive_repository)

    # ---- GitHub extended hunt ----

    p = subparsers.add_parser("github-hunt-secret-scanning", help="List secret scanning alerts")
    p.add_argument("--repo", default=None, help="Repository name (omit for all org repos)")
    p.add_argument("--state", default="open", choices=["open", "resolved"], help="Alert state (default: open)")
    p.add_argument("--max-alerts", dest="max_alerts", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_hunt_secret_scanning)

    p = subparsers.add_parser("github-hunt-code-scanning", help="List code scanning alerts for a repository")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--state", default="open", help="Alert state: open, dismissed, fixed (default: open)")
    p.add_argument("--max-alerts", dest="max_alerts", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_hunt_code_scanning)

    p = subparsers.add_parser("github-list-org-members", help="List all organization members")
    p.add_argument("--role", default=None, choices=["member", "admin"], help="Filter by role")
    p.add_argument("--max-members", dest="max_members", type=int, default=500)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_org_members)

    p = subparsers.add_parser("github-list-outside-collaborators", help="List users with repo access outside the org")
    p.add_argument("--max-items", dest="max_items", type=int, default=200)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_outside_collaborators)

    p = subparsers.add_parser("github-list-deploy-keys", help="List deploy keys for a repository")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--max-keys", dest="max_keys", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_deploy_keys)

    # ---- GitHub forensics ----

    p = subparsers.add_parser("github-forensics-org-settings", help="Capture org configuration snapshot")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_org_settings)

    p = subparsers.add_parser("github-forensics-repo-metadata", help="Capture repository configuration snapshot")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_metadata)

    p = subparsers.add_parser("github-forensics-repo-collaborators", help="List all repository collaborators")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--max-items", dest="max_items", type=int, default=200)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_collaborators)

    p = subparsers.add_parser("github-forensics-branch-protection", help="Get branch protection rules")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--branch", required=True, help="Branch name (e.g. main)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_branch_protection)

    p = subparsers.add_parser("github-forensics-org-webhooks", help="List all organization webhooks")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_org_webhooks)

    p = subparsers.add_parser("github-forensics-repo-webhooks", help="List all repository webhooks")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_webhooks)

    return parser


def compute_relative_range(weeks_ago: int = None, months_ago: int = None):
    """
    Returns (start, end) datetimes in UTC based on relative offsets.
    - weeks_ago N → from N weeks ago until now
    - months_ago N → from N months ago until now
    """
    now = datetime.now(timezone.utc)

    if weeks_ago is not None:
        start = now - timedelta(weeks=weeks_ago)
        return start, now

    if months_ago is not None:
        start = now - relativedelta(months=months_ago)
        return start, now

    return None, None


def main():
    parser = build_parser()
    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    func(args)

if __name__ == "__main__":
    main()

