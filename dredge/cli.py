#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import csv
import os
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from typing import Dict, List, Optional

# Library imports – adjust if your package paths differ
from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig
from dredge.github_ir.config import GitHubIRConfig
from dredge.k8s_ir.config import K8sAuthConfig

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


def print_table(headers: tuple, rows: list) -> None:
    """Print a simple space-aligned table. Falls back to a plain message
    when there are no rows."""
    if not rows:
        print("(no results)")
        return

    widths = [
        max(len(str(headers[i])), *(len(str(row[i])) for row in rows))
        for i in range(len(headers))
    ]
    print("    ".join(str(h).ljust(w) for h, w in zip(headers, widths)))
    for row in rows:
        print("    ".join(str(c).ljust(w) for c, w in zip(row, widths)))



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


def build_k8s_config_from_args(args: argparse.Namespace) -> Optional[K8sAuthConfig]:
    if not any(
        [
            args.k8s_token,
            args.k8s_in_cluster,
            args.k8s_kubeconfig,
            args.k8s_context,
        ]
    ):
        return None

    token = args.k8s_token
    if not token and args.k8s_token_env_var:
        import os
        token = os.environ.get(args.k8s_token_env_var)

    return K8sAuthConfig(
        token=token,
        api_server=args.k8s_api_server,
        ca_cert_file=args.k8s_ca_cert,
        verify_ssl=not args.k8s_insecure_skip_tls_verify,
        in_cluster=args.k8s_in_cluster,
        kubeconfig_path=args.k8s_kubeconfig,
        context=args.k8s_context,
        namespace=args.k8s_namespace,
    )


def _k8s_dredge(args: argparse.Namespace) -> Dredge:
    """Build a Dredge instance with Kubernetes config, raising SystemExit if unconfigured."""
    k8s_cfg = build_k8s_config_from_args(args)
    if k8s_cfg is None:
        raise SystemExit(
            "You must configure Kubernetes auth: --k8s-kubeconfig, --k8s-context, "
            "--k8s-in-cluster, or --k8s-token"
        )
    auth = build_aws_auth_from_args(args)  # optional; might be unused
    return Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
        k8s_config=k8s_cfg,
    )


def _k8s_namespace(args: argparse.Namespace) -> str:
    """Resolve the effective namespace: subcommand --namespace, else global --k8s-namespace."""
    namespace = getattr(args, "namespace", None) or args.k8s_namespace
    if not namespace:
        raise SystemExit("You must provide --namespace (or set the global --k8s-namespace)")
    return namespace


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

    # A human explicitly typing --source-ip with no other filter has already
    # made the "scan everything" call — no need to make them pass a second
    # flag to confirm it. Just warn (to stderr, so stdout stays clean JSON).
    full_scan = bool(args.source_ip) and not any([args.user, args.access_key_id, args.event_name])
    if full_scan:
        print(
            "note: --source-ip given without --user/--access-key-id/--event-name — "
            "scanning every CloudTrail event in the time range for a match; this can "
            "be slow and results may be truncated at --max-events (see statistics.truncated).",
            file=sys.stderr,
        )

    # Multi-region fan-out: --all-regions, or --regions r1 r2 (repeatable; the
    # value "all" also means every enabled region). Each regional endpoint is
    # queried concurrently.
    regions_arg = None
    if getattr(args, "all_regions", False):
        regions_arg = "all"
    elif getattr(args, "regions", None):
        # Accept comma-separated values and/or a repeated flag (and any mix):
        # --regions us-east-1,us-east-2  ==  --regions us-east-1 --regions us-east-2
        regions = _flatten_csv(args.regions)
        regions_arg = "all" if "all" in regions else regions

    if regions_arg is not None:
        res = dredge.aws_ir.hunt.lookup_events_multi_region(
            regions=regions_arg,
            user_name=args.user,
            access_key_id=args.access_key_id,
            event_name=args.event_name,
            source_ip=args.source_ip,
            start_time=start,
            end_time=end,
            max_events_per_region=args.max_events,
            allow_full_scan=full_scan,
            max_workers=args.max_workers,
        )
    else:
        res = dredge.aws_ir.hunt.lookup_events(
            user_name=args.user,
            access_key_id=args.access_key_id,
            event_name=args.event_name,
            source_ip=args.source_ip,
            start_time=start,
            end_time=end,
            max_events=args.max_events,
            allow_full_scan=full_scan,
        )
    print_result(res, output=getattr(args, "output", "json"))


def _read_list_file(path: str) -> List[str]:
    """Read one value per line from a text file, ignoring blank lines and
    lines starting with '#'."""
    with open(path) as f:
        return [
            stripped
            for line in f
            if (stripped := line.strip()) and not stripped.startswith("#")
        ]


def _flatten_csv(values) -> List[str]:
    """Flatten a list flag that is both repeatable and comma-separated:
    ["a,b", "c"] -> ["a", "b", "c"]. Whitespace around items is stripped and
    empty items dropped, so `--x a, b` and `--x a --x b` are equivalent."""
    return [part.strip() for v in (values or []) for part in v.split(",") if part.strip()]


def _resolve_hunt_time_range(args: argparse.Namespace):
    if args.week_ago or args.month_ago:
        return compute_relative_range(weeks_ago=args.week_ago, months_ago=args.month_ago)
    if args.today:
        now = datetime.now(timezone.utc)
        return now.replace(hour=0, minute=0, second=0, microsecond=0), now
    return parse_iso_datetime(args.start_time), parse_iso_datetime(args.end_time)


def handle_aws_hunt_cloudtrail_multi_user(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )

    users = _flatten_csv(args.user)
    if args.users_file:
        users.extend(_read_list_file(args.users_file))
    # Dedupe while preserving order.
    users = list(dict.fromkeys(users))
    if not users:
        print("error: no users given — pass --user (repeatable) and/or --users-file", file=sys.stderr)
        sys.exit(2)

    start, end = _resolve_hunt_time_range(args)

    full_scan = bool(args.source_ip) and not args.event_name
    if full_scan:
        print(
            "note: --source-ip given without --event-name — scanning every CloudTrail "
            "event in each user's time range for a match; this can be slow.",
            file=sys.stderr,
        )

    res = dredge.aws_ir.hunt.hunt_cloudtrail_multi_user(
        users,
        mode=args.mode,
        event_name=args.event_name,
        source_ip=args.source_ip,
        start_time=start,
        end_time=end,
        max_events_per_user=args.max_events_per_user,
        allow_full_scan=full_scan,
        stop_on_error=args.stop_on_error,
        output_path=args.output_path,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_user_activity_by_ip(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )

    allowed_ips = _flatten_csv(args.allowed_ip)
    if args.allowed_ips_file:
        allowed_ips.extend(_read_list_file(args.allowed_ips_file))
    allowed_ips = list(dict.fromkeys(allowed_ips))
    if not allowed_ips:
        print("error: no allowed IPs given — pass --allowed-ip (repeatable) and/or --allowed-ips-file", file=sys.stderr)
        sys.exit(2)

    start, end = _resolve_hunt_time_range(args)

    res = dredge.aws_ir.hunt.hunt_user_activity_by_ip(
        args.user,
        allowed_ips,
        event_name=args.event_name,
        start_time=start,
        end_time=end,
        max_events=args.max_events,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_review(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    from dredge.aws_ir.review import AwsIRReview

    # `review_service` is set per subcommand: "full" (all services) or a single
    # service name (which runs its deeper tier-2 checks too).
    if args.review_service == "full":
        services = "all"
        tiers = (1, 2) if getattr(args, "deep", False) else (1,)
    else:
        services = [args.review_service]
        tiers = (1, 2)

    # Region fan-out (regional checks): --all-regions or --regions r1,r2.
    regions = None
    if getattr(args, "all_regions", False):
        regions = "all"
    elif getattr(args, "regions", None):
        r = _flatten_csv(args.regions)
        regions = "all" if "all" in r else r

    res = dredge.aws_ir.review.review(
        services=services,
        tiers=tiers,
        incident_start=parse_iso_datetime(getattr(args, "incident_start", None)),
        ips=_flatten_csv(getattr(args, "ip", None)) or None,
        include=_flatten_csv(getattr(args, "include", None)) or None,
        exclude=_flatten_csv(getattr(args, "exclude", None)) or None,
        regions=regions,
        max_workers=getattr(args, "max_workers", 12),
    )

    if getattr(args, "csv", None):
        AwsIRReview.to_csv(res, args.csv)
        print(f"wrote CSV: {args.csv}", file=sys.stderr)
    if getattr(args, "html", None):
        AwsIRReview.to_html(res, args.html)
        print(f"wrote HTML: {args.html}", file=sys.stderr)

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


def handle_aws_download_s3_logs(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    suffixes = tuple(args.suffix) if args.suffix else (".json", ".json.gz")
    res = dredge.aws_ir.forensics.download_s3_logs(
        args.bucket,
        prefix=args.prefix,
        destination=args.destination,
        suffixes=suffixes,
        decompress_gzip=not args.no_decompress,
        max_objects=args.max_objects,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
        days_ago=args.days_ago,
        max_workers=args.max_workers,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_query_cloudtrail_logs(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.query_local_cloudtrail_logs(
        args.path,
        source_ip=args.source_ip,
        user_name=args.user,
        access_key_id=args.access_key_id,
        event_name=args.event_name,
        event_source=args.event_source,
        aws_region=args.region,
        account_id=args.account_id,
        start_time=parse_iso_datetime(args.start_time),
        end_time=parse_iso_datetime(args.end_time),
        fields=args.fields.split(",") if args.fields else None,
        max_events=args.max_events,
    )
    print_result(res, output=getattr(args, "output", "json"))


_SG_DIRECTION_ARG_TO_LIB = {"inbound": "ingress", "outbound": "egress", "both": "both"}


def handle_aws_hunt_security_groups_by_ip(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_security_groups_by_ip(
        _flatten_csv(args.ip),
        direction=_SG_DIRECTION_ARG_TO_LIB[args.direction],
        max_groups=args.max_groups,
    )
    if args.verbose:
        print_result(res, output=getattr(args, "output", "json"))
        return

    _DIRECTION_LABELS = {"ingress": "Inbound", "egress": "Outbound"}
    _MATCH_TYPE_LABELS = {"explicit": "Explicit", "wildcard": "Wildcard (*)"}
    rows = []
    for m in res.details.get("matches", []):
        seen = set()
        for rule in m.get("matched_rules", []):
            direction = _DIRECTION_LABELS.get(rule.get("direction"), rule.get("direction") or "")
            match_type = _MATCH_TYPE_LABELS.get(rule.get("match_type"), rule.get("match_type") or "")
            for t in rule.get("matched_targets", []):
                key = (direction, match_type, t)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((
                    m.get("group_name") or "", m.get("group_id") or "", direction, match_type, t,
                ))

    print_table(("Group name", "ID", "Direction", "Match", "Matched targets"), rows)
    if res.errors:
        print()
        print("Errors:", "; ".join(res.errors))


def handle_aws_hunt_exposed_secrets(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.hunt.hunt_exposed_secrets(
        include=args.include or None,
        keep_raw=bool(args.unredacted),
        test_pairs=args.test,
        max_ec2_instances=args.max_ec2_instances,
    )
    if args.unredacted:
        raw_values = res.details.pop("raw_values", {})
        with open(args.unredacted, "w") as fh:
            json.dump(raw_values, fh, indent=2)
        os.chmod(args.unredacted, 0o600)
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


# ------------- Kubernetes response handlers -------------


def handle_k8s_revoke_role_binding(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.revoke_role_binding(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_revoke_cluster_role_binding(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.revoke_cluster_role_binding(args.name), output=getattr(args, "output", "json"))


def handle_k8s_disable_service_account(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.disable_service_account(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_delete_service_account(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.delete_service_account(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_delete_pod(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.response.delete_pod(_k8s_namespace(args), args.name, grace_period_seconds=args.grace_period_seconds),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_scale_deployment(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.response.scale_deployment(_k8s_namespace(args), args.name, args.replicas),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_cordon_node(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.cordon_node(args.name), output=getattr(args, "output", "json"))


def handle_k8s_drain_node(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.response.drain_node(
            args.name,
            grace_period_seconds=args.grace_period_seconds,
            ignore_daemonsets=args.ignore_daemonsets,
        ),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_delete_node(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.delete_node(args.name), output=getattr(args, "output", "json"))


def handle_k8s_quarantine_pod(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.response.quarantine_pod(_k8s_namespace(args), args.name, policy_name=args.policy_name),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_quarantine_namespace(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.response.quarantine_namespace(_k8s_namespace(args), policy_name=args.policy_name),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_delete_secret(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.response.delete_secret(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_label_resource(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    labels = dict(t.split("=", 1) for t in (args.labels_raw or []))
    namespace = (args.namespace or args.k8s_namespace) if args.kind in ("pod", "deployment") else None
    print_result(
        d.k8s_ir.response.label_resource(args.kind, namespace, args.name, labels),
        output=getattr(args, "output", "json"),
    )


# ------------- Kubernetes forensics handlers -------------


def handle_k8s_get_pod_manifest(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.forensics.get_pod_manifest(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_get_pod_logs(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.forensics.get_pod_logs(
            _k8s_namespace(args), args.name,
            container=args.container, previous=args.previous, tail_lines=args.tail_lines,
        ),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_get_pod_events(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.forensics.get_pod_events(_k8s_namespace(args), args.name), output=getattr(args, "output", "json"))


def handle_k8s_describe_node(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.forensics.describe_node(args.name), output=getattr(args, "output", "json"))


def handle_k8s_capture_workload_manifest(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.forensics.capture_workload_manifest(args.kind, _k8s_namespace(args), args.name),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_list_pods_on_node(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.forensics.list_pods_on_node(args.name), output=getattr(args, "output", "json"))


def handle_k8s_exec_pod_command(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.forensics.exec_pod_command(_k8s_namespace(args), args.name, args.command, container=args.container),
        output=getattr(args, "output", "json"),
    )


# ------------- Kubernetes hunt handlers -------------


def handle_k8s_hunt_events(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.hunt.list_events(
            namespace=args.namespace or args.k8s_namespace,
            involved_object_kind=args.involved_object_kind,
            involved_object_name=args.involved_object_name,
            reason=args.reason,
            event_type=args.event_type,
            start_time=parse_iso_datetime(args.start_time),
            end_time=parse_iso_datetime(args.end_time),
            max_events=args.max_events,
        ),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_hunt_role_bindings_for_subject(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.hunt.list_role_bindings_for_subject(
            kind=args.kind, name=args.name, namespace=args.namespace or args.k8s_namespace,
        ),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_hunt_pods_by_service_account(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(
        d.k8s_ir.hunt.list_pods_by_service_account(_k8s_namespace(args), args.service_account),
        output=getattr(args, "output", "json"),
    )


def handle_k8s_hunt_privileged_pods(args: argparse.Namespace) -> None:
    d = _k8s_dredge(args)
    print_result(d.k8s_ir.hunt.list_privileged_pods(max_pods=args.max_pods), output=getattr(args, "output", "json"))


# ------------- argparse wiring -------------

# Display order for the grouped `dredge -h` overview, by provider slug and
# bucket slug.
_PROVIDER_ORDER = ["aws", "k8s", "github", "gcp"]
_PROVIDER_LABELS = {"aws": "AWS", "k8s": "Kubernetes", "github": "GitHub", "gcp": "GCP"}
_BUCKET_ORDER = ["review", "hunt", "response", "forensics"]
_BUCKET_LABELS = {
    "review": "Review (posture)",
    "hunt": "Hunt & Investigate",
    "response": "Response & Remediation",
    "forensics": "Forensics",
}

# Global option destinations grouped for the help screen, in display order.
_GLOBAL_OPTION_GROUPS = [
    ("AWS auth / region", "aws_"),
    ("GitHub auth", "github_"),
    ("Kubernetes auth", "k8s_"),
]


def _make_help_printer(parser: argparse.ArgumentParser):
    """func default for an intermediate (provider/bucket) node: running it with
    no deeper command selected prints that node's help instead of erroring."""
    def _printer(_args: argparse.Namespace) -> None:
        parser.print_help()
    return _printer


class _NestedRegistrar:
    """Builds and holds the `provider -> bucket -> command` argparse tree.

    Adding a command is one call — `subparsers.command("aws", "hunt", "x",
    help=...)` — which returns the leaf parser to add arguments to. Provider
    and bucket nodes are created lazily the first time a command needs them
    (bare `dredge aws` / `dredge aws hunt` print that level's help). There is
    exactly one way to register a command and it names the nested path
    explicitly, so the invocation (`dredge aws hunt x`) is visible at the
    call site — no separate flat-name -> nested mapping to keep in sync."""

    def __init__(self, parser: argparse.ArgumentParser) -> None:
        self._providers = parser.add_subparsers(
            dest="provider", required=True, metavar="<provider>",
        )
        self._provider_buckets: Dict[str, Any] = {}
        self._bucket_commands: Dict[tuple, Any] = {}
        # (provider, bucket, leaf, help) for the grouped overview.
        self.commands: List[tuple] = []

    def _bucket_subparsers(self, provider: str):
        if provider not in self._provider_buckets:
            pp = self._providers.add_parser(
                provider, help=f"{_PROVIDER_LABELS.get(provider, provider)} commands",
            )
            pp.set_defaults(func=_make_help_printer(pp))
            self._provider_buckets[provider] = pp.add_subparsers(
                dest=f"{provider}_bucket", metavar="<bucket>",
            )
        return self._provider_buckets[provider]

    def _command_subparsers(self, provider: str, bucket: str):
        key = (provider, bucket)
        if key not in self._bucket_commands:
            bp = self._bucket_subparsers(provider).add_parser(
                bucket, help=f"{_PROVIDER_LABELS.get(provider, provider)} {_BUCKET_LABELS[bucket]} commands",
            )
            bp.set_defaults(func=_make_help_printer(bp))
            self._bucket_commands[key] = bp.add_subparsers(
                dest=f"{provider}_{bucket}_command", metavar="<command>",
            )
        return self._bucket_commands[key]

    def command(self, provider: str, bucket: str, name: str, **kwargs) -> argparse.ArgumentParser:
        if bucket not in _BUCKET_LABELS:
            raise ValueError(f"unknown bucket {bucket!r} (expected one of {sorted(_BUCKET_LABELS)})")
        leaf_parser = self._command_subparsers(provider, bucket).add_parser(name, **kwargs)
        self.commands.append((provider, bucket, name, kwargs.get("help")))
        return leaf_parser


class _GroupedHelpAction(argparse.Action):
    """Prints a categorized command overview instead of argparse's flat dump."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        _print_grouped_help(parser)
        parser.exit()


def _print_grouped_help(parser: argparse.ArgumentParser) -> None:
    commands = getattr(parser, "_dredge_commands", [])

    lines: List[str] = []
    lines.append(f"usage: {parser.prog} [global options] <provider> <bucket> <command> [command options]")
    lines.append("")
    if parser.description:
        lines.append(parser.description)
        lines.append("")

    lines.append("Global options:")
    grouped_dests = set()
    for label, prefix in _GLOBAL_OPTION_GROUPS:
        actions = [
            a for a in parser._actions
            if a.option_strings and a.dest.startswith(prefix)
        ]
        if not actions:
            continue
        lines.append(f"  {label}:")
        width = max(len(", ".join(a.option_strings)) for a in actions)
        for a in actions:
            grouped_dests.add(a.dest)
            opts = ", ".join(a.option_strings)
            lines.append(f"    {opts.ljust(width)}  {a.help or ''}")
    other = [
        a for a in parser._actions
        if a.option_strings
        and a.dest not in grouped_dests
        and a.dest not in ("help",)
        and not isinstance(a, argparse._SubParsersAction)
    ]
    if other:
        lines.append("  Other:")
        width = max(len(", ".join(a.option_strings)) for a in other)
        for a in other:
            opts = ", ".join(a.option_strings)
            lines.append(f"    {opts.ljust(width)}  {a.help or ''}")
    lines.append("")

    # (provider, bucket) -> [(leaf, help)]
    grouped: Dict[tuple, List[tuple]] = {}
    for provider, bucket, leaf, help_ in commands:
        grouped.setdefault((provider, bucket), []).append((leaf, help_))

    for provider in _PROVIDER_ORDER:
        for bucket in _BUCKET_ORDER:
            items = sorted(grouped.get((provider, bucket), []))
            if not items:
                continue
            lines.append(f"{_PROVIDER_LABELS.get(provider, provider)} — {_BUCKET_LABELS[bucket]}:")
            width = max(len(f"{provider} {bucket} {leaf}") for leaf, _ in items)
            for leaf, help_ in items:
                invocation = f"{provider} {bucket} {leaf}"
                lines.append(f"  {invocation.ljust(width)}  {help_ or ''}")
            lines.append("")

    lines.append(f"Run '{parser.prog} <provider> <bucket> <command> --help' for a command's full options.")
    print("\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dredge",
        description="Dredge incident response CLI (AWS + Kubernetes + GitHub + GCP)",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help",
        action=_GroupedHelpAction,
        help="Show a categorized command overview and exit",
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

    # Kubernetes-global options (used when k8s subcommands are run)
    parser.add_argument("--k8s-kubeconfig", default=None, help="Path to kubeconfig file (default: ~/.kube/config or $KUBECONFIG)")
    parser.add_argument("--k8s-context", default=None, help="Kubeconfig context to use")
    parser.add_argument("--k8s-in-cluster", action="store_true", help="Use the in-cluster (mounted) service account token")
    parser.add_argument("--k8s-token", default=None, help="Explicit bearer/service-account token (no kubeconfig)")
    parser.add_argument("--k8s-token-env-var", default="K8S_TOKEN", help="Env var to read the token from if --k8s-token is not set")
    parser.add_argument("--k8s-api-server", default=None, help="API server URL (required with --k8s-token)")
    parser.add_argument("--k8s-ca-cert", default=None, help="Path to CA cert file (used with --k8s-token)")
    parser.add_argument("--k8s-insecure-skip-tls-verify", action="store_true", help="Disable TLS verification (used with --k8s-token)")
    parser.add_argument("--k8s-namespace", default=None, help="Default namespace for namespaced k8s subcommands")

    # --version flag
    try:
        dredge_version = version("dredge")
    except PackageNotFoundError:
        dredge_version = "development"

    parser.add_argument(
        "--version",
        action="version",
        version=f"dredge {dredge_version}",
        help="Show the installed dredge version and exit",
    )

    # Subcommands. `subparsers` is a nested registrar, not a raw argparse
    # subparsers action: each `subparsers.command("aws", "hunt", "x", ...)` below
    # registers `dredge aws hunt x` in the provider → bucket → command tree.
    subparsers = _NestedRegistrar(parser)

    # --- AWS response subcommands ---

    p = subparsers.command("aws", "response", "disable-access-key", help="Disable an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_disable_access_key)

    p = subparsers.command("aws", "response", "delete-access-key", help="Delete an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_delete_access_key)

    p = subparsers.command("aws", "response", "disable-user", help="Disable an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_disable_user)

    p = subparsers.command("aws", "response", "delete-user", help="Delete an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_delete_user)

    p = subparsers.command("aws", "response", "disable-role", help="Disable an IAM role")
    p.add_argument("--role", required=True, help="IAM role name")
    p.set_defaults(func=handle_aws_disable_role)

    p = subparsers.command("aws", "response", "block-s3-account", help="Block S3 public access at account level"
    )
    p.add_argument("--account-id", required=True, help="AWS account ID")
    p.set_defaults(func=handle_aws_block_s3_account)

    p = subparsers.command("aws", "response", "block-s3-bucket", help="Make an S3 bucket private / block public access"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.set_defaults(func=handle_aws_block_s3_bucket)

    p = subparsers.command("aws", "response", "block-s3-object", help="Make a specific S3 object private"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.add_argument("--key", required=True, help="Object key")
    p.set_defaults(func=handle_aws_block_s3_object)

    p = subparsers.command("aws", "response", "isolate-ec2", help="Network-isolate EC2 instances (forensic SG)"
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

    p = subparsers.command("aws", "response", "delete-mfa-devices", help="Deactivate and delete MFA devices for a user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_delete_mfa_devices)

    p = subparsers.command("aws", "response", "revoke-active-sessions", help="Invalidate active sessions for a user via deny policy")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_revoke_active_sessions)

    p = subparsers.command("aws", "response", "stop-ec2", help="Stop EC2 instances (can be restarted)")
    p.add_argument("instance_ids", nargs="+", help="One or more EC2 instance IDs")
    p.set_defaults(func=handle_aws_stop_ec2)

    p = subparsers.command("aws", "response", "terminate-ec2", help="Terminate EC2 instances (snapshot EBS volumes first by default)")
    p.add_argument("instance_ids", nargs="+", help="One or more EC2 instance IDs")
    p.add_argument(
        "--no-snapshot",
        dest="snapshot_first",
        action="store_false",
        help="Skip EBS snapshots before termination",
    )
    p.set_defaults(func=handle_aws_terminate_ec2, snapshot_first=True)

    p = subparsers.command("aws", "response", "block-nacl-cidrs", help="Add DENY rules for CIDRs to all NACLs in a VPC")
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

    p = subparsers.command("aws", "response", "disable-lambda", help="Throttle a Lambda function to zero concurrency")
    p.add_argument("--function-name", required=True, help="Lambda function name or ARN")
    p.set_defaults(func=handle_aws_disable_lambda)

    p = subparsers.command("aws", "response", "disable-kms-key", help="Disable a KMS key")
    p.add_argument("--key-id", required=True, help="KMS key ID or ARN")
    p.set_defaults(func=handle_aws_disable_kms_key)

    p = subparsers.command("aws", "response", "schedule-kms-deletion", help="Schedule a KMS key for deletion")
    p.add_argument("--key-id", required=True, help="KMS key ID or ARN")
    p.add_argument(
        "--pending-window-days",
        type=int,
        default=7,
        help="Days before deletion (7–30, default 7)",
    )
    p.set_defaults(func=handle_aws_schedule_kms_deletion)

    p = subparsers.command("aws", "response", "tag-resources", help="Apply tags to AWS resources by ARN")
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

    p = subparsers.command("aws", "hunt", "guardduty", help="List GuardDuty findings")
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

    p = subparsers.command("aws", "response", "isolate-rds", help="Isolate an RDS instance (empty SG, disable public access)")
    p.add_argument("db_instance_id", help="RDS DB instance identifier")
    p.set_defaults(func=handle_aws_isolate_rds)

    p = subparsers.command("aws", "response", "stop-ecs-service", help="Scale an ECS service to 0 desired tasks")
    p.add_argument("cluster", help="ECS cluster name or ARN")
    p.add_argument("service", help="ECS service name or ARN")
    p.set_defaults(func=handle_aws_stop_ecs_service)

    p = subparsers.command("aws", "response", "stop-ecs-task", help="Force-stop a running ECS task")
    p.add_argument("cluster", help="ECS cluster name or ARN")
    p.add_argument("task_id", help="ECS task ID or ARN")
    p.set_defaults(func=handle_aws_stop_ecs_task)

    p = subparsers.command("aws", "response", "disable-secret", help="Schedule a Secrets Manager secret for deletion")
    p.add_argument("secret_id", help="Secret ID or ARN")
    p.add_argument("--recovery-window-days", type=int, default=7, dest="recovery_window_days",
                   help="Days before permanent deletion (7–30, default 7)")
    p.set_defaults(func=handle_aws_disable_secret)

    p = subparsers.command("aws", "response", "disable-eventbridge-rule", help="Disable an EventBridge rule")
    p.add_argument("rule_name", help="EventBridge rule name")
    p.add_argument("--event-bus-name", default="default", dest="event_bus_name",
                   help="Event bus name (default: default)")
    p.set_defaults(func=handle_aws_disable_eventbridge_rule)

    p = subparsers.command("aws", "response", "terminate-ssm-sessions", help="Terminate all active SSM sessions on an instance")
    p.add_argument("instance_id", help="EC2 instance ID")
    p.set_defaults(func=handle_aws_terminate_ssm_sessions)

    p = subparsers.command("aws", "response", "detach-iam-policy", help="Detach a managed policy from a user or role")
    p.add_argument("policy_arn", help="Policy ARN to detach")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--user-name", dest="user_name", help="IAM user name")
    group.add_argument("--role-name", dest="role_name", help="IAM role name")
    p.set_defaults(func=handle_aws_detach_iam_policy)

    p = subparsers.command("aws", "response", "quarantine-s3-bucket", help="Block public access and apply deny-all policy to an S3 bucket")
    p.add_argument("bucket_name", help="S3 bucket name")
    p.add_argument("--account-id", dest="account_id", help="AWS account ID (auto-detected if omitted)")
    p.set_defaults(func=handle_aws_quarantine_s3_bucket)

    p = subparsers.command("aws", "hunt", "security-hub", help="Query Security Hub findings")
    p.add_argument("--severity-label", dest="severity_labels", action="append",
                   help="Severity label filter (e.g. HIGH, CRITICAL); repeatable")
    p.add_argument("--workflow-status", dest="workflow_status", action="append",
                   help="Workflow status filter (e.g. NEW, NOTIFIED); repeatable")
    p.add_argument("--product-name", dest="product_name", help="Product name filter (e.g. GuardDuty)")
    p.add_argument("--start-time", dest="start_time", help="ISO 8601 start time")
    p.add_argument("--end-time", dest="end_time", help="ISO 8601 end time")
    p.add_argument("--max-findings", type=int, default=100, dest="max_findings")
    p.set_defaults(func=handle_aws_hunt_security_hub)

    p = subparsers.command("aws", "hunt", "access-analyzer", help="List IAM Access Analyzer findings")
    p.add_argument("analyzer_arn", help="Access Analyzer ARN")
    p.add_argument("--status", help="Finding status filter: ACTIVE, ARCHIVED, RESOLVED")
    p.add_argument("--resource-type", dest="resource_type", help="Resource type filter (e.g. AWS::S3::Bucket)")
    p.add_argument("--max-findings", type=int, default=100, dest="max_findings")
    p.set_defaults(func=handle_aws_hunt_access_analyzer)

    p = subparsers.command("aws", "hunt", "config-history", help="Get AWS Config resource configuration history")
    p.add_argument("resource_type", help="Resource type (e.g. AWS::EC2::Instance)")
    p.add_argument("resource_id", help="Resource ID")
    p.add_argument("--start-time", dest="start_time", help="ISO 8601 start time")
    p.add_argument("--end-time", dest="end_time", help="ISO 8601 end time")
    p.add_argument("--max-items", type=int, default=100, dest="max_items")
    p.set_defaults(func=handle_aws_hunt_config_history)

    p = subparsers.command("aws", "response", "iam-credential-report", help="Generate and retrieve IAM credential report")
    p.set_defaults(func=handle_aws_iam_credential_report)

    p = subparsers.command("aws", "response", "enable-vpc-flow-logs", help="Enable VPC flow logs")
    p.add_argument("vpc_id", help="VPC ID")
    p.add_argument("--log-group-name", default="/aws/vpc/flowlogs", dest="log_group_name")
    p.add_argument("--deliver-logs-permission-arn", dest="deliver_logs_permission_arn",
                   help="IAM role ARN for CloudWatch Logs delivery")
    p.add_argument("--log-destination-type", default="cloud-watch-logs", dest="log_destination_type",
                   choices=["cloud-watch-logs", "s3"])
    p.add_argument("--log-destination", dest="log_destination", help="S3 bucket ARN (for s3 type)")
    p.add_argument("--traffic-type", default="ALL", dest="traffic_type", choices=["ALL", "ACCEPT", "REJECT"])
    p.set_defaults(func=handle_aws_enable_vpc_flow_logs)

    p = subparsers.command("aws", "response", "ssm-session-history", help="Retrieve completed SSM session history")
    p.add_argument("--instance-id", dest="instance_id", help="Filter by EC2 instance ID")
    p.add_argument("--owner", help="Filter by session owner")
    p.add_argument("--max-sessions", type=int, default=100, dest="max_sessions")
    p.set_defaults(func=handle_aws_ssm_session_history)

    p = subparsers.command("aws", "response", "cloudtrail-status", help="Check CloudTrail trail status and configuration")
    p.add_argument("--include-shadow-trails", action="store_true", dest="include_shadow_trails",
                   help="Include shadow trails from other regions")
    p.set_defaults(func=handle_aws_cloudtrail_status)

    p = subparsers.command("aws", "forensics", "download-s3-logs",
        help="Download log objects from an S3 bucket/prefix into one flat local folder",
    )
    p.add_argument("--bucket", required=True, help="S3 bucket name")
    p.add_argument("--prefix", default=None, help="Only download keys under this prefix")
    p.add_argument(
        "--destination", required=True, help="Local directory to write files into (created if missing)"
    )
    p.add_argument(
        "--suffix",
        action="append",
        default=None,
        help="Only download keys ending in this suffix (repeatable). Default: .json and .json.gz. "
        "Pass --suffix '' to download every object under the prefix.",
    )
    p.add_argument(
        "--no-decompress",
        action="store_true",
        help="Do not gunzip .gz objects; write them as-is",
    )
    p.add_argument("--max-objects", type=int, default=None, dest="max_objects", help="Stop after downloading this many objects")
    p.add_argument(
        "--start-time",
        default=None,
        help="Only download logs dated on/after this day (ISO 8601). Switches to a date-aware "
        "folder walk instead of listing the whole prefix -- see --days-ago for the common case "
        "of an org/Control Tower CloudTrail bucket laid out as "
        "<account-id>/CloudTrail/<region>/<year>/<month>/<day>/*. Mutually exclusive with --days-ago.",
    )
    p.add_argument("--end-time", default=None, help="Only download logs dated on/before this day (ISO 8601). Defaults to now.")
    p.add_argument(
        "--days-ago",
        type=int,
        default=None,
        dest="days_ago",
        help="Shortcut for --start-time = N days ago. E.g. --days-ago 2 pulls the last 2 days "
        "across every account/region found under --prefix, without listing older history.",
    )
    p.add_argument(
        "--max-workers",
        type=int,
        default=8,
        dest="max_workers",
        help="Concurrency for the folder-discovery phase when --start-time/--days-ago is given",
    )
    p.set_defaults(func=handle_aws_download_s3_logs)

    p = subparsers.command("aws", "hunt", "query-cloudtrail-logs",
        help="Filter/project fields from CloudTrail log files already on disk (offline, no AWS calls)",
    )
    p.add_argument(
        "--path", required=True,
        help="Directory of CloudTrail *.json/*.json.gz log files (e.g. from aws-download-s3-logs), or a single file",
    )
    p.add_argument("--source-ip", default=None, help="Exact match on sourceIPAddress")
    p.add_argument("--user", default=None, help="Match userIdentity.userName, or substring of userIdentity.arn")
    p.add_argument("--access-key-id", default=None, help="Exact match on userIdentity.accessKeyId")
    p.add_argument("--event-name", default=None, help="Exact match on eventName")
    p.add_argument("--event-source", default=None, help="Exact match on eventSource (e.g. s3.amazonaws.com)")
    p.add_argument("--region", default=None, help="Exact match on awsRegion")
    p.add_argument("--account-id", default=None, help="Match userIdentity.accountId or recipientAccountId")
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601), filters on eventTime")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601), filters on eventTime")
    p.add_argument(
        "--fields",
        default=None,
        help="Comma-separated dot-path fields to project, e.g. "
        "eventTime,userIdentity.accountId,userIdentity.arn,sourceIPAddress. "
        "Default: eventTime,userIdentity.accountId,userIdentity.arn,"
        "userIdentity.accessKeyId,eventSource,eventName,awsRegion,userAgent",
    )
    p.add_argument("--max-events", type=int, default=None, dest="max_events", help="Cap on matched records returned (default: unlimited)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_aws_query_cloudtrail_logs)

    p = subparsers.command("aws", "hunt", "security-groups-by-ip",
        help="Find security groups with ingress/egress rules covering one or more IPs",
    )
    p.add_argument(
        "--ip",
        action="append",
        required=True,
        help="IP address or CIDR to search for. Comma-separated and/or repeatable: "
        "--ip 1.2.3.4,10.0.0.0/8 or --ip 1.2.3.4 --ip 10.0.0.0/8.",
    )
    p.add_argument(
        "--direction",
        choices=["inbound", "outbound", "both"],
        default="both",
        help="Only scan inbound (ingress) or outbound (egress) rules. Default: both.",
    )
    p.add_argument("--max-groups", type=int, default=500, dest="max_groups", help="Maximum security groups to scan")
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print the full result (rules, ports, protocols, statistics) instead of the summary table",
    )
    p.add_argument("--output", choices=["json", "csv"], default="json", help="Format used with --verbose")
    p.set_defaults(func=handle_aws_hunt_security_groups_by_ip)

    p = subparsers.command("aws", "hunt", "exposed-secrets",
        help="Scan Lambda/ECS/SSM/EC2 user-data/CodeBuild for plaintext secrets",
    )
    p.add_argument(
        "--include",
        action="append",
        choices=["lambda", "ecs", "ssm", "ec2_user_data", "codebuild"],
        default=None,
        help="Restrict scan to these source(s) (repeatable). Default: scan all five.",
    )
    p.add_argument(
        "--test",
        action="store_true",
        help="Verify every detected AWS access-key + secret-key pair live via "
        "sts:GetCallerIdentity (read-only; no other API is called). Off by default.",
    )
    p.add_argument(
        "--unredacted",
        default=None,
        metavar="PATH",
        help="Write raw plaintext values (hash -> value) to this file, mode 0600, "
        "for a rotation worklist. Excluded from the printed result. Handle the file "
        "as sensitive.",
    )
    p.add_argument(
        "--max-ec2-instances",
        type=int,
        default=500,
        dest="max_ec2_instances",
        help="Cap on EC2 instances scanned for user-data",
    )
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_aws_hunt_exposed_secrets)

    p = subparsers.command("aws", "hunt", "cloudwatch-logs", help="Run a CloudWatch Logs Insights query")
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

    p = subparsers.command("aws", "hunt", "cloudtrail", help="Hunt CloudTrail events with simple filters"
    )
    p.add_argument("--user", default=None, help="CloudTrail Username")
    p.add_argument("--access-key-id", default=None, help="AccessKeyId")
    p.add_argument("--event-name", default=None, help="Event name (e.g. ConsoleLogin)")
    p.add_argument(
        "--source-ip",
        default=None,
        help="Source IP address. CloudTrail has no server-side IP filter, so this "
        "is applied client-side. If given without --user/--access-key-id/"
        "--event-name, every event in the time range is scanned for a match "
        "(can be slow — see statistics.truncated in the output).",
    )
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return (per region when fanning out). "
        "Pass 0 for unlimited — keeps paginating until CloudTrail has no more "
        "matching events for the time range.",
    )
    p.add_argument(
        "--all-regions",
        action="store_true",
        dest="all_regions",
        help="Query every region enabled for the account concurrently (LookupEvents "
        "is a regional API). The global --region still sets the base session region.",
    )
    p.add_argument(
        "--regions",
        action="append",
        default=None,
        help="Query these specific regions concurrently. Comma-separated and/or "
        "repeatable: --regions us-east-1,us-east-2 or --regions us-east-1 --regions "
        "eu-west-1 (or a mix). The value 'all' means every enabled region. Distinct "
        "from the global --region, which sets the base session region.",
    )
    p.add_argument(
        "--max-workers",
        type=int,
        default=12,
        dest="max_workers",
        help="Max regions queried concurrently when --all-regions/--regions is used",
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
        help="Search only today's CloudTrail events (UTC)",
    )
    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")

    p.set_defaults(func=handle_aws_hunt_cloudtrail)

    # --- AWS hunt (CloudTrail, multiple users) ---

    p = subparsers.command("aws", "hunt", "cloudtrail-multi-user",
        help="Hunt CloudTrail events for a list of users (repeatable --user and/or --users-file)",
    )
    p.add_argument(
        "--user",
        action="append",
        default=[],
        help="Username to hunt. Comma-separated and/or repeatable: --user alice,bob "
        "or --user alice --user bob.",
    )
    p.add_argument(
        "--users-file",
        default=None,
        help="Path to a file with one username per line (blank lines and lines "
        "starting with # are ignored). Combined with any --user flags.",
    )
    p.add_argument(
        "--mode",
        choices=["per_user", "batch"],
        default="per_user",
        help="per_user (default): keep results grouped by user. batch: also "
        "merge every user's events into one time-sorted list.",
    )
    p.add_argument("--event-name", default=None, help="Event name (e.g. ConsoleLogin)")
    p.add_argument(
        "--source-ip",
        default=None,
        help="Source IP address, applied client-side per user (see 'aws hunt cloudtrail').",
    )
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events-per-user",
        type=int,
        default=500,
        help="Maximum number of events to return per user. Pass 0 for unlimited.",
    )
    p.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop at the first user whose lookup fails instead of continuing with the rest of the list",
    )
    p.add_argument(
        "--output-path",
        default=None,
        help="Stream each user's result to this file as JSON Lines as soon as it completes, "
        "so progress survives a failure partway through a long list",
    )
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.add_argument("--today", action="store_true", help="Search only today's CloudTrail events (UTC)")
    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")
    p.set_defaults(func=handle_aws_hunt_cloudtrail_multi_user)

    # --- AWS hunt (CloudTrail, one user against an IP allowlist) ---

    p = subparsers.command("aws", "hunt", "user-activity-by-ip",
        help="Hunt one user's CloudTrail activity, classifying each event by whether its source IP is in an allowlist",
    )
    p.add_argument("--user", required=True, help="CloudTrail Username to hunt")
    p.add_argument(
        "--allowed-ip",
        action="append",
        default=[],
        help="IP or CIDR the user is expected to operate from. Comma-separated "
        "and/or repeatable: --allowed-ip 10.0.0.0/8,1.2.3.4 or --allowed-ip "
        "10.0.0.0/8 --allowed-ip 1.2.3.4.",
    )
    p.add_argument(
        "--allowed-ips-file",
        default=None,
        help="Path to a file with one IP/CIDR per line (blank lines and lines "
        "starting with # are ignored). Combined with any --allowed-ip flags.",
    )
    p.add_argument("--event-name", default=None, help="Event name (e.g. ConsoleLogin)")
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return. Pass 0 for unlimited.",
    )
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.add_argument("--today", action="store_true", help="Search only today's CloudTrail events (UTC)")
    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")
    p.set_defaults(func=handle_aws_hunt_user_activity_by_ip)

    # --- AWS security review (posture) ---
    #
    # `aws review full` runs headline (tier-1) checks across every service +
    # organization controls (--deep for tier-2 too). `aws review <service>`
    # runs one service, including its deeper tier-2 checks.

    def _add_review_common(pp, *, incident=True, ip=True):
        pp.add_argument("--csv", default=None, help="Write findings to this CSV file")
        pp.add_argument("--html", default=None, help="Write a self-contained HTML report to this file")
        pp.add_argument("--include", action="append", default=None,
                        help="Only run these check ids (comma-separated and/or repeatable)")
        pp.add_argument("--exclude", action="append", default=None,
                        help="Skip these check ids (comma-separated and/or repeatable)")
        pp.add_argument("--all-regions", action="store_true", dest="all_regions",
                        help="Fan out the regional checks (EC2/RDS/Lambda/ECS/org) across every "
                        "enabled region concurrently. Global checks (IAM/S3) still run once.")
        pp.add_argument("--regions", action="append", default=None,
                        help="Fan out regional checks across these regions (comma-separated and/or "
                        "repeatable; 'all' means every enabled region).")
        pp.add_argument("--max-workers", type=int, default=12, dest="max_workers",
                        help="Concurrency for the multi-region fan-out")
        pp.add_argument("--output", choices=["json", "csv"], default="json",
                        help="stdout format for the summary (--csv/--html files are separate)")
        if incident:
            pp.add_argument("--incident-start", default=None,
                            help="Incident start (ISO 8601). Enables the 'resources created since' check.")
        if ip:
            pp.add_argument("--ip", action="append", default=None,
                            help="IP/CIDR to flag security groups referencing it (comma-separated "
                            "and/or repeatable). Enables the ec2-sg-references-ip check.")

    p = subparsers.command("aws", "review", "full",
        help="Full security review across every service + org controls (tier-1; add --deep for tier-2)")
    p.add_argument("--deep", action="store_true",
                   help="Include tier-2 (deeper) checks in the full review")
    _add_review_common(p)
    p.set_defaults(func=handle_aws_review, review_service="full")

    _REVIEW_SERVICE_HELP = {
        "iam": "Review IAM (admins, console-without-MFA, weak role trust, stale access keys)",
        "ec2": "Review EC2/network (world-open critical ports, public snapshots, IMDSv1, SGs referencing an IP)",
        "s3": "Review S3 (public buckets, default encryption)",
        "rds": "Review RDS (public instances, storage encryption)",
        "lambda": "Review Lambda (public function URLs)",
        "ecs": "Review ECS (services with ECS Exec / execute-command enabled)",
        "org": "Review org/account controls (GuardDuty, CloudTrail, VPC flow logs, Security Hub, Access Analyzer)",
        "recent": "Review resources created since --incident-start (IAM users/roles, Lambda, S3)",
    }
    for _svc, _help in _REVIEW_SERVICE_HELP.items():
        p = subparsers.command("aws", "review", _svc, help=_help)
        _add_review_common(p, ip=(_svc == "ec2"))
        p.set_defaults(func=handle_aws_review, review_service=_svc)

    # --- GitHub hunt ---

    p = subparsers.command("github", "hunt", "audit", help="Hunt GitHub org/enterprise audit logs"
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

    p = subparsers.command("github", "response", "block-org-member", help="Block a user from interacting with the org")
    p.add_argument("--username", required=True, help="GitHub username to block")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_block_org_member)

    p = subparsers.command("github", "response", "remove-org-member", help="Remove a user from the organization")
    p.add_argument("--username", required=True, help="GitHub username to remove")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_remove_org_member)

    p = subparsers.command("github", "response", "remove-repo-collaborator", help="Remove a collaborator from a repository")
    p.add_argument("--repo", required=True, help="Repository name (without org prefix)")
    p.add_argument("--username", required=True, help="GitHub username to remove")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_remove_repo_collaborator)

    p = subparsers.command("github", "response", "revoke-deploy-key", help="Revoke a repository deploy key")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--key-id", dest="key_id", type=int, required=True, help="Deploy key ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_revoke_deploy_key)

    p = subparsers.command("github", "response", "delete-org-webhook", help="Delete an organization-level webhook")
    p.add_argument("--hook-id", dest="hook_id", type=int, required=True, help="Webhook ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_delete_org_webhook)

    p = subparsers.command("github", "response", "delete-repo-webhook", help="Delete a repository-level webhook")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--hook-id", dest="hook_id", type=int, required=True, help="Webhook ID (integer)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_delete_repo_webhook)

    p = subparsers.command("github", "response", "archive-repository", help="Archive a repository (make read-only)")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_archive_repository)

    # ---- GitHub extended hunt ----

    p = subparsers.command("github", "hunt", "secret-scanning", help="List secret scanning alerts")
    p.add_argument("--repo", default=None, help="Repository name (omit for all org repos)")
    p.add_argument("--state", default="open", choices=["open", "resolved"], help="Alert state (default: open)")
    p.add_argument("--max-alerts", dest="max_alerts", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_hunt_secret_scanning)

    p = subparsers.command("github", "hunt", "code-scanning", help="List code scanning alerts for a repository")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--state", default="open", help="Alert state: open, dismissed, fixed (default: open)")
    p.add_argument("--max-alerts", dest="max_alerts", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_hunt_code_scanning)

    p = subparsers.command("github", "hunt", "list-org-members", help="List all organization members")
    p.add_argument("--role", default=None, choices=["member", "admin"], help="Filter by role")
    p.add_argument("--max-members", dest="max_members", type=int, default=500)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_org_members)

    p = subparsers.command("github", "hunt", "list-outside-collaborators", help="List users with repo access outside the org")
    p.add_argument("--max-items", dest="max_items", type=int, default=200)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_outside_collaborators)

    p = subparsers.command("github", "hunt", "list-deploy-keys", help="List deploy keys for a repository")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--max-keys", dest="max_keys", type=int, default=100)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_list_deploy_keys)

    # ---- GitHub forensics ----

    p = subparsers.command("github", "forensics", "org-settings", help="Capture org configuration snapshot")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_org_settings)

    p = subparsers.command("github", "forensics", "repo-metadata", help="Capture repository configuration snapshot")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_metadata)

    p = subparsers.command("github", "forensics", "repo-collaborators", help="List all repository collaborators")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--max-items", dest="max_items", type=int, default=200)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_collaborators)

    p = subparsers.command("github", "forensics", "branch-protection", help="Get branch protection rules")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--branch", required=True, help="Branch name (e.g. main)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_branch_protection)

    p = subparsers.command("github", "forensics", "org-webhooks", help="List all organization webhooks")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_org_webhooks)

    p = subparsers.command("github", "forensics", "repo-webhooks", help="List all repository webhooks")
    p.add_argument("--repo", required=True, help="Repository name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_github_forensics_repo_webhooks)

    # ---- Kubernetes response ----

    p = subparsers.command("k8s", "response", "revoke-role-binding", help="Delete a RoleBinding")
    p.add_argument("name", help="RoleBinding name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_revoke_role_binding)

    p = subparsers.command("k8s", "response", "revoke-cluster-role-binding", help="Delete a ClusterRoleBinding")
    p.add_argument("name", help="ClusterRoleBinding name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_revoke_cluster_role_binding)

    p = subparsers.command("k8s", "response", "disable-service-account", help="Delete a ServiceAccount's tokens and bindings")
    p.add_argument("name", help="ServiceAccount name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_disable_service_account)

    p = subparsers.command("k8s", "response", "delete-service-account", help="Disable then delete a ServiceAccount")
    p.add_argument("name", help="ServiceAccount name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_delete_service_account)

    p = subparsers.command("k8s", "response", "delete-pod", help="Force-delete a pod")
    p.add_argument("name", help="Pod name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--grace-period-seconds", type=int, default=0, dest="grace_period_seconds")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_delete_pod)

    p = subparsers.command("k8s", "response", "scale-deployment", help="Scale a Deployment (default: to 0)")
    p.add_argument("name", help="Deployment name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--replicas", type=int, default=0)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_scale_deployment)

    p = subparsers.command("k8s", "response", "cordon-node", help="Mark a node unschedulable")
    p.add_argument("name", help="Node name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_cordon_node)

    p = subparsers.command("k8s", "response", "drain-node", help="Cordon a node and evict its pods")
    p.add_argument("name", help="Node name")
    p.add_argument("--grace-period-seconds", type=int, default=30, dest="grace_period_seconds")
    p.add_argument("--no-ignore-daemonsets", dest="ignore_daemonsets", action="store_false",
                   help="Also evict DaemonSet-owned pods (they will be immediately rescheduled)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_drain_node, ignore_daemonsets=True)

    p = subparsers.command("k8s", "response", "delete-node", help="Remove a Node object from the cluster (not the underlying VM)")
    p.add_argument("name", help="Node name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_delete_node)

    p = subparsers.command("k8s", "response", "quarantine-pod", help="Isolate a pod with a deny-all NetworkPolicy")
    p.add_argument("name", help="Pod name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--policy-name", default="dredge-forensic-isolation", dest="policy_name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_quarantine_pod)

    p = subparsers.command("k8s", "response", "quarantine-namespace", help="Apply a deny-all NetworkPolicy across a namespace")
    p.add_argument("--namespace", default=None)
    p.add_argument("--policy-name", default="dredge-forensic-isolation", dest="policy_name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_quarantine_namespace)

    p = subparsers.command("k8s", "response", "delete-secret", help="Delete a Secret")
    p.add_argument("name", help="Secret name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_delete_secret)

    p = subparsers.command("k8s", "response", "label-resource", help="Apply labels to a pod/node/namespace/deployment")
    p.add_argument("kind", choices=["pod", "node", "namespace", "deployment"])
    p.add_argument("name", help="Resource name")
    p.add_argument("--namespace", default=None, help="Required for kind=pod|deployment")
    p.add_argument("--label", dest="labels_raw", action="append", required=True,
                   help="Label in Key=Value format (repeat for multiple)")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_label_resource)

    # ---- Kubernetes forensics ----

    p = subparsers.command("k8s", "forensics", "get-pod-manifest", help="Capture the full manifest of a pod")
    p.add_argument("name", help="Pod name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_get_pod_manifest)

    p = subparsers.command("k8s", "forensics", "get-pod-logs", help="Capture container logs from a pod")
    p.add_argument("name", help="Pod name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--container", default=None)
    p.add_argument("--previous", action="store_true", help="Get logs from the previous terminated container")
    p.add_argument("--tail-lines", type=int, default=None, dest="tail_lines")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_get_pod_logs)

    p = subparsers.command("k8s", "forensics", "get-pod-events", help="List Events for a pod")
    p.add_argument("name", help="Pod name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_get_pod_events)

    p = subparsers.command("k8s", "forensics", "describe-node", help="Capture the full manifest of a node")
    p.add_argument("name", help="Node name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_describe_node)

    p = subparsers.command("k8s", "forensics", "capture-workload-manifest", help="Capture a workload controller's manifest")
    p.add_argument("kind", choices=["deployment", "statefulset", "daemonset"])
    p.add_argument("name", help="Workload name")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_capture_workload_manifest)

    p = subparsers.command("k8s", "forensics", "list-pods-on-node", help="List pods scheduled to a node")
    p.add_argument("name", help="Node name")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_list_pods_on_node)

    p = subparsers.command("k8s", "forensics", "exec-pod-command", help="Run a diagnostic command in a pod (best-effort)")
    p.add_argument("name", help="Pod name")
    p.add_argument("command", nargs="+", help="Command and arguments to run")
    p.add_argument("--namespace", default=None)
    p.add_argument("--container", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_exec_pod_command)

    # ---- Kubernetes hunt ----

    p = subparsers.command("k8s", "hunt", "events", help="Search Kubernetes Events")
    p.add_argument("--namespace", default=None, help="Omit for cluster-wide search")
    p.add_argument("--involved-object-kind", dest="involved_object_kind", default=None)
    p.add_argument("--involved-object-name", dest="involved_object_name", default=None)
    p.add_argument("--reason", default=None)
    p.add_argument("--event-type", dest="event_type", default=None, help="Normal or Warning")
    p.add_argument("--start-time", default=None, help="ISO 8601 start time")
    p.add_argument("--end-time", default=None, help="ISO 8601 end time")
    p.add_argument("--max-events", type=int, default=500, dest="max_events")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_hunt_events)

    p = subparsers.command("k8s", "hunt", "role-bindings-for-subject", help="Find RoleBindings/ClusterRoleBindings referencing a subject")
    p.add_argument("--kind", required=True, help='Subject kind: "User", "Group", or "ServiceAccount"')
    p.add_argument("--name", required=True, help="Subject name")
    p.add_argument("--namespace", default=None, help="Omit to search cluster-wide")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_hunt_role_bindings_for_subject)

    p = subparsers.command("k8s", "hunt", "pods-by-service-account", help="List pods running under a ServiceAccount")
    p.add_argument("--service-account", required=True, dest="service_account")
    p.add_argument("--namespace", default=None)
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_hunt_pods_by_service_account)

    p = subparsers.command("k8s", "hunt", "privileged-pods", help="Flag pods with elevated host access")
    p.add_argument("--max-pods", type=int, default=500, dest="max_pods")
    p.add_argument("--output", choices=["json", "csv"], default="json")
    p.set_defaults(func=handle_k8s_hunt_privileged_pods)

    # Used by the grouped `dredge -h` overview (_print_grouped_help).
    parser._dredge_commands = subparsers.commands

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
    if func is None:  # pragma: no cover -- unreachable: every subparser sets func, and subparsers.add_subparsers(required=True) makes argparse itself raise SystemExit(2) before main() ever sees a commandless Namespace
        parser.print_help()
        raise SystemExit(1)
    try:
        func(args)
    except ValueError as exc:
        # Validation errors raised by the library (bad IP, missing filter,
        # unknown scanner, etc.) — a one-line message beats a stack trace.
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":  # pragma: no cover -- only executes via `python -m dredge.cli`, not on import; exercising it needs a different (subprocess) test mechanism for 1 line of value
    main()

