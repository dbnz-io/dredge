"""
Security review: a read-only posture assessment for AWS.

Two ways to run it:

  * **Full review** across every service plus organization-wide controls
    (GuardDuty on? CloudTrail logging? VPC flow logs?), for the fast "where do I
    stand" snapshot — headline (tier-1) findings by default, `deep=True` to
    include the second layer (tier-2).
  * **Targeted review** of a single service (`iam`, `ec2`, `s3`, `rds`,
    `lambda`, `org`, `recent`), which always includes that service's deeper
    second-layer checks.

Every check is tagged with a `service` and a `tier` (1 = headline, 2 = deeper).
Checks compose the existing `AwsIRHunt` capabilities where they exist and add the
rest. Each check is defensive: a per-check permission/API error is recorded and
the others still run, so a partial review is always better than nothing.

Findings roll up into `OperationResult.details` and can be written as CSV or a
self-contained HTML report. Regional checks (EC2/RDS/Lambda) use the session
region; IAM/S3/org(some) are global.
"""
from __future__ import annotations

import html
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import botocore.exceptions

from ..config import DredgeConfig
from ..log import get_logger, event
from .services import AwsServiceRegistry
from .hunt import AwsIRHunt
from .models import OperationResult

_log = get_logger(__name__)

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_CRITICAL_PORTS = [22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 11211, 2375, 5900, 23, 21, 445]

_STALE_KEY_DAYS = 90

# Services a review can target. "recent" is incident-relative; "org" is
# account/region-wide guardrails.
SERVICES = ["iam", "ec2", "s3", "rds", "lambda", "ecs", "org", "recent"]


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    resource_type: str
    resource_id: str
    recommendation: str
    service: str = ""       # set by run() from the check registry
    tier: int = 0           # set by run()
    region: Optional[str] = None
    created_time: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)


class AwsIRReview:
    """Read-only posture review producing prioritized `Finding`s."""

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig,
                 hunt: Optional[AwsIRHunt] = None) -> None:
        self._services = services
        self._config = config
        self._hunt = hunt or AwsIRHunt(services, config)

    # check_id -> (service, tier, method_name, needs_incident_start, scope)
    # scope "global" runs once; "regional" runs per region when fanning out.
    _CHECKS = [
        ("iam-admin-principals", "iam", 1, "_check_admin_principals", False, "global"),
        ("iam-console-without-mfa", "iam", 1, "_check_console_without_mfa", False, "global"),
        ("iam-weak-role-trust", "iam", 1, "_check_weak_role_trust", False, "global"),
        ("iam-stale-access-keys", "iam", 2, "_check_stale_access_keys", False, "global"),
        ("s3-public-buckets", "s3", 1, "_check_public_s3", False, "global"),
        ("s3-no-default-encryption", "s3", 2, "_check_s3_encryption", False, "global"),
        ("rds-public-instances", "rds", 1, "_check_public_rds", False, "regional"),
        ("rds-unencrypted", "rds", 2, "_check_rds_encryption", False, "regional"),
        ("ec2-open-critical-ports", "ec2", 1, "_check_open_critical_ports", False, "regional"),
        ("ec2-public-snapshots", "ec2", 1, "_check_public_snapshots", False, "regional"),
        ("ec2-imdsv1-allowed", "ec2", 2, "_check_imdsv1", False, "regional"),
        ("ec2-instance-connect-endpoints", "ec2", 2, "_check_instance_connect", False, "regional"),
        ("ec2-sg-references-ip", "ec2", 2, "_check_sg_by_ip", False, "regional"),
        ("lambda-public-function-urls", "lambda", 1, "_check_lambda_function_urls", False, "regional"),
        ("ecs-execute-command-enabled", "ecs", 1, "_check_ecs_exec", False, "regional"),
        ("org-guardduty-enabled", "org", 1, "_check_guardduty", False, "regional"),
        ("org-cloudtrail-logging", "org", 1, "_check_cloudtrail", False, "regional"),
        ("org-vpc-flow-logs", "org", 1, "_check_vpc_flow_logs", False, "regional"),
        ("org-security-hub-enabled", "org", 2, "_check_security_hub", False, "regional"),
        ("org-access-analyzer", "org", 2, "_check_access_analyzer", False, "regional"),
        ("recent-resources", "recent", 1, "_check_recently_created", True, "global"),
    ]

    def review(
        self,
        *,
        services=None,
        tiers=(1, 2),
        incident_start: Optional[datetime] = None,
        ips: Optional[List[str]] = None,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        regions=None,
        max_workers: int = 12,
    ) -> OperationResult:
        """
        Run the review.

        Args:
            services: None / "all" for every service, or a list to target
                specific services (e.g. ["iam"]).
            tiers: which tiers to run — (1,) headline only, (1, 2) full depth.
            incident_start: enables the `recent` service (resources created
                since this time). Time-relative checks are skipped without it.
            ips: for `ec2-sg-references-ip` — security groups referencing these
                IPs/CIDRs are flagged. Skipped when not provided.
            include / exclude: check ids to force-in / force-out.
            regions: None → the session region only. A list, or "all" (every
                enabled region), fans out the **regional** checks (EC2/RDS/
                Lambda/ECS/org guardrails) across those regions concurrently;
                global checks (IAM/S3) still run once. Findings carry their
                region.
            max_workers: concurrency for the regional fan-out.

        Returns:
            OperationResult with details["findings"] (sorted by severity),
            details["summary"], details["checks"] (per-check status, with a
            per-region breakdown when fanning out), details["meta"].
        """
        target = set(SERVICES) if (services is None or services == "all") else set(services)
        tiers = set(tiers)

        # Which checks are selected, by scope.
        selected = []
        skipped: Dict[str, Dict[str, Any]] = {}
        for check_id, service, tier, method_name, needs_start, scope in self._CHECKS:
            if service not in target or tier not in tiers:
                continue
            if include is not None and check_id not in include:
                continue
            if exclude and check_id in exclude:
                continue
            if needs_start and incident_start is None:
                skipped[check_id] = {"status": "skipped", "reason": "no incident_start", "count": 0}
                continue
            if check_id == "ec2-sg-references-ip" and not ips:
                skipped[check_id] = {"status": "skipped", "reason": "no --ip given", "count": 0}
                continue
            selected.append((check_id, service, tier, method_name, scope))

        # Resolve the region list for the regional fan-out.
        if regions is None:
            region_list = None  # single-region: run regional checks against base services
        elif regions == "all":
            region_list = self._services.resolve_enabled_regions()
        else:
            region_list = list(dict.fromkeys(regions))

        result = OperationResult(operation="review", target="aws-account", success=True)
        findings: List[Finding] = []
        checks_status: Dict[str, Dict[str, Any]] = dict(skipped)

        def _run(review_obj, check_id, method_name, service, tier, region):
            try:
                produced = getattr(review_obj, method_name)(incident_start=incident_start, ips=ips)
                for f in produced:
                    f.service, f.tier = service, tier
                    if region and not f.region:
                        f.region = region
                return produced, None
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
                return [], str(exc)

        # Global checks: once, against the base services.
        for check_id, service, tier, method_name, scope in selected:
            if scope != "global":
                continue
            produced, error = _run(self, check_id, method_name, service, tier, None)
            findings.extend(produced)
            checks_status[check_id] = {"status": "ran", "count": len(produced)} if error is None \
                else {"status": "failed", "count": 0, "error": error}
            if error:
                result.add_error(f"{check_id}: {error}")

        regional_selected = [c for c in selected if c[4] == "regional"]
        if regional_selected:
            if region_list is None:
                # Single region: run against base services once.
                for check_id, service, tier, method_name, _s in regional_selected:
                    produced, error = _run(self, check_id, method_name, service, tier, None)
                    findings.extend(produced)
                    checks_status[check_id] = {"status": "ran", "count": len(produced)} if error is None \
                        else {"status": "failed", "count": 0, "error": error}
                    if error:
                        result.add_error(f"{check_id}: {error}")
            else:
                # Multi-region fan-out: one region-scoped review per region.
                def _region_worker(region):
                    robj = AwsIRReview(self._services.regional(region), self._config)
                    per = {}
                    got: List[Finding] = []
                    for check_id, service, tier, method_name, _s in regional_selected:
                        produced, error = _run(robj, check_id, method_name, service, tier, region)
                        got.extend(produced)
                        per[check_id] = {"count": len(produced)} if error is None else {"error": error}
                    return region, got, per

                agg: Dict[str, Dict[str, Any]] = {c[0]: {"by_region": {}} for c in regional_selected}
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    for region, got, per in pool.map(_region_worker, region_list):
                        findings.extend(got)
                        for cid, info in per.items():
                            agg[cid]["by_region"][region] = info
                for cid, info in agg.items():
                    total = sum(v.get("count", 0) for v in info["by_region"].values())
                    errors = {r: v["error"] for r, v in info["by_region"].items() if "error" in v}
                    info["status"] = "failed" if errors and total == 0 else ("partial" if errors else "ran")
                    info["count"] = total
                    if errors:
                        result.add_error(f"{cid}: failed in {len(errors)} region(s)")
                    checks_status[cid] = info

        findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.service, f.check_id,
                                     f.region or "", f.resource_id))

        summary: Dict[str, int] = {}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1

        result.details["findings"] = [asdict(f) for f in findings]
        result.details["summary"] = summary
        result.details["checks"] = checks_status
        result.details["total_findings"] = len(findings)
        result.details["meta"] = {
            "account_id": self._account_id(),
            "region": getattr(self._services._session, "region_name", None),
            "regions": region_list,
            "services": sorted(target),
            "tiers": sorted(tiers),
            "incident_start": incident_start.isoformat() if incident_start else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        _log.info(event("aws_ir_review", "complete", total=len(findings), regions=len(region_list or []), **summary))
        return result

    def _account_id(self) -> Optional[str]:
        try:
            return self._services.sts.get_caller_identity().get("Account")
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError):
            return None

    # ------------------------------------------------------------------ #
    # IAM
    # ------------------------------------------------------------------ #

    def _check_admin_principals(self, **_) -> List[Finding]:
        res = self._hunt.list_iam_admin_principals()
        out: List[Finding] = []
        for name in res.details.get("admin_users", []):
            out.append(_f("iam-admin-principals", "IAM user with administrator-equivalent access",
                          "HIGH", "AWS::IAM::User", name,
                          "Confirm this admin is expected; scope down or enforce strong MFA."))
        for name in res.details.get("admin_roles", []):
            out.append(_f("iam-admin-principals", "IAM role with administrator-equivalent access",
                          "HIGH", "AWS::IAM::Role", name,
                          "Confirm this admin role is expected and its trust policy is tight."))
        return out

    def _check_console_without_mfa(self, **_) -> List[Finding]:
        res = self._hunt.get_iam_credential_report()
        out: List[Finding] = []
        for row in res.details.get("users", []):
            if str(row.get("password_enabled")).lower() == "true" and str(row.get("mfa_active")).lower() != "true":
                out.append(_f("iam-console-without-mfa", "IAM user with console access and no MFA",
                              "CRITICAL", "AWS::IAM::User", row.get("user", "?"),
                              "Enforce MFA or disable console access immediately.",
                              detail={"password_last_used": row.get("password_last_used")}))
        return out

    def _check_weak_role_trust(self, **_) -> List[Finding]:
        iam = self._services.iam
        out: List[Finding] = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                doc = _decode_policy(role.get("AssumeRolePolicyDocument"))
                for stmt in _as_list(doc.get("Statement")):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal")
                    aws = _as_list((principal or {}).get("AWS") if isinstance(principal, dict) else principal)
                    if principal == "*" or "*" in aws:
                        out.append(_f("iam-weak-role-trust", "IAM role trusts any principal (Principal: *)",
                                      "CRITICAL", "AWS::IAM::Role", role.get("RoleName", "?"),
                                      "Restrict the trust policy to specific principals; add conditions.",
                                      detail={"statement": stmt}))
                    elif aws and not stmt.get("Condition"):
                        out.append(_f("iam-weak-role-trust", "IAM role trusts an AWS account with no conditions",
                                      "HIGH", "AWS::IAM::Role", role.get("RoleName", "?"),
                                      "Add a condition (e.g. sts:ExternalId) or narrow the trusted principal.",
                                      detail={"trusted": aws}))
        return out

    def _check_stale_access_keys(self, **_) -> List[Finding]:
        res = self._hunt.get_iam_credential_report()
        cutoff = datetime.now(timezone.utc) - timedelta(days=_STALE_KEY_DAYS)
        out: List[Finding] = []
        for row in res.details.get("users", []):
            for n in ("1", "2"):
                if str(row.get(f"access_key_{n}_active")).lower() != "true":
                    continue
                rotated = _parse_time(row.get(f"access_key_{n}_last_rotated"))
                if rotated and rotated < cutoff:
                    out.append(_f("iam-stale-access-keys",
                                  f"IAM access key not rotated in {_STALE_KEY_DAYS}+ days",
                                  "MEDIUM", "AWS::IAM::AccessKey", f"{row.get('user','?')}#key{n}",
                                  "Rotate or deactivate long-lived access keys.",
                                  detail={"last_rotated": _iso(rotated)}))
        return out

    # ------------------------------------------------------------------ #
    # S3
    # ------------------------------------------------------------------ #

    def _check_public_s3(self, **_) -> List[Finding]:
        res = self._hunt.hunt_exposed_s3_buckets()
        return [
            _f("s3-public-buckets", "Publicly exposed S3 bucket", "CRITICAL",
               "AWS::S3::Bucket", e.get("bucket", "?"),
               "Enable Block Public Access; review bucket policy/ACL and access logs.",
               detail={"reason": e.get("reason")})
            for e in res.details.get("buckets", []) if e.get("exposed")
        ]

    def _check_s3_encryption(self, **_) -> List[Finding]:
        s3 = self._services.s3
        out: List[Finding] = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b.get("Name")
            try:
                s3.get_bucket_encryption(Bucket=name)
            except botocore.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    out.append(_f("s3-no-default-encryption", "S3 bucket without default encryption",
                                  "MEDIUM", "AWS::S3::Bucket", name,
                                  "Enable default SSE (SSE-S3 or SSE-KMS) on the bucket."))
                elif code in ("AccessDenied", "AccessDeniedException"):
                    continue
                else:
                    raise
        return out

    # ------------------------------------------------------------------ #
    # RDS
    # ------------------------------------------------------------------ #

    def _check_public_rds(self, **_) -> List[Finding]:
        rds = self._services.rds
        region = getattr(rds.meta, "region_name", None)
        out: List[Finding] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                if db.get("PubliclyAccessible"):
                    out.append(_f("rds-public-instances", "Publicly accessible RDS instance",
                                  "CRITICAL", "AWS::RDS::DBInstance", db.get("DBInstanceIdentifier", "?"),
                                  "Set PubliclyAccessible=false and restrict the security group.",
                                  region=region,
                                  detail={"engine": db.get("Engine"),
                                          "endpoint": (db.get("Endpoint") or {}).get("Address")}))
        return out

    def _check_rds_encryption(self, **_) -> List[Finding]:
        rds = self._services.rds
        region = getattr(rds.meta, "region_name", None)
        out: List[Finding] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                if not db.get("StorageEncrypted"):
                    out.append(_f("rds-unencrypted", "RDS instance without storage encryption",
                                  "HIGH", "AWS::RDS::DBInstance", db.get("DBInstanceIdentifier", "?"),
                                  "Encryption can only be set at creation — restore into an encrypted instance.",
                                  region=region))
        return out

    # ------------------------------------------------------------------ #
    # EC2 / network
    # ------------------------------------------------------------------ #

    def _check_open_critical_ports(self, **_) -> List[Finding]:
        res = self._hunt.list_open_security_groups(ports=_CRITICAL_PORTS)
        return [
            _f("ec2-open-critical-ports", "Security group open to 0.0.0.0/0 on a sensitive port",
               "CRITICAL", "AWS::EC2::SecurityGroup", g.get("group_id", "?"),
               "Restrict the source CIDR to known ranges; remove world-open rules.", detail=g)
            for g in res.details.get("open_groups", [])
        ]

    def _check_public_snapshots(self, **_) -> List[Finding]:
        res = self._hunt.list_public_snapshots()
        return [
            _f("ec2-public-snapshots", "Publicly restorable snapshot", "HIGH",
               "AWS::EC2::Snapshot", s.get("snapshot_id", "?"),
               "Remove public sharing; snapshots can leak entire volumes.", detail=s)
            for s in res.details.get("snapshots", [])
        ]

    def _check_imdsv1(self, **_) -> List[Finding]:
        ec2 = self._services.ec2
        region = getattr(ec2.meta, "region_name", None)
        out: List[Finding] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if (inst.get("MetadataOptions") or {}).get("HttpTokens") != "required":
                        out.append(_f("ec2-imdsv1-allowed", "EC2 instance allows IMDSv1 (token not required)",
                                      "MEDIUM", "AWS::EC2::Instance", inst.get("InstanceId", "?"),
                                      "Require IMDSv2 (HttpTokens=required) to blunt SSRF credential theft.",
                                      region=region))
        return out

    def _check_sg_by_ip(self, *, ips=None, **_) -> List[Finding]:
        res = self._hunt.hunt_security_groups_by_ip(ips, direction="both")
        out: List[Finding] = []
        for m in res.details.get("matches", []):
            out.append(_f("ec2-sg-references-ip", "Security group references a supplied IP/CIDR",
                          "HIGH", "AWS::EC2::SecurityGroup", m.get("group_id", "?"),
                          "Confirm this rule is expected; remove if the IP is attacker-related.",
                          detail=m))
        return out

    # ------------------------------------------------------------------ #
    # Lambda
    # ------------------------------------------------------------------ #

    def _check_lambda_function_urls(self, **_) -> List[Finding]:
        lam = self._services.lambda_
        region = getattr(lam.meta, "region_name", None)
        out: List[Finding] = []
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                name = fn.get("FunctionName")
                try:
                    cfg = lam.get_function_url_config(FunctionName=name)
                except botocore.exceptions.ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                        continue
                    raise
                public = cfg.get("AuthType") == "NONE"
                out.append(_f("lambda-public-function-urls",
                              "Lambda function URL" + (" with no auth (public)" if public else " (IAM-authed)"),
                              "CRITICAL" if public else "MEDIUM", "AWS::Lambda::Function", name,
                              "Remove the function URL or require AWS_IAM auth if not intentionally public.",
                              region=region, detail={"auth_type": cfg.get("AuthType"), "url": cfg.get("FunctionUrl")}))
        return out

    # ------------------------------------------------------------------ #
    # ECS
    # ------------------------------------------------------------------ #

    def _check_ecs_exec(self, **_) -> List[Finding]:
        ecs = self._services.ecs
        region = getattr(ecs.meta, "region_name", None)
        out: List[Finding] = []
        for cpage in ecs.get_paginator("list_clusters").paginate():
            for cluster in cpage.get("clusterArns", []):
                svc_arns: List[str] = []
                for spage in ecs.get_paginator("list_services").paginate(cluster=cluster):
                    svc_arns.extend(spage.get("serviceArns", []))
                for i in range(0, len(svc_arns), 10):  # describe_services takes <=10
                    desc = ecs.describe_services(cluster=cluster, services=svc_arns[i:i + 10])
                    for s in desc.get("services", []):
                        if s.get("enableExecuteCommand"):
                            out.append(_f("ecs-execute-command-enabled",
                                          "ECS service has ECS Exec (execute-command) enabled",
                                          "HIGH", "AWS::ECS::Service", s.get("serviceName", "?"),
                                          "ECS Exec gives an interactive shell into running tasks — confirm it's "
                                          "intended and tightly scoped by IAM; a stolen role could use it for RCE.",
                                          region=region, detail={"cluster": cluster}))
        return out

    # ------------------------------------------------------------------ #
    # EC2 Instance Connect
    # ------------------------------------------------------------------ #

    def _check_instance_connect(self, **_) -> List[Finding]:
        """EC2 Instance Connect Endpoints let a caller open SSH/RDP to *private*
        instances via the AWS API (SendSSHPublicKey), bypassing public IPs — an
        IR-relevant capability worth confirming."""
        ec2 = self._services.ec2
        region = getattr(ec2.meta, "region_name", None)
        out: List[Finding] = []
        token = None
        while True:
            kw = {} if token is None else {"NextToken": token}
            resp = ec2.describe_instance_connect_endpoints(**kw)
            for eice in resp.get("InstanceConnectEndpoints", []):
                out.append(_f("ec2-instance-connect-endpoints", "EC2 Instance Connect Endpoint present",
                              "MEDIUM", "AWS::EC2::InstanceConnectEndpoint",
                              eice.get("InstanceConnectEndpointId", "?"),
                              "EICE enables SSH/RDP to private instances via the API — confirm it's expected "
                              "and restricted (ec2-instance-connect:OpenTunnel) by IAM.",
                              region=region, detail={"vpc": eice.get("VpcId"), "state": eice.get("State")}))
            token = resp.get("NextToken")
            if not token or not isinstance(token, str):
                break
        return out

    # ------------------------------------------------------------------ #
    # Organization / account guardrails (a finding == the control is missing)
    # ------------------------------------------------------------------ #

    def _check_guardduty(self, **_) -> List[Finding]:
        detectors = self._services.guardduty.list_detectors().get("DetectorIds", [])
        if not detectors:
            return [_f("org-guardduty-enabled", "GuardDuty is not enabled in this region",
                       "HIGH", "AWS::GuardDuty::Detector", "(none)",
                       "Enable GuardDuty for continuous threat detection.")]
        return []

    def _check_cloudtrail(self, **_) -> List[Finding]:
        ct = self._services.cloudtrail
        trails = ct.describe_trails().get("trailList", [])
        logging_any = False
        for t in trails:
            try:
                if ct.get_trail_status(Name=t.get("TrailARN") or t.get("Name")).get("IsLogging"):
                    logging_any = True
                    break
            except botocore.exceptions.ClientError:
                continue
        if not logging_any:
            return [_f("org-cloudtrail-logging", "No CloudTrail trail is actively logging",
                       "HIGH", "AWS::CloudTrail::Trail", "(none)",
                       "Enable a multi-region CloudTrail with log file validation.")]
        return []

    def _check_vpc_flow_logs(self, **_) -> List[Finding]:
        ec2 = self._services.ec2
        region = getattr(ec2.meta, "region_name", None)
        with_logs = set()
        for page in ec2.get_paginator("describe_flow_logs").paginate():
            for fl in page.get("FlowLogs", []):
                with_logs.add(fl.get("ResourceId"))
        out: List[Finding] = []
        for page in ec2.get_paginator("describe_vpcs").paginate():
            for vpc in page.get("Vpcs", []):
                if vpc.get("VpcId") not in with_logs:
                    out.append(_f("org-vpc-flow-logs", "VPC without flow logs", "MEDIUM",
                                  "AWS::EC2::VPC", vpc.get("VpcId", "?"),
                                  "Enable VPC flow logs to CloudWatch or S3 for network visibility.",
                                  region=region))
        return out

    def _check_security_hub(self, **_) -> List[Finding]:
        try:
            self._services.securityhub.describe_hub()
            return []
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("InvalidAccessException", "ResourceNotFoundException"):
                return [_f("org-security-hub-enabled", "Security Hub is not enabled in this region",
                           "MEDIUM", "AWS::SecurityHub::Hub", "(none)",
                           "Enable Security Hub to aggregate findings across services.")]
            raise

    def _check_access_analyzer(self, **_) -> List[Finding]:
        analyzers = self._services.accessanalyzer.list_analyzers().get("analyzers", [])
        if not analyzers:
            return [_f("org-access-analyzer", "IAM Access Analyzer has no analyzer in this region",
                       "MEDIUM", "AWS::AccessAnalyzer::Analyzer", "(none)",
                       "Create an Access Analyzer to detect external/cross-account access.")]
        return []

    # ------------------------------------------------------------------ #
    # Recently created (incident-relative)
    # ------------------------------------------------------------------ #

    def _check_recently_created(self, *, incident_start: datetime, **_) -> List[Finding]:
        out: List[Finding] = []
        iam = self._services.iam
        for page in iam.get_paginator("list_users").paginate():
            for u in page.get("Users", []):
                if _after(u.get("CreateDate"), incident_start):
                    out.append(_new_res("AWS::IAM::User", u.get("UserName"), u.get("CreateDate")))
        for page in iam.get_paginator("list_roles").paginate():
            for r in page.get("Roles", []):
                if _after(r.get("CreateDate"), incident_start):
                    out.append(_new_res("AWS::IAM::Role", r.get("RoleName"), r.get("CreateDate")))
        lam = self._services.lambda_
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                if _after(_parse_time(fn.get("LastModified")), incident_start):
                    out.append(_new_res("AWS::Lambda::Function", fn.get("FunctionName"), fn.get("LastModified")))
        for b in self._services.s3.list_buckets().get("Buckets", []):
            if _after(b.get("CreationDate"), incident_start):
                out.append(_new_res("AWS::S3::Bucket", b.get("Name"), b.get("CreationDate")))
        return out

    # ------------------------------------------------------------------ #
    # Report output
    # ------------------------------------------------------------------ #

    @staticmethod
    def to_csv(result: OperationResult, path: str) -> None:
        import csv
        findings = result.details.get("findings", [])
        cols = ["severity", "service", "tier", "check_id", "resource_type", "resource_id",
                "region", "created_time", "title", "recommendation", "detail"]
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            for f in findings:
                row = {k: f.get(k, "") for k in cols}
                row["detail"] = json.dumps(f.get("detail", {}), default=str)
                w.writerow(row)

    @staticmethod
    def to_html(result: OperationResult, path: str) -> None:
        with open(path, "w") as fh:
            fh.write(_render_html(result))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _f(check_id, title, severity, rtype, rid, recommendation, *, region=None, detail=None) -> Finding:
    return Finding(check_id=check_id, title=title, severity=severity, resource_type=rtype,
                   resource_id=rid or "?", recommendation=recommendation, region=region,
                   detail=detail or {})


def _new_res(rtype: str, rid: Optional[str], created) -> Finding:
    return Finding(
        check_id="recent-resources",
        title=f"{rtype.split('::')[-1]} created after the incident start",
        severity="HIGH", resource_type=rtype, resource_id=rid or "?", created_time=_iso(created),
        recommendation="Verify this resource is authorized; new resources during an incident are prime suspects.",
    )


def _decode_policy(doc) -> Dict[str, Any]:
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except (ValueError, TypeError):
            return {}
    return {}


def _as_list(v) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _parse_time(v) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _after(when, start: datetime) -> bool:
    dt = _parse_time(when)
    if dt is None or start is None:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    return dt >= start


def _iso(v) -> Optional[str]:
    dt = _parse_time(v)
    return dt.isoformat() if dt else (v if isinstance(v, str) else None)


_SEVERITY_COLOR = {"CRITICAL": "#b00020", "HIGH": "#d9640a", "MEDIUM": "#c9a400", "LOW": "#3a7", "INFO": "#567"}


def _render_html(result: OperationResult) -> str:
    findings = result.details.get("findings", [])
    summary = result.details.get("summary", {})
    meta = result.details.get("meta", {})
    checks = result.details.get("checks", {})

    def esc(x) -> str:
        return html.escape("" if x is None else str(x))

    chips = "".join(
        f'<span class="chip" style="background:{_SEVERITY_COLOR.get(sev,"#567")}">{esc(sev)}: {summary.get(sev,0)}</span>'
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if summary.get(sev)
    ) or '<span class="chip" style="background:#3a7">No findings</span>'

    rows = "".join(
        f'<tr data-sev="{esc(f.get("severity"))}" data-svc="{esc(f.get("service"))}">'
        f'<td><span class="sev" style="background:{_SEVERITY_COLOR.get(f.get("severity"),"#567")}">{esc(f.get("severity"))}</span></td>'
        f'<td>{esc(f.get("service"))}</td><td>T{esc(f.get("tier"))}</td>'
        f'<td>{esc(f.get("check_id"))}</td>'
        f'<td class="mono">{esc(f.get("resource_id"))}</td>'
        f'<td>{esc(f.get("region") or "")}</td>'
        f'<td>{esc(f.get("title"))}<div class="rec">{esc(f.get("recommendation"))}</div></td></tr>'
        for f in findings
    )

    check_rows = "".join(
        f'<tr><td class="mono">{esc(cid)}</td><td>{esc(c.get("status"))}</td>'
        f'<td>{esc(c.get("count"))}</td><td>{esc(c.get("error") or c.get("reason") or "")}</td></tr>'
        for cid, c in checks.items()
    )

    svc_buttons = "".join(
        f'<button class="filter svc" data-k="svc" data-v="{esc(s)}">{esc(s)}</button>'
        for s in meta.get("services", [])
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dredge — Security Review</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px; }}
h1 {{ margin: 0 0 4px; font-size: 22px; }}
.meta {{ color: #888; margin-bottom: 16px; }}
.chip {{ color: #fff; padding: 4px 10px; border-radius: 12px; margin-right: 8px; font-weight: 600; }}
.chips, .controls {{ margin: 12px 0; }}
button {{ font: inherit; padding: 4px 10px; margin: 0 6px 6px 0; border: 1px solid #8886; border-radius: 6px; background: transparent; cursor: pointer; }}
button.active {{ background: #8883; font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #8883; vertical-align: top; }}
th {{ position: sticky; top: 0; background: Canvas; }}
.sev {{ color: #fff; padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 700; }}
.mono {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px; }}
.rec {{ color: #888; font-size: 12px; margin-top: 2px; }}
.small {{ color: #888; font-size: 12px; }}
details {{ margin-top: 24px; }}
</style></head>
<body>
<h1>Dredge — Security Review</h1>
<div class="meta">
  Account <b>{esc(meta.get('account_id'))}</b> · region <b>{esc(meta.get('region'))}</b> ·
  services <b>{esc(', '.join(meta.get('services', [])))}</b> · tiers <b>{esc(meta.get('tiers'))}</b> ·
  generated {esc(meta.get('generated_at'))}
  {('· incident start <b>' + esc(meta.get('incident_start')) + '</b>') if meta.get('incident_start') else ''}
</div>
<div class="chips">{chips}</div>
<div class="controls">
  <b class="small">Severity:</b>
  <button class="filter active" data-k="sev" data-v="ALL">All ({len(findings)})</button>
  {''.join(f'<button class="filter" data-k="sev" data-v="{s}">{s}</button>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if summary.get(s))}
  &nbsp; <b class="small">Service:</b>
  <button class="filter svc active" data-k="svc" data-v="ALL">All</button>
  {svc_buttons}
</div>
<table id="t">
<thead><tr><th>Severity</th><th>Service</th><th>Tier</th><th>Check</th><th>Resource</th><th>Region</th><th>Finding</th></tr></thead>
<tbody>{rows or '<tr><td colspan="7" class="small">No findings — clean, or checks were skipped (see below).</td></tr>'}</tbody>
</table>
<details><summary class="small">Checks run</summary>
<table><thead><tr><th>Check</th><th>Status</th><th>Findings</th><th>Note</th></tr></thead>
<tbody>{check_rows}</tbody></table>
</details>
<script>
const state = {{ sev: 'ALL', svc: 'ALL' }};
function apply() {{
  document.querySelectorAll('#t tbody tr').forEach(tr => {{
    const okS = state.sev === 'ALL' || tr.dataset.sev === state.sev;
    const okV = state.svc === 'ALL' || tr.dataset.svc === state.svc;
    tr.style.display = (okS && okV) ? '' : 'none';
  }});
}}
document.querySelectorAll('.filter').forEach(b => b.onclick = () => {{
  const k = b.dataset.k;
  document.querySelectorAll('.filter[data-k="'+k+'"]').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  state[k] = b.dataset.v;
  apply();
}});
</script>
</body></html>"""
