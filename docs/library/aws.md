# Library — AWS

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

d = Dredge(auth=AwsAuthConfig(profile_name="ir", region_name="us-east-1"))
```

Every call returns an [`OperationResult`](README.md#operationresult).

## Collect + hunt CloudTrail (the fast path)

```python
# 1) Pull the last 2 days of logs across every account/region from an org bucket
d.aws_ir.forensics.download_s3_logs(
    "my-org-cloudtrail",
    prefix="AWSLogs/",
    destination="./ct-logs",
    days_ago=2,
)

# 2) Query them offline (no AWS calls)
res = d.aws_ir.hunt.query_local_cloudtrail_logs(
    "./ct-logs",
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    fields=["eventTime", "eventName", "sourceIPAddress", "userIdentity.arn"],
)
for event in res.details["events"]:
    ...

# 2b) Or triage them into a severity-ranked incident report. Sweeps the curated
#     dangerous eventNames; pass IOCs to also pull IOC-attributable activity and
#     float dangerous+IOC overlaps to the top.
res = d.aws_ir.hunt.incident_local_cloudtrail_logs(
    "./ct-logs",
    ioc_ips=["1.2.3.4", "10.0.0.0/24"],           # exact or CIDR
    ioc_users=["alice", "arn:aws:iam::111:role/foo"],
)
for f in res.details["findings"]:                  # sorted severity desc
    print(f["severity"], f["severity_score"], f["eventName"], f["reasons"])
print(res.details["severity_counts"])              # {"CRITICAL": 2, "HIGH": 5, ...}

# 3) Or hunt live via LookupEvents (last ~90 days)
res = d.aws_ir.hunt.lookup_events(access_key_id="AKIAIOSFODNN7EXAMPLE")
print(res.details["events"])

# 3b) Fan out across regions concurrently (LookupEvents is a regional API).
#     regions="all" (default) queries every enabled region; or pass a list.
res = d.aws_ir.hunt.lookup_events_multi_region(
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    regions="all",                 # or ["us-east-1", "eu-west-1"]
)
res.details["events"]              # merged, time-sorted across regions
res.details["by_region"]           # per-region counts + any errors
```

### Baseline-deviation hunts

```python
# One identity, classified against an IP allowlist
res = d.aws_ir.hunt.hunt_user_activity_by_ip(
    "deploy-bot",
    allowed_ips=["10.0.0.0/8", "203.0.113.10"],
)
res.details["unexpected_events"]   # <- the deviation signal
res.details["expected_events"]
res.details["unparseable_source_ip_events"]

# A list of identities in one pass; stream to a file as it goes
res = d.aws_ir.hunt.hunt_cloudtrail_multi_user(
    ["alice", "bob"],
    mode="per_user",            # or "batch"
    output_path="./hits.jsonl",
)
res.details["per_user"]
```

## Security review (posture)

A read-only posture review — prioritized findings across IAM, EC2, S3, RDS,
Lambda, and org-wide controls, plus resources created since the incident began.
Emit as CSV + a self-contained HTML page.

```python
from dredge.aws_ir.review import AwsIRReview
from datetime import datetime, timezone

# Full review: all services tier-1 (+ org controls). tiers=(1, 2) for depth.
res = d.aws_ir.review.review(
    services="all", tiers=(1,),
    incident_start=datetime(2026, 4, 1, tzinfo=timezone.utc),
)
res.details["summary"]        # {"CRITICAL": 3, "HIGH": 5, ...}
res.details["findings"]       # prioritized; each carries service + tier

# Targeted, deeper review of one service:
res = d.aws_ir.review.review(services=["ec2"], ips=["203.0.113.50"])

# Fan the regional checks across regions (global IAM/S3 checks run once):
res = d.aws_ir.review.review(services="all", tiers=(1,), regions="all")
res.details["meta"]["regions"]        # regions queried; findings carry .region

AwsIRReview.to_csv(res, "review.csv")
AwsIRReview.to_html(res, "review.html")
```

`services` is `"all"` or a list; `tiers` is `(1,)` headline or `(1, 2)` deep;
`include`/`exclude` force checks by id. See the
[CLI reference](../cli/aws.md#review-posture) for the full service/check matrix.

## Other hunts

```python
res = d.aws_ir.hunt.list_guardduty_findings("detector-id", severity_min=7.0)
print(res.details["findings"])

res = d.aws_ir.hunt.hunt_security_hub_findings(severity_labels=["CRITICAL", "HIGH"])
res = d.aws_ir.hunt.get_iam_credential_report()
```

## Containment

```python
d.aws_ir.response.disable_user("compromised-user")
d.aws_ir.response.isolate_ec2_instances(["i-0123456789abcdef0"])
d.aws_ir.response.quarantine_s3_bucket("sensitive-bucket")
d.aws_ir.response.disable_lambda_function("my-function")
```

Dry-run everything destructive first with `DredgeConfig(dry_run=True)` — see the
[library overview](README.md#dry-run).

## Forensics

```python
d.aws_ir.forensics.get_ebs_snapshot("vol-0123456789abcdef0", description="IR case 42")
d.aws_ir.forensics.get_cloudtrail_status()
```

For the full method list, see the [command & feature reference](../reference.md).
