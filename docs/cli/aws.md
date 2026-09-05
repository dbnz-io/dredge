# CLI — AWS

`dredge aws <bucket> <command>`. Auth/region are global flags before `aws`
(see [Authentication](../authentication.md)). Examples below use
`--aws-profile ir --region us-east-1`; substitute your own.

- [Review (posture)](#review-posture)
- [Hunt & investigate](#hunt--investigate)
- [Forensics](#forensics)
- [Response / containment](#response--containment)

---

## Review (posture)

A read-only **security posture review** — the high-signal findings that tell you
where to dig deeper — emitted as CSV and a self-contained, filterable HTML page.
Run the whole account, or target one service for a deeper look.

```bash
# Full review across every service + org-wide controls (headline findings)
dredge --aws-profile ir --region us-east-1 \
  aws review full \
  --incident-start 2026-04-01T00:00:00Z \
  --csv ./review.csv --html ./review.html

# ...and --deep to include the second-layer (tier-2) checks too
dredge --aws-profile ir --region us-east-1 aws review full --deep --html ./review.html
```

Targeting a **single service** always runs its deeper tier-2 checks:

```bash
dredge --aws-profile ir --region us-east-1 aws review iam --html ./iam.html
dredge --aws-profile ir --region us-east-1 aws review s3

# org/account guardrails (GuardDuty, CloudTrail, flow logs, …)
dredge --aws-profile ir --region us-east-1 aws review org

# EC2 review + flag security groups referencing an IP
dredge --aws-profile ir --region us-east-1 \
  aws review ec2 --ip 203.0.113.50,198.51.100.0/24

# Full review, fanning the regional checks across every enabled region
dredge --aws-profile ir --region us-east-1 aws review full --all-regions --html ./review.html
```

Open the HTML in a browser: findings are colored by severity and **filterable by
severity and by service**. The same findings print to stdout as JSON.

### Services and checks

| Service (`aws review <svc>`) | Tier-1 (headline) | Tier-2 (deeper) |
|---|---|---|
| `iam` | admin principals · console-without-MFA · weak role trust (`Principal: *` / cross-account no-condition) | access keys not rotated in 90+ days |
| `ec2` | security groups world-open on critical ports (22/3389/3306/…) · public snapshots | IMDSv1 allowed · EC2 Instance Connect Endpoints · SGs referencing `--ip` |
| `s3` | publicly exposed buckets | no default encryption |
| `rds` | publicly accessible instances | storage not encrypted |
| `lambda` | public function URLs (`AuthType=NONE`) | — |
| `ecs` | services with ECS Exec (`execute-command`) enabled | — |
| `org` | GuardDuty enabled? · CloudTrail logging? · VPC flow logs? | Security Hub enabled? · Access Analyzer present? |
| `recent` | resources created since `--incident-start` (IAM users/roles, Lambda, S3) | — |

- **`aws review full`** = tier-1 across all services + org (add `--deep` for tier-2).
- **`aws review <service>`** = that service, tier-1 **and** tier-2.
- **Multi-region:** `--all-regions` (or `--regions us-east-1,eu-west-1`) fans the
  **regional** checks (EC2/RDS/Lambda/ECS/org guardrails) across regions
  concurrently; global checks (IAM/S3) run once. Findings carry their region.
- Org checks flag a **missing** control (e.g. GuardDuty off → a finding).
- `--incident-start <iso>` enables the `recent` check — the fastest way to spot
  attacker-created resources.
- `--include` / `--exclude` (comma-separated and/or repeatable) force checks in/out.
- Each check is independent: a permission error in one is reported in the result's
  `checks` map and the rest still run.

> Regional checks (EC2/RDS/Lambda) use the region from `--region`; IAM/S3/org are
> (mostly) global. Run per region for full regional coverage.

---

## Hunt & investigate

Read-only. New here? Start with [Getting started](../getting-started.md).

### CloudTrail — live (LookupEvents, ~90 days)

```bash
# By access key, over an explicit window
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --access-key-id AKIAIOSFODNN7EXAMPLE \
  --start-time 2026-04-01T00:00:00Z --end-time 2026-04-12T00:00:00Z

# By user, today only; or relative windows
dredge --aws-profile ir --region us-east-1 aws hunt cloudtrail --user alice --today
dredge --aws-profile ir --region us-east-1 aws hunt cloudtrail --event-name ConsoleLogin --week-ago 2
```

Filters: `--user`, `--access-key-id`, `--event-name`, `--source-ip`. Time:
`--start-time`/`--end-time` (ISO 8601), or `--today` / `--week-ago N` /
`--month-ago N`. `--max-events` caps results (`0` = unlimited).

#### Across multiple regions (concurrent)

LookupEvents is a **regional** API — each region's endpoint only returns events
recorded in that region. Fan out to many regions at once:

```bash
# Every region enabled for the account, queried concurrently
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --access-key-id AKIAIOSFODNN7EXAMPLE --all-regions

# Specific regions — comma-separated and/or repeatable (--regions all also
# means every enabled region)
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --user suspicious-user \
  --regions us-east-1,eu-west-1,ap-southeast-2
```

`--regions` accepts `us-east-1,us-east-2`, or `--regions us-east-1 --regions
eu-west-1`, or any mix. Each regional endpoint is hit in parallel (tune with
`--max-workers`).
`--max-events` becomes the per-region cap. Results merge into one time-sorted
list; the response includes a `by_region` breakdown (counts + any per-region
error) so a region you lack access to is reported without failing the rest.

> The global `--region` sets the **base session region**; `--all-regions` /
> `--regions` control the **fan-out**. Enabled regions are discovered via EC2
> `DescribeRegions` (falling back to the static list if that's denied).

### CloudTrail — offline (query downloaded logs)

Query `*.json`/`*.json.gz` already on disk (e.g. from `download-s3-logs`). No AWS
calls; every raw field is available.

```bash
dredge aws hunt query-cloudtrail-logs \
  --path ./ct-logs \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --fields eventTime,eventName,sourceIPAddress,userIdentity.arn

dredge aws hunt query-cloudtrail-logs --path ./ct-logs \
  --source-ip 203.0.113.50 --account-id 111122223333
```

Filters: `--source-ip`, `--user`, `--access-key-id`, `--event-name`,
`--event-source`, `--region`, `--account-id`, `--start-time`/`--end-time`.
`--fields` projects dot-paths (e.g. `userIdentity.accountId`). `--ir` keeps only
the curated high-signal "dangerous" eventNames so you can plot them on a
timeline.

#### Incident report — ranked by severity

`--incident` turns the same offline scan into a triage **report**: it sweeps the
logs for the curated dangerous eventNames and emits findings **ranked by
severity** (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`), highest first. Output
defaults to CSV (add `--output json` for the raw result).

```bash
# Top dangerous events across a folder of logs, ranked.
dredge aws hunt query-cloudtrail-logs --path ./ct-logs --incident > report.csv
```

Add `--iocs` to correlate against known indicators. It runs the same
dangerous-event sweep **and** pulls any activity attributable to an IOC — even
non-dangerous calls, kept as lower-priority context — then floats the
**overlaps** (a dangerous action *by* a flagged IOC) to the top:

```bash
dredge aws hunt query-cloudtrail-logs --path ./ct-logs \
  --iocs "ips=1.2.3.4,10.0.0.0/24;users=alice,arn:aws:iam::111:role/foo" \
  > report.csv          # --iocs implies --incident
```

IOC format: `ips=<csv>;users=<csv>`. IPs match `sourceIPAddress` exactly or by
CIDR; users match `userName` / `accessKeyId` / `principalId` exactly or as a
substring of the ARN (so assumed-role sessions match). Severity =
per-category base score + an overlap boost when a dangerous event also hits an
IOC. Concretely, a `CreateAccessKey` from a flagged IP (`CRITICAL`) outranks a
`GetSecretValue` by an unremarkable role (`HIGH`) — both reported, one
prioritised. `--start-time`/`--end-time` bound the window; `--max-events` caps
the findings kept.

### CloudTrail — list-driven hunts

```bash
# Many identities in one pass. --output-path streams JSON Lines as it goes,
# so a long run survives a mid-list failure. mode: per_user (default) | batch.
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail-multi-user \
  --user alice,bob --users-file suspects.txt \
  --mode per_user --output-path ./hits.jsonl --week-ago 1

# One identity, each event tagged expected/unexpected against an IP allowlist.
# The "unexpected" bucket is the baseline-deviation signal.
dredge --aws-profile ir --region us-east-1 \
  aws hunt user-activity-by-ip \
  --user deploy-bot --allowed-ip 10.0.0.0/8,203.0.113.10 --week-ago 1
```

List args (`--user`, `--allowed-ip`, and `--regions`/`--ip` elsewhere) are
**comma-separated and/or repeatable** — `--allowed-ip a,b` == `--allowed-ip a
--allowed-ip b` — and most also accept a `--*-file` pointing at a
newline-delimited file.

### GuardDuty / Security Hub / Access Analyzer / Config / CloudWatch

```bash
dredge --aws-profile ir --region us-east-1 \
  aws hunt guardduty --detector-id abc123 --severity-min 7.0

dredge --aws-profile ir --region us-east-1 \
  aws hunt security-hub --severity-label CRITICAL --severity-label HIGH

dredge --aws-profile ir --region us-east-1 \
  aws hunt access-analyzer arn:aws:access-analyzer:us-east-1:111122223333:analyzer/ir

dredge --aws-profile ir --region us-east-1 \
  aws hunt config-history AWS::EC2::Instance i-0123456789abcdef0

dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudwatch-logs --log-group /aws/lambda/my-fn \
  --query 'fields @timestamp, @message | sort @timestamp desc'
```

Other hunts: `aws hunt security-groups-by-ip --ip 203.0.113.50`,
`aws hunt exposed-secrets`. Run `dredge aws hunt --help` for the full list.

---

## Forensics

Evidence capture and log collection.

### Collect CloudTrail logs from S3 (date-aware)

The fast path for an org / Control Tower bucket
(`…/<account-id>/CloudTrail/<region>/<year>/<month>/<day>/…`): pull a date window
across **every account/region** without listing years of history.

```bash
dredge --aws-profile ir --region us-east-1 \
  aws forensics download-s3-logs \
  --bucket my-org-cloudtrail --prefix AWSLogs/ \
  --destination ./ct-logs --days-ago 2
```

- `--days-ago N` or `--start-time`/`--end-time` (ISO 8601) triggers the
  date-aware walk. Without them, it does a plain flat-prefix download.
- `--prefix` at or above the account-id level.
- `--max-workers` tunes discovery concurrency; `--max-objects` caps downloads;
  `--suffix` / `--no-decompress` control filtering and gunzip.

Feed `--destination` straight into `aws hunt query-cloudtrail-logs`.

### Other forensics

```bash
# Enable VPC flow logs
dredge --aws-profile ir --region us-east-1 \
  aws response enable-vpc-flow-logs vpc-abc123 \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/FlowLogsRole

# Confirm CloudTrail is on and logging (do this early in an investigation)
dredge --aws-profile ir --region us-east-1 aws response cloudtrail-status
```

> Some trail-status / flow-log commands live under the `response` bucket in the
> CLI. Run `dredge aws --help` to see the exact placement.

---

## Response / containment

**Mutating.** Dry-run first: add the global `--dry-run` flag (before `aws`) to
simulate — no API call, result includes `"dry_run": true`.

### IAM

```bash
dredge --aws-profile ir --region us-east-1 \
  aws response disable-access-key --user compromised-user --access-key-id AKIA123456789

dredge --aws-profile ir --region us-east-1 \
  aws response disable-user --user compromised-user

dredge --aws-profile ir --region us-east-1 \
  aws response revoke-active-sessions --user compromised-user

dredge --aws-profile ir --region us-east-1 \
  aws response detach-iam-policy arn:aws:iam::123456789012:policy/AdminAccess --role-name OldRole
```

### EC2 / network

```bash
dredge --aws-profile ir --region us-east-1 \
  aws response isolate-ec2 i-0123456789abcdef0 i-0abcdef1234567890

dredge --aws-profile ir --region us-east-1 \
  aws response block-nacl-cidrs --vpc-id vpc-abc123 --cidr 198.51.100.0/24

dredge --aws-profile ir --region us-east-1 \
  aws response terminate-ec2 i-0123456789abcdef0   # snapshots EBS first by default
```

### RDS / ECS / Lambda / SSM

```bash
dredge --aws-profile ir --region us-east-1 aws response isolate-rds my-prod-db
dredge --aws-profile ir --region us-east-1 aws response stop-ecs-service my-cluster my-service
dredge --aws-profile ir --region us-east-1 aws response disable-lambda --function-name my-function
dredge --aws-profile ir --region us-east-1 aws response terminate-ssm-sessions i-0123456789abcdef0
```

### S3

```bash
dredge --aws-profile ir --region us-east-1 \
  aws response block-s3-account --account-id 111122223333

dredge --aws-profile ir --region us-east-1 \
  aws response quarantine-s3-bucket suspicious-bucket
```

Full containment surface (KMS, Secrets Manager, EventBridge, security-group
rules, tagging, …): `dredge aws response --help`, or the
[command reference](../reference.md).
