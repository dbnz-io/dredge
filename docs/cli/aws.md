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

# Deep review of every configured profile and its account's enabled regions
dredge aws --aws-profile all --aws-region all review full --deep \
  --sso-login --max-workers 4 --html ./review.html --csv ./review.csv
```

Open the HTML in a browser: findings are colored by severity and **filterable by
severity and by service** (and by profile for profile sweeps). The same findings
print to stdout as JSON.

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
- **Multiple profiles:** `--aws-profile all` reviews every locally configured
  profile. Combine it with `--aws-region all` (or `--region all`) to discover
  enabled regions separately for each account. Both flags also work independently,
  and with service-specific commands such as `review iam` or `review ecs`.
  Global checks run once per profile. Profiles in the same account are reviewed
  independently because their permissions may differ.
- **Authentication:** cached credentials are reused. Optional `--sso-login`
  renews failed SSO sessions once per shared session through AWS CLI; browser/MFA
  interaction may still be required. See [profile authentication details](#all-configured-profiles-and-enabled-regions).
- **Sweep concurrency:** with either provider-level `all` flag or `--sso-login`,
  `--max-workers` limits concurrent profiles (default 12, range 1–32); regions
  run sequentially within each profile. Without those flags it retains its
  existing meaning of concurrent regions.
- **Sweep reports:** findings include `profile`, `account_id`, `principal_arn`,
  and `region`. JSON includes per-profile authentication/check/region outcomes;
  CSV includes finding attribution; HTML shows profile coverage, errors, and
  a profile filter. Failures mark the review incomplete while other profiles
  continue. A region-discovery failure still allows global checks to run.
- Org checks flag a **missing** control (e.g. GuardDuty off → a finding).
- `--incident-start <iso>` enables the `recent` check — the fastest way to spot
  attacker-created resources.
- `--include` / `--exclude` (comma-separated and/or repeatable) force checks in/out.
- Each check is independent: a permission error in one is reported in the result's
  `checks` map and the rest still run.

Without a region selector, regional checks use the configured session region.
IAM/S3 checks are global; organization guardrail checks are regional. Global-only
profile sweeps skip region discovery, so they do not require `ec2:DescribeRegions`.

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

### Exposed secrets

The default scan covers ten configuration sources in the selected region:
Lambda environment variables, ECS task definitions, SSM `String` parameters,
EC2 user data, CodeBuild, Elastic Beanstalk, App Runner, Batch, Glue, and Amplify.
Use repeatable `--include` flags to restrict the configuration scan:

```bash
dredge --aws-profile ir --region us-east-1 aws hunt exposed-secrets \
  --include elasticbeanstalk --include apprunner --include batch \
  --include glue --include amplify
```

The new configuration sources inspect:

| Source | Fields inspected |
| --- | --- |
| `elasticbeanstalk` | Environment properties in `aws:elasticbeanstalk:application:environment` |
| `apprunner` | `RuntimeEnvironmentVariables` for image and code services |
| `batch` | All active job definition revisions: parameters and container environment variables, including multi-node, ECS, and EKS layouts |
| `glue` | Job `DefaultArguments` and `NonOverridableArguments` |
| `amplify` | App, automatic branch creation, and branch environment variables |

Secrets Manager / SSM references are not dereferenced. Findings are deduplicated
and redacted by default. `--unredacted PATH` writes raw values to a file with mode
0600; `--test` explicitly enables STS verification of detected AWS key pairs.
Service access failures are reported while other sources continue.

#### All configured profiles and enabled regions

```bash
dredge aws --aws-profile all --aws-region all hunt exposed-secrets

# Start AWS CLI SSO login when a cached SSO session is missing/expired.
dredge aws --aws-profile all --aws-region all hunt exposed-secrets \
  --sso-login --max-workers 4 > secret-findings.json
```

`--aws-profile` and `--aws-region` / `--region` can appear before `aws` or immediately
after it, before `hunt`. The command name is plural: `exposed-secrets`.
The `all` values are supported for this hunt and [AWS posture reviews](#review-posture).

- **Profiles:** every profile configured in the AWS shared config/credentials
  files, honoring `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`. This does
  not discover unconfigured SSO account/role combinations or organization accounts.
- **Authentication:** the profile's existing SDK credential chain, including
  static keys, `credential_process`, role profiles, and cached SSO sessions.
  STS `GetCallerIdentity` validates each profile and records its account and
  principal. An inaccessible profile is reported while the others continue.
- **SSO:** `--sso-login` invokes `aws sso login` only after a missing/expired SSO
  authentication error, at most once per shared `sso_session` (or legacy start
  URL/region). Source-profile chains are followed. AWS CLI v2 must be installed;
  browser/MFA approval can still be required. Without the flag, failures include
  a login hint. Dredge does not configure new profiles or bypass MFA.
- **Regions:** `ec2:DescribeRegions` discovers enabled regions separately for
  each authenticated account. A discovery failure is reported; the sweep does
  not silently substitute a static region list. Configure a region on each
  profile, especially for GovCloud/China. Without any region information, the
  bootstrap defaults to `us-east-1` (with partition-specific defaults for role ARNs).
- **Concurrency:** at most four profiles scan concurrently (`--max-workers 1..32`).
  Regions run sequentially within each profile; boto3 sessions are not shared
  between workers. Initial authentication/login prompts run serially.
- **Results:** findings are deduplicated across scans, with each occurrence's
  profile, account, principal ARN, and region in `details.credentials[].sources`.
  `details.profiles` retains individual authentication, region, source-error,
  count, and content-budget results. Profiles using different roles in the same
  account are scanned independently. Progress and SSO prompts go to stderr;
  the final report goes to stdout.

Using only one `all` flag also works: all profiles in a chosen region, or one
profile across all its enabled regions. Combining all/named profile selection
with explicit credential flags is rejected in the sweep API to prevent profiles
from accidentally sharing one credential set. For this CLI, `--aws-profile all`
cannot be combined with explicit credential flags.

S3/CloudWatch remain opt-in. In a sweep, content limits apply **per profile and
region**; totals increase with the number of scans. S3 prefixes run only once
per profile and appear under the `global` result, relying on the SDK to route to
the bucket's region. A targeted S3-only sweep skips region discovery entirely.
CloudWatch group names are queried in each selected profile/region. To control
cost, run content scans with a specific profile and region when possible.

The AWS SDK handles profile authentication and credential refresh; interactive
SSO renewal uses the [AWS CLI login flow](https://docs.aws.amazon.com/cli/latest/reference/sso/login.html).
Several profiles can reuse one [SSO session](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

S3 and CloudWatch content are **off by default**, including when all configuration
sources are scanned. Each has a separate, repeatable opt-in flag. `--content-only`
skips configuration scanning and requires at least one content target:

```bash
# Small UTF-8 objects under an explicit prefix (no bucket-wide scan).
dredge --aws-profile ir aws hunt exposed-secrets --content-only \
  --scan-s3 s3://incident-artifacts/app/config/ --s3-max-objects 50

# One log group, one hour, optionally narrowed to a stream prefix.
dredge --aws-profile ir --region us-east-1 aws hunt exposed-secrets --content-only \
  --scan-cloudwatch /aws/lambda/payments --cloudwatch-stream-prefix '2026/11/06/' \
  --start-time 2026-11-06T08:00:00Z --end-time 2026-11-06T09:00:00Z \
  --cloudwatch-max-events 500
```

S3 requires `s3://bucket/nonempty-prefix`; wildcards are rejected. Matching is a
literal key prefix, so use a trailing `/` for a directory-like target. It examines
at most 100 listed objects across all targets, including skipped objects. It skips
objects larger than 1 MiB, archive storage classes that require restoration,
compressed content, and binary/non-UTF-8 data. It does not decompress archives or
scan previous object versions. Byte-range GETs bound downloads; available ETags
prevent reading an object that changed after listing.

CloudWatch requires explicit group names and both timestamps, with a window of
at most 24 hours. It uses `FilterLogEvents`, with an optional server-side stream
prefix, and examines at most 1,000 messages across all groups. It does not discover
groups, start Logs Insights queries, or request unmasking. Masked values cannot
be detected. Empty result pages still count toward the API budget.

| Limit | Default | Scope |
| --- | --- | --- |
| `--s3-max-objects` | 100 | All S3 targets, including skipped/duplicate listed entries |
| `--s3-max-object-bytes` | 1,048,576 (1 MiB) | Each S3 object |
| `--cloudwatch-max-events` | 1,000 | All CloudWatch groups |
| `--content-max-bytes` | 10,485,760 (10 MiB) | Separately for S3 and CloudWatch |
| `--content-max-api-calls` | 100 | Separately for S3 and CloudWatch, including failed calls |
| `--content-max-seconds` | 60 | Separately for S3 and CloudWatch |

All limits must be positive. The S3 byte budget reserves bytes before each GET,
including failed requests. The CloudWatch byte budget limits processed message
bytes; one additional API page may already have been received. API counts exclude
SDK retries, and time limits are checked before requests, so an in-flight request
can finish after the deadline. These bounds control client work, not the exact
AWS bill or CloudWatch's internal scanned bytes. Use narrow targets and windows.

Inspect `details.content_scans` for counts, skipped objects, `truncated`, and
`stop_reasons`. Hitting a limit retains findings and does not itself set
`success=false`; API failures do. A clean partial result does not establish that
the remaining content is secret-free. Detection covers credential patterns,
JSON string fields, and key/value assignments; it does not decode arbitrary
encodings or parse every file format.

Additional read permissions for configuration scans are
`elasticbeanstalk:DescribeEnvironments`, `elasticbeanstalk:DescribeConfigurationSettings`,
`apprunner:ListServices`, `apprunner:DescribeService`, `batch:DescribeJobDefinitions`,
`glue:GetJobs`, `amplify:ListApps`, and `amplify:ListBranches`. Targeted content scans
use `s3:ListBucket`, `s3:GetObject` (and `kms:Decrypt` where required for encrypted
objects), or `logs:FilterLogEvents`. Scope these permissions to the selected resources.

### Certificate IOC hunt and CA inventory

With no IOCs, `certificates` inventories ACM in every enabled AWS Region and
prints the number of certificates issued by each CA. The JSON result also
includes certificate attachments discovered on ELBv2 listeners, API Gateway
v1/v2 custom domains, and CloudFront distributions:

```bash
dredge --aws-profile ir aws hunt certificates
dredge --aws-profile ir aws hunt certificates --output json
```

Supply exact SHA-256 certificate fingerprints (hashes of DER certificates,
not SPKI hashes) and/or issuer-name substrings to switch to IOC hunt mode.
The fingerprint check covers every retrievable ACM leaf and chain certificate:

```bash
dredge --aws-profile ir aws hunt certificates \
  --fingerprint 'AA:BB:...' --ca-name 'Example CA'

# Built-in fingerprints and issuer leads for the October 2026 eMudhra incident
dredge --aws-profile ir aws hunt certificates --preset emudhra-2026

# One sha256:<hash>, ca:<name>, bare hash, or bare CA name per line
dredge --aws-profile ir aws hunt certificates --iocs-file incident-iocs.txt \
  --regions us-east-1,eu-west-1 --output json
```

Issuer-name hits are investigative leads; exact fingerprint hits provide the
stronger certificate-material match. Regional API failures appear in the JSON
result and do not stop scans of other Regions.

For the strongest exposure audit, inspect legacy IAM server certificates and
AWS Private CA chains, then probe the TLS chains currently served by discovered
endpoints:

```bash
dredge --aws-profile incident-readonly aws hunt certificates \
  --preset emudhra-2026 --strong --output json

# Internal or otherwise undiscoverable endpoints can be supplied explicitly.
dredge --aws-profile incident-readonly aws hunt certificates \
  --preset emudhra-2026 --runtime \
  --runtime-endpoint internal-api.example.net:8443 --output json
```

`--strong` enables both `--deep` (IAM server certificates and Private CA) and
`--runtime` (served TLS). Runtime probes make outbound TLS connections and may
appear in network or service logs. The audit remains read-only and does not
export private keys, modify listeners, replace certificates, or revoke them.

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
