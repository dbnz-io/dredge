# Huawei Cloud security assessment

Huawei review uses the same finding, service, severity, tier, and check-status
structure as the AWS assessment. It is read-only and returns JSON, with optional
CSV findings and a self-contained HTML report. Install the optional SDKs with
`pip install 'dredge-ir[huawei]'` (or `pip install -e '.[huawei]'` in a checkout).

## CLI

Review every configured SDK/SSO profile and its accessible regional IAM projects:

```bash
dredge huawei --huawei-profile all --huawei-region all \
  review full --deep --sso-login --html huawei-review.html --csv huawei-review.csv
```

`full` selects tier 1; `--deep` adds tier 2. A service command runs both tiers:

```bash
dredge huawei --huawei-profile audit --huawei-region ap-southeast-1 \
  review rds --html rds-review.html

dredge huawei --huawei-profile audit review iam

dredge huawei --huawei-profile audit review vpc \
  --regions cn-north-4,ap-southeast-1 --ip 203.0.113.8

dredge huawei --huawei-profile all --huawei-region all \
  review recent --incident-start 2026-11-01T00:00:00Z
```

Service commands: `iam`, `obs`, `vpc`, `ecs`, `evs`, `rds`, `cce`,
`functiongraph`, `cts`, `lts`, `hss`, `secmaster`, `recent`.
Huawei ECS is Elastic Cloud Server (virtual machines).

Authentication flags go before `huawei` or immediately after it, before
`review`. `--regions` is repeatable and accepts comma-separated regions;
`--all-regions` is equivalent to `--regions all`. These command-level selectors
override `--huawei-region`. `--include` and `--exclude` select check IDs from
the table below; both are repeatable and accept comma-separated values.
`--ip` accepts one IP/CIDR per occurrence.

The [authentication guide](huawei.md#sso-and-multiple-profiles) describes SDK
profiles, Identity Center sessions, and `--huawei-profile-source koocli`.
`--sso-login` permits device authorization for expired/missing sessions. Shared
SSO sessions authorize once, before workers start. Existing sessions refresh
without additional prompts. The default concurrency is four account/agency
workers (`--max-workers`, range 1–32); projects run serially within each worker.

Global IAM/OBS checks run once per profile/account/agency. Global-only reviews
do not require region/project discovery. OBS requests use each bucket's region.
Regional CLI reviews discover projects through IAM; specify
`--huawei-project-id ID` to restrict one project, or `all` for all accessible
projects in the selected regions. A profile's project is its default;
all-region selection ignores that default. The environment credential chain
honors `HUAWEICLOUD_SDK_REGION` and `HUAWEICLOUD_SDK_PROJECT_ID`. An explicit
project selector still takes precedence over all-region selection.
Unknown/unmapped project scopes remain visible as uninspected; discovery
failures retain already-collected global findings.

## Checks

All scopes are regional except IAM, OBS, and `recent-iam-resources`.

| Check ID | Tier | Assessment signal |
|---|---:|---|
| `iam-login-protection` | 1 | Enabled console users without login protection, or using SMS/email instead of virtual MFA |
| `iam-admin-groups` | 1 | Account-wide administrator grants to groups, including broad custom IAM grants |
| `iam-old-access-keys` | 2 | Active permanent keys at least 90 days old; only key suffixes are reported |
| `iam-external-agencies` | 2 | Agencies trusting another account, for authorization review |
| `iam-password-policy` | 2 | Minimum password length below 12 |
| `obs-public-buckets` | 1 | OBS public-status API reports a public bucket |
| `obs-public-access-block` | 2 | Disabled bucket public-access blocking settings |
| `obs-default-encryption` | 2 | Missing default bucket encryption configuration |
| `obs-access-logging` | 2 | No access-log target bucket |
| `vpc-open-critical-ports` | 1 | Enabled ingress allow rules from all IPv4/IPv6 addresses to critical ports |
| `vpc-sg-references-ip` | 2 | Rule source overlaps a supplied `--ip`; skipped without an IP |
| `vpc-flow-logs` | 1 | VPCs exist but no active flow log was returned |
| `ecs-public-addresses` | 1 | Servers with floating/public addresses |
| `evs-unencrypted-volumes` | 2 | Unencrypted disks |
| `rds-public-instances` | 1 | Databases with public addresses |
| `rds-storage-encryption` | 2 | Database storage has no encryption key |
| `rds-ssl-disabled` | 2 | Database SSL is disabled |
| `rds-backup-retention` | 2 | Automated backup retention below 7 days, excluding replicas |
| `cce-public-api` | 1 | External Kubernetes API endpoints |
| `cce-legacy-auth` | 2 | Legacy x509 cluster authentication mode |
| `cce-master-encryption` | 2 | Control-plane volume encryption is disabled |
| `functiongraph-unauthenticated-triggers` | 1 | Active API gateway triggers configured with authentication `NONE` |
| `cts-system-tracker` | 1 | No enabled system tracker returned |
| `cts-log-archive` | 1 | System tracker has neither an OBS nor an enabled LTS archive destination |
| `cts-integrity-validation` | 2 | OBS trace-file integrity validation is disabled |
| `lts-log-retention` | 2 | Log-group retention below 30 days |
| `hss-host-protection` | 1 | Running ECS instances missing from HSS inventory, or unhealthy protection/agent status |
| `secmaster-workspaces` | 2 | No project workspace returned; centralized detection coverage needs review |
| `recent-iam-resources` | 1 | IAM users/agencies created since `--incident-start` |
| `recent-regional-resources` | 1 | ECS/RDS/CCE resources created since `--incident-start` |

Recent-resource checks skip without `--incident-start`. Threshold overrides:
`--key-age-days`, `--min-password-length`, `--min-backup-days`,
`--min-log-retention-days`. These are assessment baselines, not universal
compliance requirements. Critical ports are 21, 22, 23, 445, 1433, 2375, 3306,
3389, 5432, 5900, 6379, 9200, 11211, and 27017; TCP and UDP rules are reviewed.

## Coverage and bounds

Each check has default limits of 1,000 resource visits (including nested
resources), 2,000 API requests, and 120 seconds per account/project. Override
with `--max-resources`, `--max-api-calls`, and `--max-seconds`. Inventory reads
are cached within each scope's review. Time limits are checked between requests
and resources; an in-flight request uses `--huawei-timeout` (20 seconds by
default). These limits do not cap the entire multi-account run or SSO discovery.

JSON includes `details.findings`, `summary`, `checks`, `profiles`, `meta`,
`uninspected`, and `complete`. Findings carry profile/account/agency/region/project
context. Single-scope library results omit `profiles`.

- API failures set `success=false` and `complete=false`; other checks continue.
- Unknown required fields and exhausted limits set `complete=false`, even if
  every attempted request succeeded. Existing findings are retained.
- Check status is `ran`, `partial`, `failed`, or `skipped`. Skipped conditional
  checks explain their missing input. Aggregate checks include `by_scope`.
- The HTML report exposes coverage/errors and filters severity, service, and
  profile. CSV contains findings only; retain JSON/HTML to assess completeness.
- No OBS object bodies, log events, stored secret values, Kubernetes credentials,
  or user data are read. Use the separate [secret hunt](huawei.md) for those.

A public address or allow rule does not prove effective Internet reachability;
rule priorities and routes need investigation. CCE checks use cloud metadata and
do not review in-cluster RBAC, workloads, or Kubernetes Secret encryption. IAM
checks cover the legacy user/group/agency APIs, not effective permissions or all
IAM v5 assignments; federated MFA must be assessed at the IdP. Key age is not
last-use age. OBS encryption is a bucket default, not an object audit. LTS stream
overrides, detailed flow-log coverage, and centralized CTS/HSS/SecMaster controls
need separate review. A SecMaster workspace does not establish healthy detection
rules or ingestion. Creation-time findings are hunting leads, not evidence of
compromise. This initial set of checks does not cover every Huawei service or
provide full parity with every AWS check.

## Permissions

Use an assessment principal with read access to the selected services. Existing
secret-scanning IAM templates do not grant all review operations. The CLI also
needs IAM region/project discovery unless only global checks are selected.
Grant read-only access for these API operations in the appropriate account/global
or regional project scopes:

| Area | SDK operations used |
|---|---|
| Discovery | `KeystoneListRegions`, `KeystoneListAuthProjects`, `KeystoneShowProject`, `KeystoneListAuthDomains` |
| IAM | `KeystoneListUsers`, `ShowUser`, `ShowUserLoginProtect`, `KeystoneListGroups`, `KeystoneListDomainPermissionsForGroup`, `ListPermanentAccessKeys`, `ListAgencies`, `ShowDomainPasswordPolicy` |
| OBS | `listBuckets`, `getBucketPublicStatus`, `getBucketPublicAccessBlock`, `getBucketEncryption`, `getBucketLogging` |
| VPC | v3 `ListSecurityGroupRules`, `ListVpcs`; v2 `ListFlowLogs` |
| Compute | ECS `ListServersDetails`; EVS `ListVolumes`; CCE `ListClusters` |
| RDS | `ListInstances`, `ShowBackupPolicy` |
| Functions | FunctionGraph `ListFunctions`, `ListFunctionTriggers` |
| Security/logging | CTS `ListTrackers`; LTS `ListLogGroups`; HSS `ListHostStatus`; SecMaster `ListWorkspaces` |

SDK operation names are listed for auditability; they are not IAM policy action
strings. Check the service's authorization reference when building a policy.
Permission denials are recorded rather than interpreted as absent controls.

## Library

```python
from dredge import Dredge
from dredge.huawei_ir import HuaweiAuthConfig, HuaweiIRReview, review_multi_profile

d = Dredge(huawei_config=HuaweiAuthConfig(
    region_name="ap-southeast-1", project_id="PROJECT_ID", profile_name="audit",
))
try:
    result = d.huawei_ir.review.review(services=["rds", "cce"], tiers=(1, 2))
    HuaweiIRReview.to_html(result, "huawei-review.html")
finally:
    d.huawei_ir.close()

result = review_multi_profile(
    profiles="all", regions="all", sso_login=True,
    services="all", tiers=(1, 2), max_workers=4,
)
HuaweiIRReview.to_csv(result, "huawei-review.csv")
```

For an existing explicit/callback auth configuration, use
`review_multi_profile(auth=config, profiles=None, regions="all", ...)` or
`d.huawei_ir.review.review(regions="all", ...)`. The single-scope library path
uses its configured project directly. Share a registry sequentially; create
separate review instances for concurrent calls. Automated tests use official SDK
request/model contracts with HTTP mocked; no live tenant validation is implied.
