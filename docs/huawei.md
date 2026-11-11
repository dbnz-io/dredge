# Huawei Cloud authentication and secret scanning

For read-only posture checks, profile/region sweeps, and CSV/HTML assessment
reports, see the [Huawei security assessment](huawei-review.md).

Huawei support is an optional dependency:

```bash
pip install 'dredge-ir[huawei]'
# From this checkout:
pip install -e '.[huawei]'
```

The scanner supports a single region/project or a sweep across configured
profiles and accessible regional IAM projects, including Identity Center SSO.
Huawei ECS means **Elastic Cloud Server (VMs)**.

## Authentication

`HuaweiAuthConfig` supports explicit AK/SK, an optional temporary security token,
an SDK credential profile, or a callback returning SDK `BasicCredentials`.
These explicit sources are mutually exclusive. With none selected, Dredge uses
the official SDK's basic credential provider chain, including environment,
profile, federation, and workload credentials supported by the installed SDK.
See the [Huawei Python SDK authentication documentation](https://github.com/huaweicloud/huaweicloud-sdk-python-v3#user-authentication).

For environment authentication, supply `HUAWEICLOUD_SDK_AK`,
`HUAWEICLOUD_SDK_SK`, and, for temporary credentials,
`HUAWEICLOUD_SDK_SECURITY_TOKEN` through your usual credential mechanism.
Region and project can be supplied separately:

```bash
export HUAWEICLOUD_SDK_REGION=cn-north-4
export HUAWEICLOUD_SDK_PROJECT_ID=YOUR_REGIONAL_PROJECT_ID
dredge huawei hunt exposed-secrets
```

Use `--simple` for a compact result with success/completeness, redacted
findings, and their locations. `--check-permissions` runs read-only list API
probes and skips the secret scan. It checks access to the default configuration
services (FunctionGraph, ECS, CAE, CodeArts Pipeline, ModelArts, ServiceStage,
and DataArts Studio) and reports denied service actions. The probes do
not fetch resource configurations, so they cannot verify detail-read actions;
when a normal scan encounters a 403 on one of those calls, the error output
also names the denied action.

```bash
dredge huawei hunt exposed-secrets --simple --check-permissions
```

For the single-project SDK path, the project ID must be present in the config,
`HUAWEICLOUD_SDK_PROJECT_ID`, or resolved credentials. SSO and multi-profile sweeps
discover projects through IAM. Auth flags work before or immediately after
`huawei`; explicit flags override the applicable defaults:

```bash
dredge --huawei-region cn-north-4 --huawei-project-id PROJECT_ID \
  huawei hunt exposed-secrets
```

The SDK credential file defaults to `~/.huaweicloud/credentials`; override it
with `HUAWEICLOUD_SDK_CREDENTIALS_FILE`. `--huawei-profile basic` selects `[basic]`;
Dredge's `--huawei-profile audit` selects `[basic.audit]` in that SDK file:

```ini
[basic.audit]
ak = YOUR_ACCESS_KEY
sk = YOUR_SECRET_KEY
security_token = YOUR_TEMPORARY_SECURITY_TOKEN
project_id = YOUR_REGIONAL_PROJECT_ID
```

Omit `security_token` for permanent credentials. Profiles containing static keys
are resolved once per registry; a callback is invoked before **every request**.
SDK-managed federated/workload credentials retain SDK refresh behavior. OBS uses
the same refreshed credentials through its separate official SDK. TLS verification
is enabled, and automatic service retries are disabled for predictable budgets.
`--huawei-timeout` defaults to 20 seconds for connect/read operations.

Neither Huawei CLI commands nor a Huawei-only `Dredge(huawei_config=...)`
initialization require AWS credentials. Accessing `d.aws_ir` later initializes AWS.

## SSO and multiple profiles

To scan all configured profiles and their accessible regional projects:

```bash
dredge huawei --huawei-profile all --huawei-region all \
  hunt exposed-secrets --sso-login --max-workers 4
```

The default `sdk` profile source reads `[basic]`, `[basic.NAME]`, and Dredge's
`[sso.NAME]` sections from `~/.huaweicloud/credentials` (or the file selected by
`HUAWEICLOUD_SDK_CREDENTIALS_FILE`). Profile names must be unique across both
types; `all` is reserved. SSO profiles contain metadata, with no permanent keys:

```ini
[sso-session corporate]
sso_start_url = https://idcenter.huaweicloud.com/YOUR_PORTAL/portal
sso_region = ap-southeast-1

[sso.production]
sso_session = corporate
account_id = YOUR_PRODUCTION_ACCOUNT_ID
permission_set_name = SecurityAudit
region = ap-southeast-1

[sso.development]
sso_session = corporate
account_id = YOUR_DEVELOPMENT_ACCOUNT_ID
permission_set_name = SecurityAudit
region = ap-southeast-1
```

Replace the URL, SSO region, account IDs, and permission-set name with your actual
Identity Center assignments. `sso_region` is the region of the Identity Center
session; `--huawei-region` selects resource regions to inspect. The `[sso.*]` and
`[sso-session ...]` sections are Dredge extensions, not SDK or KooCLI SSO formats.
You can put `sso_start_url` and `sso_region` directly in a profile instead.

Profiles referencing the same session share one authorization. Use distinct
session names for different user identities, even when they use the same portal.
Without `sso_session`, each profile has its own session. Each profile requires
one account selector (`account_id` or `account_name`) and one assignment selector
(`permission_set_name` or `agency_urn`). To discover every assigned account and
permission set for one session, explicitly set `account_id = all` and
`permission_set_name = all`. Omitting a selector does not expand the scope.

`--sso-login` permits the official OIDC device authorization flow when a session
is missing or cannot be refreshed. Dredge prints a verification URL and code to
stderr; open the URL and complete the identity provider's login/MFA. Authorization
prompts run sequentially before scanning. Subsequent runs can omit `--sso-login`
and use cached sessions. Expired tokens and temporary agency credentials refresh
automatically when possible; a worker never opens a new interactive login.
Missing/revoked sessions are reported per profile with a login hint.

Tokens and client registrations are stored in Dredge's own
`~/.huaweicloud/dredge-sso-cache` directory (override with
`DREDGE_HUAWEI_SSO_CACHE_DIR`). Cache directories use mode 0700 and files mode
0600, with atomic writes and symlink checks. Temporary agency AK/SK/security
tokens stay in memory and are refreshed before service requests. Authentication
material is excluded from scan reports and exception messages.

To use existing **KooCLI SSO profile metadata**:

```bash
dredge huawei --huawei-profile-source koocli \
  --huawei-profile all --huawei-region all \
  hunt exposed-secrets --sso-login
```

This source uses `hcloud configure list --cli-output=json`, selects SSO profiles,
and imports their portal, region, account, and agency metadata. KooCLI must be
installed and profiles already configured. Dredge does not decrypt or reuse
KooCLI's credential cache or change its active profile; the first Dredge run
needs its own authorization. Imported profiles keep separate sessions. If your
KooCLI version masks required metadata, define native SSO profiles with the full
values instead. KooCLI AK/SK and AssumeRole profiles are not imported.

`--huawei-region all` uses IAM's region catalog and accessible project list,
including regional subprojects named `REGION_suffix`. It does not create or
enable projects. An explicit `--huawei-project-id PROJECT_ID` narrows the scan;
`--huawei-project-id all` includes accessible projects in the selected region.
For an all-region sweep, a profile's default project and the project's environment
variable are ignored, preventing one account's project ID from being reused in
another account. With no region override, a profile's `region` (or the region
environment variable) is used; a configured project alone can determine its region.

Up to `--max-workers` account/agency scans run concurrently (default 4, maximum
32); projects within each run are sequential. Findings are deduplicated by hash
and retain profile, account, agency, region, and project attribution. Each
profile's scope outcomes and failures are in `details.profiles`. Discovery
failures, unmapped projects, inaccessible services, and truncated scans remain
visible in `errors`, `details.uninspected`, and `details.complete`.

Content targets remain opt-in. Budgets apply **per profile/account/agency/region/
project**, so total work grows with the selected scope. OBS sweeps require one
explicit bucket region and scan each prefix once per account/agency, across its
projects. Run OBS separately from an all-region configuration scan. CCE uses one
explicit Kubernetes context in a separate single-cluster invocation; a Huawei
profile sweep does not discover clusters or obtain their Kubernetes credentials.

The implementation follows Huawei's
[device authorization APIs](https://support.huaweicloud.com/intl/en-us/api-identitycenter/StartDeviceAuthorization.html),
[agency credential API](https://support.huaweicloud.com/intl/en-us/api-identitycenter/GetAgencyCredentials.html),
[KooCLI SSO metadata](https://support.huaweicloud.com/intl/en-us/usermanual-hcli/hcli_03_009.html),
and [accessible project discovery](https://support.huaweicloud.com/intl/en-us/api-iam/iam_06_0003.html).
OIDC uses the configured SSO region; PortalAPI uses the public global endpoint
shipped by Huawei's SDK. Separate sovereign/partner endpoint deployments are not
configured by this integration. Validation uses mocked APIs and real SDK request
models; it has not been tested against a live Huawei Identity Center tenant.

## Coverage

| Source | Default | Inspected data |
|---|---|---|
| `functiongraph` | Yes | Readable environment variables from function configuration |
| `ecs_user_data` | Yes | Base64-decoded, UTF-8 ECS user data |
| `cae` | Yes | Environment values in the latest effective component configuration |
| `codearts` | Yes | Readable non-private variables in CodeArts Pipeline parameter groups |
| `modelarts` | Yes | Training job and inference deployment environment variables/commands |
| `servicestage` | Yes | Application/environment variables and component environment/command configuration |
| `dataartsstudio` | Yes | Workspace environment variables and API-readable DataArts connection configuration |
| CCI | Explicit `--include cci` | Pod/deployment environment and commands; Secret objects are hash-only inventory |
| `cce` | Explicit `--include cce` | Pod/workload environment values and commands; ConfigMap text |
| OBS | Explicit `--scan-obs` | Small UTF-8 objects beneath a nonempty prefix |
| LTS | Explicit `--scan-lts` | Log messages in specified streams and a time window |
| CSMS | Explicit `--scan-csms` | Hash inventory of a named secret's latest version |
| Kubernetes Secrets | Explicit `--scan-k8s-secrets` with CCE | Hash inventory of decoded text values |

The default scans all seven supported configuration sources. Select one or more
with `--include`; specifying it replaces the default set. CodeArts variables
marked private are not emitted or inspected and are reported as uninspected.
CodeArts access is project-scoped and requires the CodeArts Pipeline SDK, included
in `dredge-ir[huawei]`.

ModelArts, ServiceStage, and DataArts Studio scanners use their official Huawei
SDKs, included in the same extra. DataArts connection records are scanned only
when the API returns their configuration fields. Customer-owned data store
contents (database rows, object contents, logs, backups, and similar payloads)
remain outside automatic discovery; use explicit OBS/LTS targets for those
content scans. Secret references are not dereferenced, and encrypted or masked
values can remain unavailable to the API caller.
CCI has no generated Python SDK in the Huawei SDK distribution, so Dredge uses
the documented read-only CCI v2 API with Huawei request signing. Secret contents
are hashed in memory and never written into findings or inventory. CCI scanning
is opt-in because the list API returns secret values. Permission-only mode does
not call the CCI Secret list API, since doing so would retrieve those values.

```bash
# Run every default configuration scanner
dredge huawei hunt exposed-secrets

# Run only FunctionGraph and CodeArts
dredge huawei hunt exposed-secrets --include functiongraph codearts

# Add targeted OBS content to the same configuration scan
dredge huawei hunt exposed-secrets --scan-obs obs://audit-bucket/application/config/
```

CAE defaults to enterprise project `0`; select another with the global flag
`--huawei-enterprise-project-id`. Secret references are not resolved automatically.
Encrypted/masked fields, missing ECS user data, and skipped object content are
reported under `details.uninspected`. Function packages, disk contents, container
images, historical CAE configurations, and remote command execution are outside
this scanner's coverage.

Detectors are shared with AWS and include contextual Huawei AK/SK pairs,
AWS pairs, GitHub/Slack/Stripe tokens, private keys, JWTs, and secret-name heuristics.
Findings are candidates for assessment; Dredge does not test their validity against
Huawei services. Deduplicated results include a hash and redacted preview.

## Targeted content scans

```bash
dredge huawei hunt exposed-secrets --content-only \
  --scan-obs obs://audit-bucket/application/config/ \
  --obs-max-objects 100 --obs-max-object-bytes 1048576

dredge huawei hunt exposed-secrets --content-only \
  --scan-lts GROUP_ID/STREAM_ID \
  --start-time 2026-11-06T08:00:00Z --end-time 2026-11-06T09:00:00Z \
  --lts-max-events 1000 --content-max-api-calls 25
```

Target flags are repeatable. Bucket-root scans and wildcard targets are rejected;
there is no automatic bucket or stream discovery. LTS requires an explicit window
greater than zero and at most 24 hours. OBS objects are bounded with range reads
and conditional ETag checks. Archives are not restored or decompressed.

Content limits default to **100 API calls, 10 MiB of content, and 60 seconds per
source**, shared across that source's explicit targets. Override with
`--content-max-api-calls`, `--content-max-bytes`, `--content-max-seconds`.
OBS additionally defaults to 100 examined objects and 1 MiB per object; LTS to
1,000 examined log events. Failed requests consume the call budget. These are
operational bounds, not a billing ceiling: LTS returns whole pages, a page can
exceed the remaining processing-byte budget, and an in-flight request can outlast
the time budget. Credential refresh may make additional IAM/metadata requests.

Configuration scanners default to 500 resources each (`--max-resources`), with
2,000 service requests, 64 MiB of inspected text, and 120 seconds per scanner.
`details.scanners` records counts, truncation, and stop reasons. API failures set
`success=false`; caps/skips are reported separately. Check `details.complete` as
well as errors; zero findings in a partial scan is not a clean assessment.

`--unredacted NEW_FILE` writes raw **exposure findings** to a newly created file
with mode 0600. It never prints them to stdout or overwrites an existing file.
CSMS and Kubernetes Secret values remain hash-only inventory, even in this mode.

## CCE and Kubernetes authentication

Use an existing authorized kubeconfig/context, an explicit Kubernetes token, or
in-cluster service account credentials. Huawei AK/SK does not itself grant Kubernetes
API access, and Dredge does not download cluster credentials.

```bash
dredge --huawei-region cn-north-4 --k8s-kubeconfig ./cce-audit.yaml \
  --k8s-context audit --k8s-namespace application \
  huawei hunt exposed-secrets --include cce
```

Without `--k8s-namespace`, the selected cluster is inspected across namespaces.
The scanner lists pods, ConfigMaps, Deployments, StatefulSets, DaemonSets,
ReplicaSets, Jobs, and CronJobs, including init/ephemeral container configuration.
RBAC must allow `list` on those resources in the selected namespaces. With
`--scan-k8s-secrets`, it additionally needs `list` on `secrets`. No `exec`, write,
or cluster-admin permission is required. The Kubernetes API endpoint must be reachable.

## Python API

For a multi-profile or SSO scan:

```python
from dredge.huawei_ir import hunt_exposed_secrets_multi_profile

result = hunt_exposed_secrets_multi_profile(
    profiles="all", regions="all", sso_login=True, max_workers=4,
    include=["functiongraph", "ecs_user_data", "cae"],
)
```

`profiles` and `regions` also accept lists of names; `profiles=None` uses the
SDK default credential chain. `profile_source="koocli"` selects imported SSO
metadata. Scanner options match the single-project method below. The sweep owns
its service registries; there is no separate namespace to close.

For a single project using SDK credentials:

```python
from dredge import Dredge
from dredge.huawei_ir import HuaweiAuthConfig

d = Dredge(huawei_config=HuaweiAuthConfig(
    region_name="cn-north-4", project_id="YOUR_PROJECT_ID",
))
try:
    result = d.huawei_ir.hunt.hunt_exposed_secrets(
        include=["functiongraph", "ecs_user_data", "cae"],
        scan_obs=["obs://audit-bucket/application/config/"],
        content_max_api_calls=25,
    )
finally:
    d.huawei_ir.close()
```

Pass `k8s_config=K8sAuthConfig(...)` to `Dredge` for CCE and include `"cce"` in
the scan. Library parameter names use underscores (`scan_lts`, `start_time`,
`end_time`, etc.); times must be timezone-aware `datetime` values.

For rotating credentials, set `credential_provider=your_callback`; it must
return `huaweicloudsdkcore.auth.credentials.BasicCredentials`, optionally with
`.with_security_token(...)`. Call `.close()` after OBS work to release its client.

## Assessment permissions

These templates use **Huawei IAM identity-policy version 5.0**, for the new IAM
console. They are broad in resource scope and cover this scanner's API calls;
they are not AWS policies or a complete Huawei posture-audit policy.

- [Configuration inspection](../policies/huawei-secret-scan.json): FunctionGraph,
  ECS, and CAE reads.
- [Optional content reads](../policies/huawei-content-scan.json): OBS listing and
  object reads, plus LTS log queries. CLI targeting still applies.
- [Optional secret inventory](../policies/huawei-secret-inventory.json): CSMS
  plaintext-value access and its KMS decrypt-data-key dependency.

Grant the selected policies in the assessment's authorized scope. Existing
resource policies, denies, enterprise-project restrictions, and key permissions
can still limit access. CCE Kubernetes RBAC is configured separately. The templates
have been checked against the published action references, not attached or tested
against a live Huawei account:
[FunctionGraph](https://support.huaweicloud.com/intl/en-us/usermanual-permissions/iam_11_0009.html),
[ECS](https://support.huaweicloud.com/intl/en-us/service-authorization-iam5/iam_11_0007.html),
[CAE](https://support.huaweicloud.com/intl/en-us/usermanual-permissions/iam_11_0119.html),
[OBS](https://support.huaweicloud.com/perms-cfg-obs/obs_40_0055.html),
[LTS](https://support.huaweicloud.com/intl/en-us/api-lts/Permission.html),
[CSMS and KMS dependency](https://support.huaweicloud.com/intl/en-us/usermanual-permissions/iam_11_1013.html).
