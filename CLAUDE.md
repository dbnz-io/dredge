# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install in editable mode
pip install -e .

# Run all tests
pytest -q

# Run tests with coverage (80% minimum enforced in CI)
pytest --cov=dredge --cov-report=term-missing --cov-fail-under=80 -q

# Run a single test file
pytest tests/test_aws_hunt.py -q

# Run a single test
pytest tests/test_aws_hunt.py::TestAwsHunt::test_lookup_by_access_key -q
```

## Architecture

Dredge is a cloud incident response (IR) and threat hunting library + CLI for AWS, Kubernetes, GitHub, and GCP.

### Namespace pattern

The top-level `Dredge` class (`dredge/__init__.py`) exposes provider namespaces as attributes:

```
Dredge
├── .aws_ir   → AwsIRNamespace
│   ├── .response  (AwsIRResponse)   — disable/delete IAM users & keys, isolate EC2, block S3
│   ├── .forensics (AwsIRForensics)  — EC2 snapshot capture
│   ├── .hunt      (AwsIRHunt)       — CloudTrail LookupEvents with filter logic
│   ├── .review    (AwsIRReview)     — posture review (per-service + org controls), CSV + HTML
│   └── .services  (AwsServiceRegistry) — lazy boto3 client cache
├── .k8s_ir   → K8sIRNamespace
│   ├── .response  (K8sIRResponse)   — revoke RBAC bindings, delete/cordon/drain pods & nodes, NetworkPolicy quarantine
│   ├── .forensics (K8sIRForensics)  — pod/node manifest & log capture, exec-based diagnostics
│   ├── .hunt      (K8sIRHunt)       — Kubernetes Events API search, RBAC/exposure hunting
│   └── .services  (K8sServiceRegistry) — lazy typed API client cache (CoreV1Api, AppsV1Api, etc.)
├── .github_ir → GitHubIRNamespace
│   ├── .hunt      (GitHubIRHunt)    — GitHub org/enterprise audit log search
│   └── .services  (GitHubServiceRegistry)
└── .gcp_ir   → GcpIRNamespace
    ├── .hunt      (GcpIRHunt)       — Cloud Logging search
    └── .services  (GcpLoggingService)
```

All action methods return `OperationResult` (defined per-namespace in `models.py`): a dataclass with `operation`, `target`, `success`, `details` (dict), and `errors` (list).

### Auth & config

- `DredgeConfig` (`dredge/config.py`): region, dry-run flag, default tags. Passed down to all namespaces.
- `AwsAuthConfig` + `AwsSessionFactory` (`dredge/auth.py`): build boto3 sessions with precedence — explicit keys > named profile > default chain. Supports role assumption and MFA.
- `GitHubIRConfig` (`dredge/github_ir/config.py`): token resolved from explicit value, provider callable, or `GITHUB_TOKEN` env var.
- `GcpIRConfig` (`dredge/gcp_ir/config.py`): project ID and credentials path.
- `K8sAuthConfig` + `K8sClientFactory` (`dredge/k8s_ir/config.py`, `dredge/k8s_ir/services.py`): precedence — explicit token/`token_provider` > `in_cluster` > kubeconfig/context ("auth like kubectl") > default (in-cluster, falling back to default kubeconfig). `token_provider` is re-invoked before every API call (no dredge-side caching), matching `GitHubIRConfig.token_provider`.

### Key implementation details

**CloudTrail hunt (`dredge/aws_ir/hunt.py`):** CloudTrail `LookupEvents` accepts only one `LookupAttribute` per call. The hunt selects the most specific filter available (`access_key_id` > `user_name` > `event_name`), then applies `source_ip` and other filters client-side. Pagination is handled automatically with configurable page size (≤50) and exponential backoff on throttling. The per-client pagination loop lives in `_paginate_lookup_events(client, ...)`, shared by `lookup_events` (single region) and `lookup_events_multi_region`. `lookup_events_multi_region(regions="all"|[...], ...)` fans out one paginated lookup per region across a `ThreadPoolExecutor` (LookupEvents is a regional API), building a per-region CloudTrail client via `services.cloudtrail_for_region(region)` and merging results into one time-sorted list with a `details["by_region"]` breakdown; per-region failures are recorded there without aborting the others. `regions="all"` resolves enabled regions via `services.resolve_enabled_regions()` (EC2 `DescribeRegions`, falling back to botocore's static list). Wired up on the `aws hunt cloudtrail` CLI command as `--all-regions` / `--regions` (repeatable; `--regions all` also means every enabled region) / `--max-workers` — distinct from the global `--region`, which sets the base session region. `hunt_cloudtrail_multi_user` runs `lookup_events` once per username in a list (CloudTrail has no server-side "username IN (...)" filter) and either keeps results grouped by user (`mode="per_user"`, default) or merges everything into one time-sorted list (`mode="batch"`); pass `output_path` to stream each user's record to a JSON Lines file as it completes, so a failure partway through a long list doesn't lose prior progress. `hunt_user_activity_by_ip` hunts a single identity and classifies every event by whether its source IP falls inside an `allowed_ips` allowlist (IPs/CIDRs), returning `expected_events`/`unexpected_events`/`unparseable_source_ip_events` buckets — the `unexpected` bucket is the baseline-deviation hunting signal. Both are wired up as CLI subcommands (`aws hunt cloudtrail-multi-user`, `aws hunt user-activity-by-ip`; list arguments accept a repeatable flag and/or a `--*-file` pointing at a newline-delimited file).

**Security review (`AwsIRReview`, `dredge/aws_ir/review.py`):** A read-only posture review, exposed as `d.aws_ir.review` and as its own CLI **bucket** (`review`, alongside hunt/response/forensics — added to `_BUCKET_ORDER`/`_BUCKET_LABELS`). Each check is tagged with a `service` (`iam`/`ec2`/`s3`/`rds`/`lambda`/`ecs`/`org`/`recent`), a `tier` (1 = headline, 2 = deeper), and a `scope` (`global` run-once, or `regional`). `review(..., regions="all"|[...])` fans the **regional** checks (EC2/RDS/Lambda/ECS/org guardrails) across regions concurrently via a `ThreadPoolExecutor` using `AwsServiceRegistry.regional(region)` (which returns a registry whose clients are region-bound — `services.py` gained a `_client()` helper + `region` param for this); global checks (IAM/S3) run once; findings carry their `region` and per-check status includes a `by_region` breakdown. Notable checks include ECS Exec (`enableExecuteCommand`) and EC2 Instance Connect Endpoints. `review(services=None|"all"|[...], tiers=(1,2), incident_start=None, ips=None, include=None, exclude=None)` runs the selected checks: `aws review full` → all services tier-1 (`--deep` adds tier-2); `aws review <service>` → that service, both tiers. Checks cover IAM (admins, console-without-MFA, weak role trust, stale access keys), S3 (public buckets, default encryption), RDS (public, unencrypted), EC2 (world-open critical ports, public snapshots, IMDSv1, security groups referencing a supplied `--ip` — composing `hunt_security_groups_by_ip`), Lambda (public function URLs), **org/account guardrails** (GuardDuty enabled? CloudTrail logging? VPC flow logs? Security Hub? Access Analyzer? — a finding means the control is *missing*), and `recent` (resources created since `incident_start`). Composes `AwsIRHunt` where checks already exist. Each check is defensive: a per-check `ClientError`/`BotoCoreError` is recorded in `details["checks"][id]` and the others still run. `Finding`s roll into `details["findings"]` (sorted by severity, each carrying `service`+`tier`), `details["summary"]`, `details["meta"]`. `AwsIRReview.to_csv/to_html(result, path)` write a CSV and a **self-contained** HTML report (inline CSS/JS, severity- **and** service-filterable, no external resources, all content escaped). Regional checks use the session region; multi-region is a follow-up.

**S3 log download (`AwsIRForensics.download_s3_logs`, `dredge/aws_ir/forensics.py`):** Flat-prefix download by default (unchanged). Passing `start_time`/`end_time` or `days_ago` switches to a date-aware two-phase approach for org/Control Tower CloudTrail buckets laid out as `[<prefix>/][o-xxxxxxxxxx/]<account-id>/CloudTrail/<region>/<year>/<month>/<day>/*`: `_discover_date_prefixes` walks the folder hierarchy with `Delimiter="/"` (no object bodies), fanned out across `max_workers` threads per level, pruning branches as soon as a dated folder is reached so years of history are never listed regardless of account/region count; only day folders inside the window then get a real object listing + download. `prefix` should point at or above the account-id level. Wired up as `aws forensics download-s3-logs --start-time/--end-time/--days-ago/--max-workers` on the CLI.

**GitHub hunt (`dredge/github_ir/hunt.py`):** Builds a query phrase from actor/action/repo filters plus a `created:` time range. Handles HTTP 429/403 with configurable backoff. Page size up to 100.

**GCP hunt (`dredge/gcp_ir/hunt.py`):** Constructs a Cloud Logging filter string from `protoPayload` fields. Page size up to 1000. GCP module is partially implemented — treat as in-progress.

**Kubernetes hunt (`dredge/k8s_ir/hunt.py`):** v1 uses the built-in Kubernetes `Events` API only — flavor-agnostic (works identically on EKS/GKE/AKS/self-managed), no audit-log plumbing required. Pagination uses the API's `limit`/`_continue` tokens. Cloud-specific audit log retrieval (EKS → CloudWatch, GKE → Cloud Logging) is intentionally out of scope for now; compose with `aws_ir.hunt`/`gcp_ir.hunt` for that.

**Kubernetes response (`dredge/k8s_ir/response.py`):** Response/forensics methods hit the standard Kubernetes API and behave identically regardless of cluster flavor. Destructive node/pod actions (`cordon_node`, `delete_node`, `drain_node`) operate at the K8s API level only — they do not reach into `aws_ir`/`gcp_ir` to stop or snapshot the underlying VM; that composition is left to the caller. `quarantine_pod`/`quarantine_namespace` apply deny-all `NetworkPolicy` objects — enforcement depends on the cluster's CNI supporting `NetworkPolicy` (e.g. Calico, Cilium); some CNIs don't enforce it at all.

**Dry-run:** `DredgeConfig(dry_run=True)` skips actual mutating API calls and returns `success=True` with `details["dry_run"] = True`. Implemented in `aws_ir/response.py`, `k8s_ir/response.py`, and `github_ir/response.py`. For GitHub, `Dredge.__init__` propagates `DredgeConfig.dry_run` into the `GitHubIRConfig` (`github_config.dry_run = github_config.dry_run or self.config.dry_run`) since the GitHub namespace is built from `GitHubIRConfig`, not `DredgeConfig`; each mutating `GitHubIRResponse` method short-circuits via `self._dry_run(result)` before its HTTP call.

### CLI

`dredge/cli.py` is a standalone argparse CLI with subcommands for all AWS IR actions, Kubernetes IR actions, and GitHub hunt/response. Global flags set AWS auth (region, profile, explicit keys, role assumption), Kubernetes auth (kubeconfig, context, in-cluster, or explicit token), and dry-run. Output is JSON by default; pass `--output csv` for CSV.

**Nested command structure:** commands are invoked as `dredge <provider> <bucket> <command>` (e.g. `dredge aws hunt access-analyzer`), so `dredge aws -h` lists the buckets (review/hunt/response/forensics), `dredge aws hunt -h` lists that bucket's commands, and a bare `dredge aws` or `dredge aws hunt` prints the level's help instead of erroring. There is exactly one way to register (and invoke) a command — the flat `aws-hunt-x` form does not exist. `_NestedRegistrar` builds the `provider → bucket → command` argparse tree; each command is registered with a single explicit call in `build_parser()`, `subparsers.command("aws", "hunt", "access-analyzer", help=...)`, which names the nested path at the call site (no flat-name → nested derivation to keep in sync) and returns the leaf parser to add arguments to. Provider/bucket nodes are created lazily and default to printing their own help. The top-level subparsers use `dest="provider"` (not `"command"`, which would shadow `k8s forensics exec-pod-command`'s positional). `dredge --help` prints a categorized overview (grouped by provider × Review/Hunt/Response/Forensics, showing nested invocations) via `_print_grouped_help`, driven by `parser._dredge_commands` (the `(provider, bucket, leaf, help)` tuples `_NestedRegistrar` records); each command's own `--help` still gives full argparse detail.

### Testing approach

Tests use `pytest` + `pytest-mock`. AWS and Kubernetes API calls are mocked via `unittest.mock` (`MagicMock` services injected directly into the response/forensics/hunt classes); no real cloud credentials or cluster are needed. Test files map 1:1 to source modules (e.g., `tests/test_aws_hunt.py` covers `dredge/aws_ir/hunt.py`, `tests/test_k8s_hunt.py` covers `dredge/k8s_ir/hunt.py`). The 80% coverage floor is enforced in CI.

### CI / release (`.github/workflows/`)

**Packaging:** the distribution name is `dredge-ir` (the bare `dredge` is taken on PyPI by an unrelated 2019 package); the import package and CLI stay `dredge` (`pip install dredge-ir` → `import dredge` / `dredge …`). Deps live only in `pyproject.toml` (no `requirements.txt`); the `test` extra (`pip install -e ".[test]"`) is the single source for the pytest toolchain used by contributors and CI.

A single workflow, `.github/workflows/release.yml` (named "CI / Release"), runs the whole pipeline, split into domain jobs so a red check names the culprit: **`test`** (matrix Python 3.10–3.13, installs `.[test]`, pytest with the 80% coverage floor) · **`security`** (`bandit -r dredge`) · **`package`** (build sdist+wheel, `twine check`, clean-wheel smoke test, uploads the `dist` artifact) · **`release`**. `test`/`security`/`package` run on every PR and push; `release` `needs` all three, runs only on a push to `main`, and no-ops unless `project.version` in `pyproject.toml` has no matching `v<version>` tag yet. Bandit runs strict (any finding fails); the handful of false positives (K8s API constant strings flagged as B105, an intentional B112 skip) are annotated inline with `# nosec <id>` + a justification comment on the preceding line (trailing prose after the id makes bandit misparse it as test names). The `release` job downloads the `package` job's `dist` artifact (so it publishes exactly what was validated), then **publishes to PyPI via Trusted Publishing** (OIDC, no stored token; `pypa/gh-action-pypi-publish`, `skip-existing`, gated on a `pypi` GitHub Environment), generates a CycloneDX SBOM from a clean `pip install .` venv (runtime deps only) into the repo root so it never goes to PyPI, and cuts a GitHub Release `v<version>` with the dists + `dredge-ir-<version>-sbom.cdx.json` attached. PyPI publish runs before the Release step (which creates the tag the idempotency guard keys on) so a transient failure is retryable. The file is intentionally named `release.yml` (not `ci.yml`) because the PyPI Trusted Publisher is bound to the workflow filename. All actions are SHA-pinned; per-job permissions are least-privilege (`contents: read` top-level; the `release` job elevates to `contents: write` + `id-token: write`). To release: bump `version` in a PR; the release fires on merge.
