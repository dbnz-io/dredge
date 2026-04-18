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

Dredge is a cloud incident response (IR) and threat hunting library + CLI for AWS, GitHub, and GCP.

### Namespace pattern

The top-level `Dredge` class (`dredge/__init__.py`) exposes provider namespaces as attributes:

```
Dredge
├── .aws_ir   → AwsIRNamespace
│   ├── .response  (AwsIRResponse)   — disable/delete IAM users & keys, isolate EC2, block S3
│   ├── .forensics (AwsIRForensics)  — EC2 snapshot capture
│   ├── .hunt      (AwsIRHunt)       — CloudTrail LookupEvents with filter logic
│   └── .services  (AwsServiceRegistry) — lazy boto3 client cache
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

### Key implementation details

**CloudTrail hunt (`dredge/aws_ir/hunt.py`):** CloudTrail `LookupEvents` accepts only one `LookupAttribute` per call. The hunt selects the most specific filter available (`access_key_id` > `user_name` > `event_name`), then applies `source_ip` and other filters client-side. Pagination is handled automatically with configurable page size (≤50) and exponential backoff on throttling.

**GitHub hunt (`dredge/github_ir/hunt.py`):** Builds a query phrase from actor/action/repo filters plus a `created:` time range. Handles HTTP 429/403 with configurable backoff. Page size up to 100.

**GCP hunt (`dredge/gcp_ir/hunt.py`):** Constructs a Cloud Logging filter string from `protoPayload` fields. Page size up to 1000. GCP module is partially implemented — treat as in-progress.

**Dry-run:** `DredgeConfig(dry_run=True)` skips actual AWS API mutating calls and returns `success=True` with `details["dry_run"] = True`. Implemented only in `aws_ir/response.py`.

### CLI

`dredge/cli.py` is a standalone argparse CLI with subcommands for all AWS IR actions and GitHub hunt. Global flags set AWS auth (region, profile, explicit keys, role assumption) and dry-run. Output is JSON by default; pass `--output csv` for CSV.

### Testing approach

Tests use `pytest` + `pytest-mock`. AWS API calls are mocked via `unittest.mock`; no real cloud credentials are needed. Test files map 1:1 to source modules (e.g., `tests/test_aws_hunt.py` covers `dredge/aws_ir/hunt.py`). The 80% coverage floor is enforced in CI.
