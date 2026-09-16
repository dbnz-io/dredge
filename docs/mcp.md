# Dredge MCP server

`mcp_server/server.py` exposes Dredge's **read-only investigation surface** to an
MCP client (e.g. Claude) over stdio. It is built for *chatting about how to use
Dredge* and driving its non-destructive work: **log download, hunting, forensic
evidence capture, and cross-source investigation/correlation** across AWS,
Kubernetes, GitHub and GCP.

> **No containment.** Not one tool reaches Dredge's `.response` surface
> (disable/delete IAM, isolate EC2, delete pods, drain nodes, quarantine, …).
> Those wrappers do not exist in the server process, so an MCP client cannot
> discover or call them.

## Install & register

```bash
pip install -e .                       # the dredge package itself
pip install -r mcp_server/requirements.txt   # mcp (1.x FastMCP)

# AWS-only, read-only investigation (default 'analyst' profile):
claude mcp add dredge \
  --env AWS_PROFILE=ir --env AWS_REGION=us-east-1 \
  -- python /abs/path/to/mcp_server/server.py
```

Then ask the client to run `dredge_capabilities` (what's enabled) and
`dredge_guide` (how-to docs), then any read tool.

## Security model

The MCP tool set is a **capability reduction**, not the security boundary. The
real boundary is the **cloud credentials the server runs under** — run it with
read-only credentials:

| Provider | Recommended credential |
|---|---|
| AWS | `SecurityAudit` + `ReadOnlyAccess` (or `ViewOnlyAccess`) |
| Kubernetes | a read-only RBAC role / `view` ClusterRole |
| GitHub | a read-scoped token (`read:org`, `repo` read, `read:audit_log`) |
| GCP | `roles/logging.viewer` |

Two independent layers must agree: an admin key under the `analyst` profile
still cannot mutate (mutating tools are never registered), and a read-only key
under the `forensic` profile still cannot snapshot (the API returns
`AccessDenied`).

Under `analyst`, the underlying Dredge instance is built with `dry_run=True` as
a belt-and-suspenders neutralizer.

## Capability profiles — `DREDGE_MCP_PROFILE`

| Profile | Tools |
|---|---|
| `analyst` *(default)* | 100% read-only: how-to/guide, log download (to the local workdir only), every hunt, the posture review, and all read/capture forensics. Never mutates cloud state. |
| `forensic` | `analyst` **+** additive EBS volume snapshotting (`create_snapshot`). Non-destructive but writes to the cloud and costs money, so it is opt-in. |

VPC flow-log enablement (`enable_vpc_flow_logs`) and pod `exec`
(`exec_pod_command`) are **never wired** under any profile.

## Provider gating

AWS is always on. The other providers register only when configured:

| Provider | Enable with |
|---|---|
| GitHub | `DREDGE_GITHUB_ORG=<org>` **or** `DREDGE_GITHUB_ENTERPRISE=<slug>` (+ `GITHUB_TOKEN`) |
| GCP | `DREDGE_GCP_PROJECT=<project>` (+ `GOOGLE_APPLICATION_CREDENTIALS` or `DREDGE_GCP_CREDENTIALS`) |
| Kubernetes | `DREDGE_ENABLE_K8S=1` (+ optional `DREDGE_K8S_CONTEXT` / `DREDGE_K8S_KUBECONFIG` / `DREDGE_K8S_IN_CLUSTER`) |

So an AWS-only deployment shows a clean AWS-only tool set (32 tools); fully
configured it is 61.

## Local-file sandbox — `DREDGE_MCP_WORKDIR`

Every tool that reads or writes local files (`aws_forensics_download_s3_logs`,
`aws_review --export`, `aws_hunt_local_cloudtrail`,
`aws_incident_local_cloudtrail`) is confined to a single working directory
(default `./dredge-mcp-workdir`). Paths that escape it — absolute paths or `..`
traversal — are rejected. Point the sandbox at real evidence with
`DREDGE_MCP_WORKDIR=/path/to/evidence`.

## Tool groups

- **meta** — `dredge_capabilities`, `dredge_guide`
- **aws hunt** — CloudTrail (single / multi-region / multi-user /
  user-activity-by-ip), GuardDuty, Security Hub, Access Analyzer, Config
  history, CloudWatch Logs Insights, IAM credential report, IAM admins, unusual
  logins, exposed S3, public snapshots, open security groups, SGs-by-IP, Lambda
  env secrets, offline local-CloudTrail query + incident triage
- **aws review** — read-only posture review, optional CSV/HTML export
- **aws forensics (read)** — CloudTrail status, IAM user detail, S3 bucket
  policy, EC2 user-data, Lambda env, recently-active roles, SSM session history,
  RDS parameter group, GuardDuty finding detail, **S3 log download**
- **aws forensics (capture, `forensic` profile)** — EBS volume / instance
  snapshots
- **k8s** — Events search, RBAC bindings by subject, pods by ServiceAccount,
  privileged pods; pod manifest/logs/events, node describe, workload manifest,
  pods-on-node
- **github** — audit log, secret/code scanning alerts, org members, outside
  collaborators, apps, workflow runs; org/repo metadata, collaborators, branch
  protection, org/repo webhooks, commit history, file-at-commit
- **gcp** — Cloud Logging search + today

## Testing

`tests/mcp_server/` mirrors the source: `test_server.py` (argument forwarding,
path confinement, serialization) and `test_server_hardening.py` (the
no-destructive guarantee, annotations, profiles, provider gating, sandbox, input
validation). API calls are mocked — no cloud credentials needed.
