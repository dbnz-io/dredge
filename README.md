<div align="center">
 <p>
  <h1>
    Dredge - 0.2.0
  </h1>
 </p>
</div>

<div align="center">

![CI](https://github.com/dbnz-io/dredge-internal/actions/workflows/ci.yml/badge.svg)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)

</div>

<div align="center">
  <h3>
   ⚡ Log collection, analysis, and rapid response in the cloud... pa' la hinchada⚡
  </h3>
</div>

---

### TL;DR

- Python library + CLI for cloud incident response and threat hunting.
- **AWS**: containment, forensics, and hunting across IAM, EC2, RDS, ECS, S3, Lambda, KMS, GuardDuty, Security Hub, CloudTrail, and more.
- **Kubernetes**: containment, forensics, and hunting across RBAC, pods, nodes, NetworkPolicy, and Secrets — works against any cluster (EKS, GKE, AKS, or self-managed) via standard kubeconfig or service-account auth.
- **GitHub**: org/enterprise audit log hunting.
- **GCP**: Cloud Logging hunting (in progress).
- 891 tests, 99% coverage, 80% floor enforced in CI.

---

<div align="justify">
<p>
Dredge is designed for rapid cloud IR — especially when you don't have all the plumbing ready at 3AM. It exposes a clean, composable Python API you can import into your own tooling and a CLI for direct use from the terminal.
</p>
</div>

---

## Current Features

### Response (AWS) — Containment

| Action | Method |
|---|---|
| Disable / delete IAM access key | `response.disable_access_key` / `delete_access_key` |
| Disable / delete IAM user | `response.disable_user` / `delete_user` |
| Disable IAM role (detach policies, clear trust) | `response.disable_role` |
| Delete MFA devices for a user | `response.delete_mfa_devices` |
| Revoke active IAM sessions (deny policy) | `response.revoke_active_sessions` |
| Detach a single managed policy from user/role | `response.detach_iam_policy` |
| Block S3 public access (account-level) | `response.block_s3_public_access` |
| Block S3 public access (bucket-level) | `response.block_s3_bucket_public_access` |
| Block S3 object public access | `response.block_s3_object_public_access` |
| Quarantine S3 bucket (block public + deny-all external) | `response.quarantine_s3_bucket` |
| Network-isolate EC2 instances (forensic SG) | `response.isolate_ec2_instances` |
| Stop EC2 instances | `response.stop_ec2_instances` |
| Terminate EC2 instances (optional EBS snapshot) | `response.terminate_ec2_instances` |
| Block CIDRs via NACL deny rules | `response.block_nacl_cidrs` |
| Revoke specific security group rules | `response.deauthorize_security_group_rules` |
| Isolate RDS instance (empty SG, disable public access) | `response.isolate_rds_instance` |
| Scale ECS service to 0 | `response.stop_ecs_service` |
| Force-stop ECS task | `response.stop_ecs_task` |
| Schedule Secrets Manager secret for deletion | `response.disable_secrets_manager_secret` |
| Disable EventBridge rule | `response.disable_eventbridge_rule` |
| Terminate active SSM sessions on an instance | `response.terminate_ssm_sessions` |
| Throttle Lambda function to zero concurrency | `response.disable_lambda_function` |
| Disable KMS key | `response.disable_kms_key` |
| Schedule KMS key deletion | `response.schedule_kms_key_deletion` |
| Tag AWS resources by ARN | `response.tag_resources` |

### Forensics (AWS)

| Action | Method |
|---|---|
| Snapshot EBS volume | `forensics.get_ebs_snapshot` |
| Snapshot all volumes on an EC2 instance | `forensics.snapshot_instance_volumes` |
| Capture Lambda environment variables | `forensics.get_lambda_environment` |
| Enable VPC flow logs (CloudWatch or S3) | `forensics.enable_vpc_flow_logs` |
| Retrieve completed SSM session history | `forensics.capture_ssm_session_history` |
| Check CloudTrail trail status and event selectors | `forensics.get_cloudtrail_status` |

### Hunt / Detection (AWS)

| Action | Method |
|---|---|
| CloudTrail LookupEvents (user, key, event, IP) | `hunt.lookup_events` |
| GuardDuty findings (severity, type, time filters) | `hunt.list_guardduty_findings` |
| Security Hub findings (severity, workflow, product) | `hunt.hunt_security_hub_findings` |
| IAM Access Analyzer findings | `hunt.hunt_access_analyzer_findings` |
| AWS Config resource configuration history | `hunt.hunt_config_resource_history` |
| CloudWatch Logs Insights query | `hunt.hunt_cloudwatch_logs` |
| IAM credential report (all users, keys, MFA, last used) | `hunt.get_iam_credential_report` |

### Hunt (GitHub)

- Org or Enterprise audit log search by `actor`, `action`, `repo`, `source_ip`, time range.
- Handles pagination and rate limiting.

### Response (Kubernetes) — Containment

| Action | Method |
|---|---|
| Delete a RoleBinding / ClusterRoleBinding | `response.revoke_role_binding` / `revoke_cluster_role_binding` |
| Disable a ServiceAccount (delete tokens + bindings) | `response.disable_service_account` |
| Fully delete a ServiceAccount | `response.delete_service_account` |
| Force-delete a pod | `response.delete_pod` |
| Scale a Deployment (e.g. to 0) | `response.scale_deployment` |
| Cordon a node | `response.cordon_node` |
| Cordon + evict all pods on a node | `response.drain_node` |
| Remove a Node object from the cluster | `response.delete_node` |
| Isolate a pod with a deny-all NetworkPolicy | `response.quarantine_pod` |
| Isolate an entire namespace with a deny-all NetworkPolicy | `response.quarantine_namespace` |
| Delete a Secret | `response.delete_secret` |
| Apply labels to a pod/node/namespace/deployment | `response.label_resource` |

### Forensics (Kubernetes)

| Action | Method |
|---|---|
| Capture a pod's full manifest | `forensics.get_pod_manifest` |
| Capture container logs | `forensics.get_pod_logs` |
| Capture Events for a pod | `forensics.get_pod_events` |
| Capture a node's full manifest | `forensics.describe_node` |
| Capture a workload controller's manifest (Deployment/StatefulSet/DaemonSet) | `forensics.capture_workload_manifest` |
| List pods scheduled to a node | `forensics.list_pods_on_node` |
| Run a diagnostic command in a pod (best-effort) | `forensics.exec_pod_command` |

### Hunt (Kubernetes)

| Action | Method |
|---|---|
| Search Kubernetes Events (namespace, involved object, reason, time range) | `hunt.list_events` |
| Find RoleBindings/ClusterRoleBindings referencing a subject | `hunt.list_role_bindings_for_subject` |
| List pods running under a ServiceAccount | `hunt.list_pods_by_service_account` |
| Flag pods with elevated host access (privileged, hostNetwork/PID/IPC) | `hunt.list_privileged_pods` |

v1 hunting uses the built-in Kubernetes Events API only — flavor-agnostic, no audit-log plumbing required. Cloud-specific audit log retrieval (EKS → CloudWatch, GKE → Cloud Logging) is on the roadmap, composing with the existing `aws_ir`/`gcp_ir` hunt modules.

---

## Installation

```bash
git clone https://github.com/dbnz-io/dredge-cli.git
cd dredge-cli
pip install -e .
```

Run tests:
```bash
pytest -q
```

See available commands:
```bash
dredge --help
```

---

## Docker

```bash
docker build -t dredge:latest .
# or
podman build -t dredge:latest .
```

---

## AWS Integration

### Authentication

| Method | How |
|---|---|
| Default credential chain | env vars, `~/.aws/credentials`, EC2/ECS role |
| Named profile | `--aws-profile` |
| Explicit keys | `--aws-access-key-id` + `--aws-secret-access-key` |
| Role assumption | `--aws-role-arn` (+ optional `--aws-external-id`) |

**Region:** `--aws-region`, or `AWS_REGION` / `AWS_DEFAULT_REGION`, or your profile config.

### Global AWS CLI Flags

```
--aws-region         AWS region (e.g. us-east-1)
--aws-profile        Named AWS profile
--aws-access-key-id  Explicit access key ID
--aws-secret-access-key
--aws-session-token  STS session token
--aws-role-arn       Role to assume
--aws-external-id    External ID for role assumption
--dry-run            Simulate without making changes
```

### CLI Examples

#### IAM Containment

```bash
# Disable an access key
dredge --aws-profile dredge-role --region us-east-1 \
  aws-disable-access-key --user compromised-user --access-key-id AKIA123456789

# Disable a user (deactivate keys, remove groups, delete login profile, detach policies)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-disable-user --user compromised-user

# Revoke active sessions (deny-all inline policy with TokenIssueTime condition)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-revoke-active-sessions --user compromised-user

# Detach a single policy from a role
dredge --aws-profile dredge-role --region us-east-1 \
  aws-detach-iam-policy arn:aws:iam::123456789012:policy/AdminAccess --role-name OldRole
```

#### EC2 / Network Containment

```bash
# Network-isolate EC2 instances (forensic empty SG)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-isolate-ec2 i-0123456789abcdef0 i-0abcdef1234567890

# Block a CIDR at the NACL level
dredge --aws-profile dredge-role --region us-east-1 \
  aws-block-nacl-cidrs --vpc-id vpc-abc123 --cidr 198.51.100.0/24

# Terminate an instance (snapshots EBS volumes first by default)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-terminate-ec2 i-0123456789abcdef0
```

#### RDS / ECS / Lambda

```bash
# Isolate an RDS instance
dredge --aws-profile dredge-role --region us-east-1 \
  aws-isolate-rds my-prod-db

# Scale down a compromised ECS service
dredge --aws-profile dredge-role --region us-east-1 \
  aws-stop-ecs-service my-cluster my-service

# Throttle a Lambda to zero
dredge --aws-profile dredge-role --region us-east-1 \
  aws-disable-lambda my-function

# Terminate active SSM sessions on an instance
dredge --aws-profile dredge-role --region us-east-1 \
  aws-terminate-ssm-sessions i-0123456789abcdef0
```

#### S3

```bash
# Block public access at account level
dredge --aws-profile dredge-role --region us-east-1 \
  aws-block-s3-account --account-id 111122223333

# Quarantine a bucket (block public + deny all external principals)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-quarantine-s3-bucket suspicious-bucket
```

#### Threat Hunting

```bash
# Hunt CloudTrail events for a compromised access key
dredge --aws-profile dredge-role --region us-east-1 \
  aws-hunt-cloudtrail --access-key-id AKIAIOSFODNN7EXAMPLE \
  --start-time 2026-04-01T00:00:00Z --end-time 2026-04-12T00:00:00Z

# List high/critical GuardDuty findings
dredge --aws-profile dredge-role --region us-east-1 \
  aws-hunt-guardduty --detector-id abc123 --severity-min 7.0

# Query Security Hub for critical findings
dredge --aws-profile dredge-role --region us-east-1 \
  aws-hunt-security-hub --severity-label CRITICAL --severity-label HIGH

# Get IAM credential report (all users, key ages, MFA status)
dredge --aws-profile dredge-role --region us-east-1 \
  aws-iam-credential-report

# Check AWS Config history for an EC2 instance
dredge --aws-profile dredge-role --region us-east-1 \
  aws-hunt-config-history AWS::EC2::Instance i-0123456789abcdef0
```

#### Forensics

```bash
# Snapshot all volumes on an instance
dredge --aws-profile dredge-role --region us-east-1 \
  aws-snapshot-instance i-0123456789abcdef0

# Enable VPC flow logs
dredge --aws-profile dredge-role --region us-east-1 \
  aws-enable-vpc-flow-logs vpc-abc123 \
  --deliver-logs-permission-arn arn:aws:iam::123:role/FlowLogsRole

# Check CloudTrail is healthy and logging
dredge --aws-profile dredge-role --region us-east-1 \
  aws-cloudtrail-status
```

---

## GitHub Integration

### Authentication

Token scopes required:
- Org audit logs: `admin:org`, `audit_log`
- Enterprise audit logs: `admin:enterprise`, `audit_log`

```bash
--github-token "$GITHUB_TOKEN"
```

Or set `GITHUB_TOKEN` in your environment.

### CLI Examples

```bash
# Hunt today's activity for a user
dredge --github-org dbnz-io --github-token "$GITHUB_TOKEN" \
  github-hunt-audit --actor sabastante --today --include all

# Hunt an action over a date range
dredge --github-enterprise dbnz-io --github-token "$GITHUB_TOKEN" \
  github-hunt-audit --action repo.create \
  --start-time 2025-01-01T00:00:00Z --end-time 2025-01-07T23:59:59Z

# Hunt suspicious IP activity
dredge --github-org dbnz-io --github-token "$GITHUB_TOKEN" \
  github-hunt-audit --source-ip 203.0.113.50 --today --include all
```

---

## Kubernetes Integration

### Authentication

Dredge authenticates to Kubernetes the same way `kubectl` does, plus a first-class path for direct service-account/bearer-token auth (for library callers and automation that don't have a kubeconfig file on disk).

| Method | How |
|---|---|
| Kubeconfig ("auth like kubectl") | `--k8s-kubeconfig` (+ optional `--k8s-context`), or default `~/.kube/config` / `$KUBECONFIG`. Cloud-specific token exchange (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`) is resolved entirely by the kubeconfig's `exec` plugin — dredge never needs to know which cloud is behind the cluster. |
| In-cluster | `--k8s-in-cluster` — uses the pod's mounted service-account token. |
| Explicit service-account / bearer token | `--k8s-token` (or `--k8s-token-env-var`, default `K8S_TOKEN`) + `--k8s-api-server` (+ optional `--k8s-ca-cert`). In the library, `K8sAuthConfig.token_provider` accepts a callable that is re-invoked before **every** API call (no dredge-side caching) — useful for short-lived, auto-rotating tokens. |
| Default | Tries in-cluster first, falls back to the default kubeconfig location. |

**Region/cluster-flavor note:** response and forensics methods run against the standard Kubernetes API and behave identically on EKS, GKE, AKS, or self-managed clusters — only auth differs by flavor, and kubeconfig already abstracts that.

### Global Kubernetes CLI Flags

```
--k8s-kubeconfig               Path to kubeconfig file
--k8s-context                  Kubeconfig context to use
--k8s-in-cluster               Use the in-cluster (mounted) service account token
--k8s-token                    Explicit bearer/service-account token
--k8s-token-env-var            Env var to read the token from (default: K8S_TOKEN)
--k8s-api-server               API server URL (required with --k8s-token)
--k8s-ca-cert                  Path to CA cert file (used with --k8s-token)
--k8s-insecure-skip-tls-verify Disable TLS verification (used with --k8s-token)
--k8s-namespace                Default namespace for namespaced subcommands
--dry-run                      Simulate without making changes
```

### CLI Examples

```bash
# Quarantine a pod suspected of compromise
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s-quarantine-pod suspicious-pod

# Cordon and drain a node
dredge --k8s-context prod-cluster \
  k8s-drain-node ip-10-0-1-23.ec2.internal

# Disable a compromised ServiceAccount (delete tokens + bindings)
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s-disable-service-account leaked-sa

# Hunt Events for a namespace over the last 24h (default window)
dredge --k8s-context prod-cluster \
  k8s-hunt-events --namespace default --event-type Warning

# Find what a compromised ServiceAccount can do
dredge --k8s-context prod-cluster \
  k8s-hunt-role-bindings-for-subject --kind ServiceAccount --name leaked-sa

# Flag pods running with elevated host access
dredge --k8s-context prod-cluster k8s-hunt-privileged-pods

# Capture forensic evidence before containment
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s-get-pod-manifest suspicious-pod
```

---

## Library Usage

### AWS

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

auth = AwsAuthConfig(profile_name="dredge-role", region_name="us-east-1")
d = Dredge(auth=auth)

# Containment
d.aws_ir.response.disable_user("compromised-user")
d.aws_ir.response.isolate_ec2_instances(["i-0123456789abcdef0"])
d.aws_ir.response.quarantine_s3_bucket("sensitive-bucket")

# Hunting
result = d.aws_ir.hunt.lookup_events(access_key_id="AKIAIOSFODNN7EXAMPLE")
print(result.details["events"])

result = d.aws_ir.hunt.list_guardduty_findings("detector-id", severity_min=7.0)
print(result.details["findings"])
```

### GitHub

```python
from dredge import Dredge
from dredge.github_ir.config import GitHubIRConfig

cfg = GitHubIRConfig(org="dbnz-io", token="ghp_xxx")
d = Dredge(github_config=cfg)

res = d.github_ir.hunt.search_today(actor="sabastante")
print(res.details["events"])
```

### Kubernetes

```python
from dredge import Dredge
from dredge.k8s_ir.config import K8sAuthConfig

# "Auth like kubectl" -- resolves cloud-specific token exchange via the
# kubeconfig's exec plugin, same as `aws eks get-token` / `gke-gcloud-auth-plugin`.
cfg = K8sAuthConfig(context="prod-cluster")
d = Dredge(k8s_config=cfg)

# Containment
d.k8s_ir.response.quarantine_pod("default", "suspicious-pod")
d.k8s_ir.response.disable_service_account("default", "leaked-sa")
d.k8s_ir.response.drain_node("ip-10-0-1-23.ec2.internal")

# Hunting
result = d.k8s_ir.hunt.list_events(namespace="default", event_type="Warning")
print(result.details["events"])

result = d.k8s_ir.hunt.list_privileged_pods()
print(result.details["flagged_pods"])
```

Direct service-account auth (no kubeconfig needed -- e.g. for CI or a token pulled from a secrets manager):

```python
cfg = K8sAuthConfig(
    api_server="https://cluster.example.com",
    token_provider=lambda: fetch_token_from_vault(),  # re-invoked before every call
    ca_cert_file="/path/to/ca.pem",
)
d = Dredge(k8s_config=cfg)
```

---

## Roadmap

- **Azure** support (auth, IR actions, log hunting).
- **Okta** IR (suspend users, revoke sessions, hunt sign-in logs).
- **GitHub IR actions** (suspend user, revoke token, remove from org).
- **GCP** — complete implementation and test coverage.
- **Kubernetes**: cloud-specific audit log hunting (EKS → CloudWatch, GKE → Cloud Logging) composed with `aws_ir`/`gcp_ir`.
- **Kubernetes**: pod filesystem/memory forensic capture via ephemeral debug containers.
- **Kubernetes**: cross-cloud credential revocation for IRSA (EKS) / Workload Identity (GKE/AKS) bound ServiceAccounts.
- IoC-based hunting (IP/domain/hash correlation across providers).
- Shodan + VirusTotal reintegration.

---

## Contributing

PRs welcome. If you want to add modules (Azure, Okta, Datadog, JumpCloud), open an issue.
