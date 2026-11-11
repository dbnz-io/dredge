# Authentication

Auth is set with **global flags placed before the provider** on the CLI, or via
config objects in the library. Huawei Cloud's AK/SK, temporary credentials,
profiles, credential providers, and CCE access are documented in the
[Huawei authentication guide](huawei.md#authentication), including
[Identity Center SSO and multiple profiles](huawei.md#sso-and-multiple-profiles).

## AWS

Precedence: explicit keys > named profile > default credential chain. Role
assumption and MFA are supported on top of any of those.

| Method | CLI | Library (`AwsAuthConfig`) |
|---|---|---|
| Default chain (env, `~/.aws/credentials`, instance role) | *(nothing)* | `AwsAuthConfig()` |
| Named profile | `--aws-profile ir` | `profile_name="ir"` |
| Explicit keys | `--aws-access-key-id …` `--aws-secret-access-key …` (`--aws-session-token …`) | `access_key_id=…, secret_access_key=…, session_token=…` |
| Assume a role | `--aws-role-arn …` (`--aws-external-id …`) | `role_arn=…, external_id=…` |

Region: `--aws-region` / `--region`, else `AWS_REGION` / `AWS_DEFAULT_REGION`,
else the profile's configured region.

AWS profile/region flags can also appear immediately after `aws`, before the
bucket (`hunt`, etc.). The secret hunt and AWS posture reviews support
[`--aws-profile all --aws-region all`](cli/aws.md#all-configured-profiles-and-enabled-regions)
to authenticate each configured profile and scan its account's enabled regions.
It reuses cached credentials; `--sso-login` can invoke AWS CLI login for expired
SSO sessions, with any browser/MFA interaction still handled by the user.

```bash
dredge --aws-profile ir --region us-east-1 aws hunt cloudtrail --today
dredge --aws-role-arn arn:aws:iam::123456789012:role/IR --region us-east-1 \
  aws hunt guardduty --detector-id abc123
```

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

d = Dredge(auth=AwsAuthConfig(profile_name="ir", region_name="us-east-1"))
```

### Deep assessment policy

Attach [policies/deep-security-audit.json](../policies/deep-security-audit.json)
as a customer-managed policy alongside AWS's
[`SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
on the assessment role. `SecurityAudit` focuses on security configuration
metadata; this add-on supplies broad inspection and evidence access. There is
no need to edit or replace the AWS-managed policy.

The add-on intentionally uses `Resource: "*"` and covers:

| Area | Access |
| --- | --- |
| Identity | IAM users, roles, trust/permission policies, credential reports, last-accessed reports, policy simulation, Organizations, Identity Center |
| Compute and containers | EC2 metadata/user data/console output, existing EBS snapshot blocks, ECS clusters/services/task definitions, EKS cluster metadata, Lambda configuration/code, ECR images |
| Application configuration | Elastic Beanstalk, App Runner, Batch, Glue, CodeBuild, Amplify, CloudFormation, AppConfig, SageMaker, Step Functions execution history |
| Secret values | Secrets Manager values, SSM parameters/history including `SecureString`, KMS decryption |
| Evidence | S3 objects and versions, CloudWatch logs including unmasking, Logs Insights queries, CloudTrail events/Lake queries, AWS Config history |
| Security controls | Security Hub, GuardDuty, Inspector/Inspector2, Macie, Detective, Access Analyzer, Security Lake configuration, Firewall Manager, Shield, WAF, Network Firewall, DNS Firewall, Audit Manager, Security Incident Response |
| Supporting infrastructure | Load balancers, Auto Scaling, RDS configuration, API Gateway, CloudFront, ACM, Private CA |

This grants access to plaintext secret values and potentially sensitive workload
data. The IAM policy includes query/report generation and decryption, but does
not grant `ecs:ExecuteCommand`, `ssm:SendCommand`, `ssm:StartSession`,
`lambda:InvokeFunction`, `iam:PassRole`, or snapshot creation. It does not grant
SQL access to databases or access to running-instance filesystems. Existing EBS
snapshot blocks can be read; creating new snapshots requires separate privileges.
Security Lake configuration access does not itself grant Lake Formation/Athena
access to the data lake.

Run these examples as a provisioning administrator, from the repository root,
replacing the account ID and role name:

```bash
aws iam create-policy \
  --policy-name DredgeDeepSecurityAudit \
  --description 'Broad inspection and secret-value access for security assessments' \
  --policy-document file://policies/deep-security-audit.json

aws iam attach-role-policy \
  --role-name AuditRole \
  --policy-arn arn:aws:iam::123456789012:policy/DredgeDeepSecurityAudit
```

The role must already have `SecurityAudit`. Creating/attaching the policy is an
administrator setup step; those privileges are not part of the assessment policy.
SCPs, permission boundaries, session policies, and resource policies still apply.
Customer-managed KMS keys must also authorize the assessment principal through
their [key policies/grants](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).
Cross-account evidence access requires the corresponding resource-side grants.
Queries, object reads, and decryption can incur AWS charges.

This policy authorizes capabilities; it does not make Dredge automatically read
every secret store or scan all S3 objects/logs. Dredge's S3/CloudWatch secret scans
still require [explicit targets and budgets](cli/aws.md#exposed-secrets), and the
scanner does not request CloudWatch unmasking even though the role can do so.

#### EKS: Kubernetes resources require cluster authorization

IAM permissions to inspect EKS do not by themselves authorize Kubernetes API
reads. For each EKS cluster, an administrator can create a `STANDARD` access
entry for the assessment role and associate
[`AmazonEKSAdminViewPolicy`](https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html#access-policy-permissions-amazoneksadminviewpolicy)
at cluster scope. AWS documents this as access to view all resources, including
Kubernetes Secrets. It is an **EKS access policy**, not an IAM managed policy.

The cluster must use `API` or `API_AND_CONFIG_MAP` authentication. If the role
already has an access entry, skip the create step:

```bash
aws eks create-access-entry \
  --region us-east-1 --cluster-name your-cluster \
  --principal-arn arn:aws:iam::123456789012:role/AuditRole \
  --type STANDARD

aws eks associate-access-policy \
  --region us-east-1 --cluster-name your-cluster \
  --principal-arn arn:aws:iam::123456789012:role/AuditRole \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminViewPolicy \
  --access-scope type=cluster
```

See AWS's [access entry](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html)
and [policy association](https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html)
instructions. The audit workstation also needs network access to the cluster API
endpoint. For self-managed Kubernetes, or legacy EKS authentication, arrange
the corresponding identity mapping and Kubernetes RBAC separately; ordinary
Kubernetes `view` access does not include Secrets.

Validation: checked against AWS's public
[service authorization data](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)
on 2026-11-06. All action selectors resolve; the policy is 4,978 characters
excluding whitespace, below the 6,144-character customer-managed policy limit.
It has not been deployed or tested against a particular account's effective
permissions.

## GitHub

Token scopes:
- Org audit logs: `admin:org`, `audit_log`
- Enterprise audit logs: `admin:enterprise`, `audit_log`

**Prefer the environment variable.** Export `GITHUB_TOKEN` and let dredge read
it — passing `--github-token <value>` exposes the secret in your shell history
and the process list (`ps`). Use the flag only for ad-hoc, throwaway tokens.

```bash
export GITHUB_TOKEN="ghp_..."
dredge --github-org dbnz-io github hunt audit --today --include all
```

Set exactly one of `--github-org` / `--github-enterprise`.

```python
from dredge import Dredge
from dredge.github_ir.config import GitHubIRConfig

# token resolved from GITHUB_TOKEN if not passed explicitly
d = Dredge(github_config=GitHubIRConfig(org="dbnz-io"))
```

`GitHubIRConfig.token_provider` accepts a callable, re-invoked before every call
(for short-lived tokens).

## Kubernetes

Dredge authenticates the same way `kubectl` does, plus a first-class path for
direct service-account/bearer-token auth (for automation without a kubeconfig on
disk). Response/forensics methods hit the standard Kubernetes API and behave
identically on EKS/GKE/AKS/self-managed — only auth differs by flavor, and
kubeconfig abstracts that (cloud token exchange like `aws eks get-token` /
`gke-gcloud-auth-plugin` / `kubelogin` is resolved by the kubeconfig's `exec`
plugin — dredge never needs to know the cloud).

| Method | CLI | Library (`K8sAuthConfig`) |
|---|---|---|
| Kubeconfig (like kubectl) | `--k8s-kubeconfig` (+ `--k8s-context`), or default `~/.kube/config` / `$KUBECONFIG` | `kubeconfig_path=…, context=…` |
| In-cluster | `--k8s-in-cluster` | `in_cluster=True` |
| Explicit token | `--k8s-token` (or `--k8s-token-env-var`) `--k8s-api-server` (+ `--k8s-ca-cert`) | `token=…` / `token_provider=…`, `api_server=…`, `ca_cert_file=…` |
| Default | *(nothing)* — in-cluster, then default kubeconfig | `K8sAuthConfig()` |

Precedence: explicit token/`token_provider` > `in_cluster` > kubeconfig/context >
default.

```bash
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s hunt privileged-pods
```

```python
from dredge import Dredge
from dredge.k8s_ir.config import K8sAuthConfig

d = Dredge(k8s_config=K8sAuthConfig(context="prod-cluster"))

# Direct token (no kubeconfig) — e.g. CI or a token from a secrets manager.
# token_provider is re-invoked before every API call (no dredge-side caching).
d = Dredge(k8s_config=K8sAuthConfig(
    api_server="https://cluster.example.com",
    token_provider=lambda: fetch_token_from_vault(),
    ca_cert_file="/path/to/ca.pem",
))
```

## GCP

Cloud Logging hunting is partially implemented. `GcpIRConfig` takes a project ID
and an optional credentials path. See [Roadmap](roadmap.md).
