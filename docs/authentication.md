# Authentication

Auth is set with **global flags placed before the provider** on the CLI, or via
config objects in the library. This page covers all four providers.

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
