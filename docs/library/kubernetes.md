# Library — Kubernetes

```python
from dredge import Dredge
from dredge.k8s_ir.config import K8sAuthConfig

# "Auth like kubectl": cloud token exchange (aws eks get-token / gke-gcloud-auth-
# plugin / kubelogin) is resolved by the kubeconfig's exec plugin.
d = Dredge(k8s_config=K8sAuthConfig(context="prod-cluster"))
```

Every call returns an [`OperationResult`](README.md#operationresult). Methods hit
the standard Kubernetes API and behave the same on EKS/GKE/AKS/self-managed.

## Hunt

```python
res = d.k8s_ir.hunt.list_events(namespace="default", event_type="Warning")
print(res.details["events"])

res = d.k8s_ir.hunt.list_role_bindings_for_subject(kind="ServiceAccount", name="leaked-sa")

res = d.k8s_ir.hunt.list_privileged_pods()
print(res.details["flagged_pods"])
```

## Forensics

```python
d.k8s_ir.forensics.get_pod_manifest("default", "suspicious-pod")
d.k8s_ir.forensics.get_pod_logs("default", "suspicious-pod")
d.k8s_ir.forensics.describe_node("ip-10-0-1-23.ec2.internal")
```

## Response — containment

Honors dry-run (`DredgeConfig(dry_run=True)`).

```python
d.k8s_ir.response.quarantine_pod("default", "suspicious-pod")
d.k8s_ir.response.disable_service_account("default", "leaked-sa")
d.k8s_ir.response.drain_node("ip-10-0-1-23.ec2.internal")
```

> NetworkPolicy quarantine depends on the cluster's CNI enforcing NetworkPolicy
> (Calico, Cilium, …). Node/pod actions operate at the Kubernetes API level only
> — they don't stop or snapshot the underlying VM; compose with `d.aws_ir` /
> `d.gcp_ir` for that.

## Direct token auth (no kubeconfig)

For CI or automation pulling a token from a secrets manager. `token_provider` is
re-invoked before **every** API call (no dredge-side caching), so short-lived
auto-rotating tokens work:

```python
d = Dredge(k8s_config=K8sAuthConfig(
    api_server="https://cluster.example.com",
    token_provider=lambda: fetch_token_from_vault(),
    ca_cert_file="/path/to/ca.pem",
))
```
