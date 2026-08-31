# CLI — Kubernetes

`dredge k8s <bucket> <command>`. Auth is global, before `k8s` — dredge
authenticates like `kubectl` (see
[Authentication](../authentication.md#kubernetes)). Examples use
`--k8s-context prod-cluster`.

Response/forensics run against the standard Kubernetes API and behave the same on
EKS, GKE, AKS, or self-managed clusters.

## Hunt

```bash
# Events for a namespace (default window: last 24h)
dredge --k8s-context prod-cluster \
  k8s hunt events --namespace default --event-type Warning

# What can a (possibly compromised) ServiceAccount do?
dredge --k8s-context prod-cluster \
  k8s hunt role-bindings-for-subject --kind ServiceAccount --name leaked-sa

# Pods running with elevated host access (privileged, hostNetwork/PID/IPC)
dredge --k8s-context prod-cluster k8s hunt privileged-pods

# Pods running under a ServiceAccount
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s hunt pods-by-service-account --service-account leaked-sa
```

## Forensics

Capture evidence **before** you contain:

```bash
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s forensics get-pod-manifest suspicious-pod

dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s forensics get-pod-logs suspicious-pod

dredge --k8s-context prod-cluster \
  k8s forensics describe-node ip-10-0-1-23.ec2.internal
```

## Response — containment

**Mutating.** Dry-run first with the global `--dry-run` flag (before `k8s`).

```bash
# Isolate a pod with a deny-all NetworkPolicy
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s response quarantine-pod suspicious-pod

# Disable a compromised ServiceAccount (delete its tokens + bindings)
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s response disable-service-account leaked-sa

# Cordon + evict all pods off a node
dredge --k8s-context prod-cluster \
  k8s response drain-node ip-10-0-1-23.ec2.internal
```

> NetworkPolicy quarantine only takes effect if the cluster's CNI enforces
> NetworkPolicy (e.g. Calico, Cilium). Destructive node/pod actions operate at
> the Kubernetes API level only — they do not stop or snapshot the underlying
> VM; compose with `aws`/`gcp` for that.

Full surface (delete pod/node, scale deployment, quarantine namespace, revoke
role bindings, delete secret, label resource): `dredge k8s response --help`.
