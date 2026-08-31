# Dredge documentation

Cloud incident response & threat hunting for AWS, Kubernetes, GitHub, and GCP —
as a Python library and a CLI.

## Start here

- **[Getting started](getting-started.md)** — install → collect AWS logs → first
  hunt, in a few minutes. The fastest, lowest-risk way in.
- **[Installation](installation.md)** — PyPI, from source, Docker.
- **[Authentication](authentication.md)** — how dredge authenticates to each
  provider.

## CLI usage

Nested commands: `dredge <provider> <bucket> <command>`.

- **[CLI overview](cli/README.md)** — command structure, global flags, dry-run,
  output formats.
- **[AWS](cli/aws.md)** — review (posture), hunt, response (containment), forensics.
- **[GitHub](cli/github.md)** — audit-log hunting and containment.
- **[Kubernetes](cli/kubernetes.md)** — hunt, response, forensics.

## Library usage

`from dredge import Dredge`.

- **[Library overview](library/README.md)** — the `Dredge` object, `OperationResult`,
  configuration, and dry-run.
- **[AWS](library/aws.md)** · **[GitHub](library/github.md)** ·
  **[Kubernetes](library/kubernetes.md)**

## Reference

- **[Command & feature reference](reference.md)** — every action across all
  providers, mapped to its CLI command and library method.
- **[Roadmap](roadmap.md)**
- **[Contributing](contributing.md)**

## What dredge covers

| Provider | Hunt | Response (containment) | Forensics |
|---|---|---|---|
| **AWS** | CloudTrail (live + offline), GuardDuty, Security Hub, Access Analyzer, Config, CloudWatch Logs, IAM credential report | IAM, EC2, RDS, ECS, S3, Lambda, KMS, Secrets, EventBridge, SSM, NACL | EBS snapshots, Lambda env, VPC flow logs, SSM history, CloudTrail status, **S3 log collection** |
| **Kubernetes** | Events API, RBAC exposure, privileged pods | RBAC, pods, nodes, NetworkPolicy quarantine, Secrets | pod/node manifests, logs, events, exec |
| **GitHub** | Org/Enterprise audit log, secret/code scanning | block/remove members, revoke deploy keys, delete webhooks, archive repos | org/repo settings, webhooks, branch protection |
| **GCP** | Cloud Logging (in progress) | — | — |
