<div align="center">
 <p>
  <h1>
    Dredge - 1.1.0
  </h1>
 </p>
</div>

<div align="center">

![CI](https://github.com/dbnz-io/dredge/actions/workflows/release.yml/badge.svg)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)

</div>

<div align="center">
  <h3>
   ⚡ Cloud log collection, threat hunting, and rapid response... pa' la hinchada ⚡
  </h3>
</div>

---

Dredge is a cloud incident-response and threat-hunting toolkit — a Python library
**and** a CLI — for **AWS, Kubernetes, GitHub, and GCP**. It's built for moving
fast when you don't have all the plumbing ready at 3AM: collect logs, hunt
through them, and contain — from one tool.

> ⭐ **Hunt CloudTrail across every AWS region at once.** `LookupEvents` is a
> regional API, so a normal search only sees one region. Dredge fans out to all
> your enabled regions **concurrently** and merges the results into one
> time-sorted timeline — one command, no scripting, no per-region loops.
> [Jump to it ↓](#hunt-cloudtrail-across-every-region-at-once)

- **AWS** — a **security review** (per-service + org-wide posture, CSV + HTML),
  hunt (CloudTrail live + offline **+ all-region fan-out**, GuardDuty, Security
  Hub, Config…), containment (IAM, EC2, RDS, ECS, S3, Lambda, KMS…), forensics
  (S3 log collection, snapshots, flow logs).
- **Kubernetes** — hunt, containment (RBAC, pods, nodes, NetworkPolicy), and
  forensics against any cluster (EKS/GKE/AKS/self-managed).
- **GitHub** — org/enterprise audit-log hunting **and** containment.
- **GCP** — Cloud Logging hunting (in progress).

📚 **Full documentation is in [`docs/`](docs/README.md).**

---

## Install

```bash
pip install dredge-ir
```

The distribution is `dredge-ir` (the bare `dredge` name is taken on PyPI); the
command and import package are both `dredge`. Python 3.10+. See
[docs/installation.md](docs/installation.md) for source and Docker.

---

## Quickstart — collect AWS logs and hunt (60 seconds)

The fastest, lowest-risk way to get value: pull CloudTrail logs and hunt through
them. All read-only.

```bash
# 1. Collect — pull the last 2 days of CloudTrail across every account/region
#    from an org / Control Tower S3 bucket. Date-aware: it only lists the dated
#    folders inside the window, not years of history.
dredge --aws-profile ir --region us-east-1 \
  aws forensics download-s3-logs \
  --bucket my-org-cloudtrail --prefix AWSLogs/ \
  --destination ./ct-logs --days-ago 2

# 2. Hunt offline over what you just pulled — no more AWS calls.
dredge aws hunt query-cloudtrail-logs \
  --path ./ct-logs --access-key-id AKIAIOSFODNN7EXAMPLE \
  --fields eventTime,eventName,sourceIPAddress,userIdentity.arn

# 3. Or hunt live via CloudTrail LookupEvents (last ~90 days).
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --user suspicious-user --week-ago 1
```

Baseline-deviation hunts, built in:

```bash
# One identity, each event tagged by whether its source IP is in an allowlist.
dredge --aws-profile ir --region us-east-1 \
  aws hunt user-activity-by-ip --user deploy-bot \
  --allowed-ip 10.0.0.0/8,203.0.113.10 --week-ago 1
```

👉 More: [Getting started](docs/getting-started.md) · [AWS CLI reference](docs/cli/aws.md)

---

## Hunt CloudTrail across every region at once

⭐ **Dredge's killer feature.** CloudTrail `LookupEvents` is a **regional** API — each region's endpoint only
returns the events recorded in that region. So the usual way to answer *"what did
this access key do anywhere in my account?"* is to loop over ~30 regions by hand
(or miss activity in the regions you forgot). Attackers know this, and operate in
regions you don't watch.

Dredge collapses that into one command. `--all-regions` queries **every enabled
region concurrently** and merges everything into a single time-sorted timeline:

```bash
# Every enabled region, all queried in parallel, merged into one timeline
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --access-key-id AKIAIOSFODNN7EXAMPLE --all-regions
```

Or target a specific set of regions:

```bash
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail --user suspicious-user \
  --regions us-east-1,eu-west-1,ap-southeast-2
```

`--regions` is comma-separated and/or repeatable (`--regions us-east-1,us-east-2`,
or `--regions us-east-1 --regions eu-west-1`, or any mix).

What you get:

- **Concurrent fan-out** — every regional endpoint is hit at the same time
  (tune with `--max-workers`), not one after another.
- **One merged, time-sorted timeline** — events from all regions in a single
  ordered list; each event keeps its `aws_region`.
- **Automatic region discovery** — `--all-regions` finds your *enabled* regions
  via EC2 `DescribeRegions` (opted-in only), so it doesn't waste calls on
  disabled ones.
- **Per-region visibility, no all-or-nothing** — a `by_region` breakdown reports
  each region's event count and any error, so a region you can't reach is noted
  without failing the rest of the hunt.
- **All the same filters** — `--access-key-id`, `--user`, `--event-name`,
  `--source-ip`, and the time flags apply identically in every region;
  `--max-events` becomes the per-region cap.

From Python:

```python
res = d.aws_ir.hunt.lookup_events_multi_region(
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    regions="all",                 # or ["us-east-1", "eu-west-1"]
)
res.details["events"]              # merged, time-sorted across regions
res.details["by_region"]           # per-region counts + any errors
```

> The global `--region` sets the base session region; `--all-regions` /
> `--regions` control the fan-out. Full details in
> [AWS CLI reference](docs/cli/aws.md#across-multiple-regions-concurrent).

---

## Command layout

Commands are nested `provider → bucket → command`, with help at every level:

```bash
dredge --help                      # everything, grouped by provider × bucket
dredge aws hunt --help             # commands under aws hunt
dredge aws hunt cloudtrail --help  # a command's options
```

Global flags (auth, region, `--dry-run`) go **before** the provider. Buckets are
`review` (posture), `hunt` (read-only investigation), `response` (containment),
`forensics` (evidence).

---

## Tactical one-liners

```bash
# Security review — posture snapshot as CSV + HTML (where to dig deeper)
dredge --aws-profile ir --region us-east-1 \
  aws review full --incident-start 2026-04-01T00:00:00Z \
  --csv ./review.csv --html ./review.html

# Contain — always dry-run destructive actions first (global --dry-run)
dredge --aws-profile ir --region us-east-1 --dry-run \
  aws response disable-user --user compromised-user
dredge --aws-profile ir --region us-east-1 \
  aws response quarantine-s3-bucket suspicious-bucket

# GitHub — hunt the audit log (token from $GITHUB_TOKEN)
dredge --github-org dbnz-io github hunt audit --actor sabastante --today --include all

# Kubernetes — isolate a pod, hunt privileged pods
dredge --k8s-context prod-cluster --k8s-namespace default \
  k8s response quarantine-pod suspicious-pod
dredge --k8s-context prod-cluster k8s hunt privileged-pods
```

---

## Use it from Python

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

d = Dredge(auth=AwsAuthConfig(profile_name="ir", region_name="us-east-1"))

# collect, then hunt
d.aws_ir.forensics.download_s3_logs("my-org-cloudtrail", prefix="AWSLogs/",
                                    destination="./ct-logs", days_ago=2)
res = d.aws_ir.hunt.lookup_events(access_key_id="AKIAIOSFODNN7EXAMPLE")
print(res.details["events"])
```

Every action returns an `OperationResult` (`success`, `details`, `errors`).
👉 [Library docs](docs/library/README.md).

---

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Install → collect → first hunt |
| [Installation](docs/installation.md) | PyPI, source, Docker |
| [Authentication](docs/authentication.md) | AWS · GitHub · Kubernetes · GCP |
| [CLI](docs/cli/README.md) | [AWS](docs/cli/aws.md) · [GitHub](docs/cli/github.md) · [Kubernetes](docs/cli/kubernetes.md) |
| [Library](docs/library/README.md) | [AWS](docs/library/aws.md) · [GitHub](docs/library/github.md) · [Kubernetes](docs/library/kubernetes.md) |
| [Command reference](docs/reference.md) | Every command, generated from the CLI |
| [Roadmap](docs/roadmap.md) · [Contributing](docs/contributing.md) | |

---

## License

[MPL-2.0](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
