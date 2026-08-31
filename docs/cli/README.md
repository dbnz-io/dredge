# CLI overview

Dredge's CLI is nested by **provider → bucket → command**:

```
dredge <provider> <bucket> <command> [options]
        │          │        │
        │          │        └─ e.g. cloudtrail, quarantine-pod, audit
        │          └────────── hunt · response · forensics
        └───────────────────── aws · k8s · github
```

- **provider** — `aws`, `k8s`, `github`
- **bucket** — `hunt` (read-only investigation), `response` (containment /
  mutating), `forensics` (evidence capture)
- **command** — the specific action

## Discovering commands

Help is available at every level and reveals what's below it:

```bash
dredge --help                        # global overview, grouped by provider × bucket
dredge aws --help                    # buckets under aws
dredge aws hunt --help               # commands under aws hunt
dredge aws hunt cloudtrail --help    # that command's full options
```

A bare `dredge aws` or `dredge aws hunt` just prints that level's help.

## Global flags go before the provider

Auth, region, and `--dry-run` are **global** — put them before the provider:

```bash
dredge --aws-profile ir --region us-east-1 aws response disable-user --user bob
        └─────────────── global ──────────┘ └──────── command ────────┘
```

See [Authentication](../authentication.md) for the full auth flag set per
provider.

## Dry-run

`--dry-run` (global) makes **response/containment** commands simulate instead of
mutating — no API call is made and the result includes `"dry_run": true`.
Supported for AWS, Kubernetes, **and** GitHub response actions. Always dry-run a
destructive command first:

```bash
dredge --aws-profile ir --region us-east-1 --dry-run \
  aws response terminate-ec2 i-0123456789abcdef0
```

Hunt/forensics commands are read-only, so `--dry-run` is a no-op for them.

## List arguments

Flags that take a list of values — `--regions`, `--allowed-ip`, `--user`,
`--ip` — are **comma-separated and/or repeatable**, and both forms mix freely:

```bash
--allowed-ip 10.0.0.0/8,203.0.113.10          # comma-separated
--allowed-ip 10.0.0.0/8 --allowed-ip 1.2.3.4  # repeated flag
--user alice,bob --user carol                  # a mix
```

Several also accept a `--*-file` (e.g. `--users-file`, `--allowed-ips-file`)
pointing at a newline-delimited file, combined with any flags.

## Output format

Output is JSON by default. Hunt commands accept `--output csv` for a flat table:

```bash
dredge --aws-profile ir --region us-east-1 \
  aws hunt guardduty --detector-id abc123 --severity-min 7.0 --output csv
```

## Per-provider pages

- [AWS](aws.md) — the largest surface: hunt, response, forensics
- [GitHub](github.md)
- [Kubernetes](kubernetes.md)
