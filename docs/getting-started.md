# Getting started

The fastest way to get value from dredge is **collect AWS logs and hunt through
them** — no containment, no risk, read-only. This page takes you from install to
your first hunt in a few minutes.

> New to the command layout? Commands are nested `provider → bucket → command`
> (e.g. `dredge aws hunt cloudtrail`). See [CLI overview](cli/README.md).

## 1. Install

```bash
pip install dredge-ir
```

The distribution is `dredge-ir`, but the command and import package are `dredge`
(`dredge ...`, `import dredge`). See [Installation](installation.md) for source
and Docker.

## 2. Point dredge at AWS

Dredge uses the standard AWS credential resolution (profile, env vars, EC2/ECS
role, or an assumed role). The simplest is a named profile + region as global
flags, before the command:

```bash
dredge --aws-profile ir --region us-east-1 aws hunt cloudtrail --today
```

Full auth options: [Authentication](authentication.md).

## 3. Collect: pull CloudTrail logs from S3

The single most useful starting move in an AWS investigation is getting the logs
local. For an organization / Control Tower CloudTrail bucket
(`…/<account-id>/CloudTrail/<region>/<year>/<month>/<day>/…`), grab the last
couple of days across **every account and region** in one command — dredge only
lists the dated folders inside the window, so it doesn't wade through years of
history:

```bash
dredge --aws-profile ir --region us-east-1 \
  aws forensics download-s3-logs \
  --bucket my-org-cloudtrail \
  --prefix AWSLogs/ \
  --destination ./ct-logs \
  --days-ago 2
```

- `--days-ago 2` — shortcut for "from 2 days ago until now". Use
  `--start-time` / `--end-time` (ISO 8601) for an exact window.
- `--prefix` should point at or above the account-id level.
- Files land flat in `./ct-logs`, gunzipped, ready to query.

## 4. Hunt offline over the logs you just pulled

No more AWS calls — query the local files. Find everything a suspected
access key did, projecting just the fields you care about:

```bash
dredge aws hunt query-cloudtrail-logs \
  --path ./ct-logs \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --fields eventTime,eventName,sourceIPAddress,userIdentity.arn
```

Filter by anything in the events — source IP, user, event name, region, account,
time range:

```bash
# Everything from a suspicious IP in one account
dredge aws hunt query-cloudtrail-logs \
  --path ./ct-logs --source-ip 203.0.113.50 --account-id 111122223333

# All console logins
dredge aws hunt query-cloudtrail-logs --path ./ct-logs --event-name ConsoleLogin
```

## 5. Hunt live (last ~90 days) via CloudTrail LookupEvents

When you don't have the logs staged, query CloudTrail directly:

```bash
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --start-time 2026-04-01T00:00:00Z --end-time 2026-04-12T00:00:00Z
```

Handy time shortcuts: `--today`, `--week-ago 2`, `--month-ago 1`.

## 6. Baseline-deviation hunts

Two higher-level hunts built for "did this identity do something out of
character":

```bash
# One identity, classified by whether each event's source IP is in an allowlist.
# The "unexpected" bucket is your deviation signal.
dredge --aws-profile ir --region us-east-1 \
  aws hunt user-activity-by-ip \
  --user deploy-bot \
  --allowed-ip 10.0.0.0/8,203.0.113.10 \
  --week-ago 1

# A list of suspected identities in one pass, streamed to a file so a long run
# survives a mid-list failure.
dredge --aws-profile ir --region us-east-1 \
  aws hunt cloudtrail-multi-user \
  --user alice,bob --users-file suspects.txt \
  --output-path ./multi-user-hits.jsonl \
  --week-ago 1
```

## 7. Output format

Everything prints JSON by default; pass `--output csv` on hunt commands to get a
table you can grep or open in a spreadsheet:

```bash
dredge --aws-profile ir --region us-east-1 \
  aws hunt guardduty --detector-id abc123 --severity-min 7.0 --output csv
```

## Where to go next

- **Full AWS command list & examples** → [CLI: AWS](cli/aws.md)
- **Containment (response actions)** — disable keys, isolate EC2, quarantine S3,
  etc. Always try `--dry-run` first → [CLI: AWS](cli/aws.md#response--containment)
- **Use it from Python instead of the shell** → [Library: AWS](library/aws.md)
- **GitHub / Kubernetes** → [CLI: GitHub](cli/github.md) ·
  [CLI: Kubernetes](cli/kubernetes.md)
- **Every action at a glance** → [Command & feature reference](reference.md)
