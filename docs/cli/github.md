# CLI — GitHub

`dredge github <bucket> <command>`. Set exactly one of `--github-org` /
`--github-enterprise` (global, before `github`). Export `GITHUB_TOKEN` rather
than passing `--github-token` — see [Authentication](../authentication.md#github).

## Hunt — audit log

Reads the token from `$GITHUB_TOKEN`:

```bash
# Today's activity for a user (web + git events)
dredge --github-org dbnz-io \
  github hunt audit --actor sabastante --today --include all

# A specific action over a date range
dredge --github-enterprise dbnz-io \
  github hunt audit --action repo.create \
  --start-time 2025-01-01T00:00:00Z --end-time 2025-01-07T23:59:59Z

# Activity from a suspicious IP
dredge --github-org dbnz-io \
  github hunt audit --source-ip 203.0.113.50 --today --include all
```

Filters: `--actor`, `--action`, `--repo`, `--source-ip`, time range,
`--include web|git|all`. Pagination and rate limiting are handled for you.

Other hunts: `github hunt secret-scanning`, `github hunt code-scanning`,
`github hunt list-org-members`, `github hunt list-outside-collaborators`,
`github hunt list-deploy-keys`. See `dredge github hunt --help`.

## Response — containment

**Mutating.** Dry-run first with the global `--dry-run` flag (before `github`);
GitHub response actions honor it (no API call, result includes `"dry_run": true`).

```bash
# Block a user from all org interaction
dredge --github-org dbnz-io --dry-run github response block-org-member --username evil-actor

# Remove a member from the org
dredge --github-org dbnz-io github response remove-org-member --username evil-actor

# Revoke a repo deploy key
dredge --github-org dbnz-io github response revoke-deploy-key --repo my-repo --key-id 123456

# Delete an org webhook (attacker persistence / exfil)
dredge --github-org dbnz-io github response delete-org-webhook --hook-id 7654321

# Archive (lock down) a compromised repo
dredge --github-org dbnz-io github response archive-repository --repo compromised-repo
```

See `dredge github response --help` for the complete list (remove collaborator,
delete repo webhook, etc.).

## Forensics

Snapshot org/repo configuration for evidence:

```bash
dredge --github-org dbnz-io github forensics org-settings
dredge --github-org dbnz-io github forensics repo-metadata --repo my-repo
dredge --github-org dbnz-io github forensics branch-protection --repo my-repo --branch main
dredge --github-org dbnz-io github forensics org-webhooks
```
