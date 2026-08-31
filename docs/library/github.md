# Library — GitHub

```python
from dredge import Dredge
from dredge.github_ir.config import GitHubIRConfig

# token resolved from $GITHUB_TOKEN if not passed explicitly (preferred).
# Set exactly one of org= / enterprise=.
d = Dredge(github_config=GitHubIRConfig(org="dbnz-io"))
```

Every call returns an [`OperationResult`](README.md#operationresult).

## Hunt — audit log

```python
res = d.github_ir.hunt.search_audit_log(actor="sabastante")
print(res.details["events"])

res = d.github_ir.hunt.search_audit_log(
    action="repo.create",
    include="all",
)
```

Filters (all keyword): `actor`, `action`, `repo`, `source_ip`, `start_time`,
`end_time`, `include` (`"web"`/`"git"`/`"all"`), `max_events`. Pagination and
rate limiting are handled internally.

Other hunts: `hunt_secret_scanning_alerts`, `hunt_code_scanning_alerts`,
`list_org_members`, `list_outside_collaborators`, `list_deploy_keys`.

## Response — containment

Honors dry-run (`DredgeConfig(dry_run=True)`) — see
[dry-run](README.md#dry-run).

```python
d.github_ir.response.block_org_member("evil-actor")
d.github_ir.response.remove_org_member("evil-actor")
d.github_ir.response.revoke_deploy_key("my-repo", 123456)
d.github_ir.response.delete_org_webhook(7654321)
d.github_ir.response.archive_repository("compromised-repo")
```

## Forensics

```python
d.github_ir.forensics.get_org_settings()
d.github_ir.forensics.get_repo_metadata("my-repo")
d.github_ir.forensics.get_branch_protection("my-repo", "main")
```
