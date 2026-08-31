# Library overview

Everything the CLI does is the `dredge` Python package underneath. Use it to
build your own IR tooling, notebooks, or automation.

> Installed via `pip install dredge-ir`; the import package is `dredge`.

## The `Dredge` object

Construct `Dredge` with the config(s) for the providers you need. Each provider
is a namespace exposing `.hunt`, `.response`, and `.forensics`:

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

d = Dredge(auth=AwsAuthConfig(profile_name="ir", region_name="us-east-1"))

d.aws_ir.hunt        # investigation (read-only)
d.aws_ir.response    # containment (mutating)
d.aws_ir.forensics   # evidence capture
```

Provider namespaces (each optional — only built if you pass its config):

| Namespace | Enabled by |
|---|---|
| `d.aws_ir` | always (uses `auth=` / `session=` / default chain) |
| `d.github_ir` | `github_config=GitHubIRConfig(...)` |
| `d.k8s_ir` | `k8s_config=K8sAuthConfig(...)` |
| `d.gcp_ir` | `gcp_config=GcpIRConfig(...)` |

GitHub/GCP/Kubernetes clients are imported lazily, so a consumer that never
passes their config never imports those dependencies.

See [Authentication](../authentication.md) for every config object.

## `OperationResult`

**Every** action — hunt, response, forensics — returns an `OperationResult`
dataclass:

```python
@dataclass
class OperationResult:
    operation: str            # e.g. "lookup_events"
    target: str               # what it acted on
    success: bool
    details: dict             # payload: events / findings / ids / dry_run …
    errors: list[str]
```

```python
res = d.aws_ir.hunt.lookup_events(access_key_id="AKIAIOSFODNN7EXAMPLE")
if res.success:
    for event in res.details["events"]:
        ...
else:
    print(res.errors)
```

The `details` payload key varies by method (`events`, `findings`,
`flagged_pods`, …) and is noted per provider. `asdict(res)` gives you a plain
dict for JSON serialization.

## Dry-run

Pass `DredgeConfig(dry_run=True)` to make **response** actions simulate: no
mutating API call, and the result has `details["dry_run"] = True`. Applies to
AWS, Kubernetes, and GitHub response actions.

```python
from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig

d = Dredge(
    auth=AwsAuthConfig(profile_name="ir", region_name="us-east-1"),
    config=DredgeConfig(dry_run=True),
)
res = d.aws_ir.response.terminate_ec2_instances(["i-0123456789abcdef0"])
assert res.details["dry_run"] is True   # nothing was terminated
```

## Per-provider pages

- [AWS](aws.md) · [GitHub](github.md) · [Kubernetes](kubernetes.md)

For the complete action list mapped to both CLI commands and library methods,
see the [command & feature reference](../reference.md).
