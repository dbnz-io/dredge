# Contributing

PRs welcome — especially new provider modules (Azure, Okta, Datadog, JumpCloud).
For anything substantial, open an issue first to discuss the shape.

## Development setup

```bash
git clone https://github.com/dbnz-io/dredge.git
cd dredge
pip install -e ".[test]"   # runtime deps + pytest toolchain
```

Dependencies live only in `pyproject.toml` (no `requirements.txt`). The `[test]`
extra is the single source for the test toolchain used locally and in CI.

## Tests

AWS/Kubernetes/GitHub API calls are mocked — no real cloud credentials or
cluster are needed.

```bash
pytest -q                                              # run everything
pytest --cov=dredge --cov-report=term-missing -q       # with coverage
pytest tests/test_aws_hunt.py -q                        # a single file
```

- Test files map 1:1 to source modules (`tests/test_aws_hunt.py` ↔
  `dredge/aws_ir/hunt.py`).
- CI enforces an **80% coverage floor**.

## Before you open a PR

CI runs the same pipeline as a single workflow (`.github/workflows/release.yml`,
"CI / Release"), split into domain jobs so a failure names the culprit:

- **test** — matrix Python 3.10–3.13, pytest + 80% coverage floor
- **security** — `bandit -r dredge` (strict; annotate genuine false positives
  inline with `# nosec <id>` + a justification comment on the preceding line)
- **package** — `python -m build` + `twine check` + a clean-wheel smoke test

Run them locally first:

```bash
pytest --cov=dredge --cov-fail-under=80 -q
bandit -r dredge -q
python -m build && python -m twine check dist/*
```

## Conventions

- New CLI commands are registered explicitly nested:
  `subparsers.command("<provider>", "<bucket>", "<name>", help="...")` — the
  bucket is `hunt` / `response` / `forensics`.
- Response (mutating) methods must honor `DredgeConfig(dry_run=True)`.
- Never return raw secrets through a result; redact.

## Releasing (maintainers)

Bump `version` in `pyproject.toml` in your PR. On merge to `main`, the pipeline
publishes `dredge-ir` to PyPI (Trusted Publishing) and cuts a GitHub Release
`v<version>` with the wheel/sdist + CycloneDX SBOM. The version gate means only a
version bump triggers a release. PyPI versions are immutable — validate on
TestPyPI first when in doubt.

## Security

Report vulnerabilities privately — see [SECURITY.md](../SECURITY.md).
