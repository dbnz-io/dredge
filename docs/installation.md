# Installation

## From PyPI

```bash
pip install dredge-ir
```

The **distribution** name is `dredge-ir` (the bare `dredge` name was already
taken on PyPI by an unrelated package). The **import package** and the **CLI
command** are both `dredge`:

```bash
dredge --help
```
```python
import dredge
```

Requires **Python 3.10+**. Dependencies are declared entirely in
`pyproject.toml` — there is no separate `requirements.txt`.

## From source (development)

```bash
git clone https://github.com/dbnz-io/dredge.git
cd dredge
pip install -e ".[test]"   # the [test] extra adds the pytest toolchain
pytest -q
```

## Docker

A `Dockerfile` is included:

```bash
docker build -t dredge:latest .
# or
podman build -t dredge:latest .

docker run --rm -e AWS_PROFILE -v ~/.aws:/root/.aws dredge:latest \
  --region us-east-1 aws hunt cloudtrail --today
```

## Verify

```bash
dredge --version
dredge --help          # categorized overview of every command
```

Next: [Getting started](getting-started.md).
