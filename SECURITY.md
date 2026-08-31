# Security Policy

Dredge is incident-response tooling that handles cloud credentials and can
take destructive containment actions. We take security issues in it seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/dbnz-io/dredge/security/advisories/new)
  (Security → Advisories → "Report a vulnerability"), or
- Email **security@solidaritylabs.io** with the details.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (proof-of-concept if possible).
- Affected version(s) / commit.
- Any suggested remediation.

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan or timeline within **10 business days**. Please give us a
reasonable window to release a fix before any public disclosure; we're happy
to credit you in the advisory unless you'd prefer to remain anonymous.

## Scope

In scope:

- Credential handling and leakage (e.g. secrets written to logs, results, or
  SBOM/artifacts).
- Response actions executing when `--dry-run` / `dry_run=True` is set.
- Privilege or authorization flaws in how dredge assumes roles / uses tokens.
- Path traversal or arbitrary file write via downloaded evidence (e.g.
  `download_s3_logs` local filenames).
- Injection or SSRF in how filters/queries are constructed.

Out of scope:

- Vulnerabilities in AWS/GCP/GitHub/Kubernetes themselves.
- Misconfiguration of the *user's* cloud environment.
- Findings that require credentials the reporter is not authorized to use.

## Supported versions

Security fixes target the latest released version on the default branch.
