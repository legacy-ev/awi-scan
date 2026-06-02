# Security Policy

`awi-scan` is an early scanner for Agentic Workflow Injection patterns in GitHub Actions.

Please report security issues privately to the maintainer before public disclosure. Until a project-specific address is available, open a GitHub security advisory in the repository.

## Scope

In scope:

- False negatives that allow obvious `P2A` or `P2S` workflow paths to pass.
- Parser bugs that crash on normal workflow YAML.
- Findings that recommend an unsafe rewrite.

Out of scope:

- Vulnerabilities in third-party actions referenced by fixtures.
- Broad GitHub Actions hardening unrelated to AI-agent taint paths.
