# Awesome List PRs

These are the best-fit curated lists for `awi-scan`. Local PR branches have been prepared in `.awesome-targets/`, but forks could not be created from this environment because GitHub API fork creation requires authenticated account access.

## Prepared PR 1

Target:

https://github.com/johnbillion/awesome-github-actions-security

Section:

`Static workflow file scanning`

Branch prepared locally:

```text
.awesome-targets/johnbillion__awesome-github-actions-security
branch: add-awi-scan
commit: Add awi-scan
```

Entry:

```md
* [awi-scan](https://github.com/legacy-ev/awi-scan) ([List of rules here](https://github.com/legacy-ev/awi-scan#rules))
```

PR title:

```text
Add awi-scan
```

PR body:

```text
Adds awi-scan, an open-source CLI and GitHub Action for detecting Agentic Workflow Injection risks in AI-powered GitHub Actions.

It fits the static workflow file scanning section because it scans workflow YAML and supports SARIF output for code scanning integrations.
```

## Prepared PR 2

Target:

https://github.com/ProjectRecon/awesome-ai-agents-security

Section:

`Static Analysis & Linters`

Branch prepared locally:

```text
.awesome-targets/ProjectRecon__awesome-ai-agents-security
branch: add-awi-scan
commit: Add awi-scan
```

Entry:

```md
- **[awi-scan](https://github.com/legacy-ev/awi-scan)** - A CLI and GitHub Action for detecting Agentic Workflow Injection risks in AI-powered GitHub Actions, including prompt-to-agent and agent-output-to-script paths.
```

PR title:

```text
Add awi-scan
```

PR body:

```text
Adds awi-scan to Static Analysis & Linters.

awi-scan detects Agentic Workflow Injection risks in AI-powered GitHub Actions, including prompt-to-agent and agent-output-to-script paths.
```

## Prepared PR 3

Target:

https://github.com/ottosulin/awesome-ai-security

Section:

`Tools`

Branch prepared locally:

```text
.awesome-targets/ottosulin__awesome-ai-security
branch: add-awi-scan
commit: Add awi-scan
```

Entry:

```md
* [awi-scan](https://github.com/legacy-ev/awi-scan) - _CLI and GitHub Action for detecting Agentic Workflow Injection risks in AI-powered GitHub Actions._
```

PR title:

```text
Add awi-scan
```

PR body:

```text
Adds awi-scan, an open-source CLI/GitHub Action that scans AI-powered GitHub Actions for Agentic Workflow Injection risks.
```

## Not Submitted Yet

These were intentionally skipped for now:

- `TalEliyahu/Awesome-AI-Security`: published inclusion criteria require 220+ stars and 3+ contributors.
- Broad DevSecOps lists: acceptable but less targeted than GitHub Actions and AI-agent security lists.
- Prompt-injection-only lists: possible later, but `awi-scan` is more workflow/agent automation security than general prompt-injection testing.

## Manual Fork Flow

For each target repo:

1. Open the target repo in GitHub.
2. Click `Fork`.
3. Keep the same fork name under `legacy-ev`.
4. Tell Codex the fork exists.
5. Codex can push the prepared `add-awi-scan` branch and give you a compare URL.
