# Maintainer Workflows

`awi-scan` is built around ongoing open-source maintenance work, not one-off code generation.

## Where Codex Helps

- Rule development: turn real workflow patterns into targeted scanner logic and regression fixtures.
- Triage: classify user-reported snippets as true AWI paths, generic GitHub Actions risk, or noise.
- Review: inspect scanner changes for false-positive risk before release.
- Docs: generate concise safer rewrites for vulnerable AI workflow patterns.
- Release work: keep CLI, GitHub Action, SARIF output, docs, and fixtures in sync.

## API Credit Use Case

API credits would support OSS-only maintainer automation:

- Batch-review public fixture workflows gathered with permission or from public repos.
- Draft suggested safer workflow rewrites from scanner findings.
- Build eval cases that compare noisy and actionable findings.
- Summarize issue reports and propose minimal reproductions.

Credits would not be used for unrelated commercial work, unauthorized security testing, or scanning repositories without permission where authorization is required.

## Current Evidence

- Public repository: https://github.com/legacy-ev/awi-scan
- Validation: [`VALIDATION.md`](VALIDATION.md)
- Tests: `npm.cmd test`
- Outputs: terminal, Markdown, JSON, SARIF
- Distribution targets: npm CLI and GitHub Action
