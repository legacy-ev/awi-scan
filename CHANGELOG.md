# Changelog

## v0.1.0

- Initial CLI and GitHub Action for detecting Agentic Workflow Injection patterns.
- Added `AWI001` prompt-to-agent, `AWI002` prompt-to-script, `AWI003` agent-output-to-script, and `AWI004` risky configuration findings.
- Added terminal, Markdown, JSON, and SARIF output.
- Added real-world validation on 20 public repos with AI-looking GitHub Actions.
- Reduced noisy findings with source-confidence scoring, trusted-user gate downgrades, and status-comment suppression.
