# Promotion Kit

Use this page as the public website URL:

https://raw.githack.com/legacy-ev/awi-scan/main/docs/index.html

Use this as the canonical repo URL:

https://github.com/legacy-ev/awi-scan

## Launch Positioning

One-line pitch:

> awi-scan is an open-source CLI and GitHub Action that detects Agentic Workflow Injection risks in AI-powered GitHub Actions.

Short pitch:

> AI GitHub Actions increasingly read issue, PR, and comment text, then feed it into agents that can label, review, fix, or mutate repos. awi-scan checks for prompt-to-agent and agent-output-to-script paths so maintainers can review those workflows before they become incidents.

Why it is timely:

> AI-agent workflows are moving from experiments into CI. The security risk is no longer only "bad generated code"; it is untrusted GitHub event text steering agents inside privileged automation.

## Best Submission Order

1. GitHub repo topics and website URL.
2. Hacker News Show HN.
3. LinkedIn/X personal post.
4. Dev.to technical explainer.
5. Curated awesome-list PRs.
6. Reddit only in communities that explicitly allow OSS showcase posts.
7. Product Hunt only after the README/demo has screenshots and a short video/GIF.

## GitHub Repo Details

Description:

```text
Scan AI-powered GitHub Actions for prompt-to-agent injection risks.
```

Website:

```text
https://raw.githack.com/legacy-ev/awi-scan/main/docs/index.html
```

Topics:

```text
github-actions security ai-security prompt-injection devsecops sarif codex ai-agents open-source
```

## Show HN

Title:

```text
Show HN: awi-scan – scan AI GitHub Actions for prompt-to-agent injection
```

Body:

```text
I built awi-scan, a small open-source CLI/GitHub Action for a narrow AI workflow security problem: untrusted GitHub issue, PR, and comment text flowing into AI-agent prompts, then into shell commands or repo mutations.

It detects four patterns:
- AWI001: prompt-to-agent injection
- AWI002: prompt-to-script injection
- AWI003: agent output reaching script/GitHub mutation steps
- AWI004: external-user triggers combined with write-token AI workflows

It supports terminal, Markdown, JSON, and SARIF output. I also ran a validation pass across 20 public repos with AI-looking GitHub Actions and documented the signal/noise in the repo.

Repo: https://github.com/legacy-ev/awi-scan
Demo page: https://raw.githack.com/legacy-ev/awi-scan/main/docs/index.html

I’d especially appreciate feedback from maintainers using Claude/Gemini/OpenAI/Copilot-style actions in CI.
```

## LinkedIn / X

Short post:

```text
I just released awi-scan: an open-source CLI and GitHub Action for detecting Agentic Workflow Injection risks in AI-powered GitHub Actions.

The core question: can untrusted issue/PR/comment text steer an AI agent, and can that agent then steer scripts or repo mutations?

It supports terminal, Markdown, JSON, and SARIF output, and I validated it against 20 public repos with AI-looking workflows.

GitHub: https://github.com/legacy-ev/awi-scan
Demo: https://raw.githack.com/legacy-ev/awi-scan/main/docs/index.html
```

Thread:

```text
1/ I released awi-scan, an OSS scanner for AI-powered GitHub Actions.

It looks for Agentic Workflow Injection: untrusted GitHub event text flowing into AI-agent prompts, then into scripts or repo mutations.

https://github.com/legacy-ev/awi-scan

2/ The problem:

AI workflows now read issue bodies, PR titles, comments, labels, and branch names, then ask agents to triage, review, fix, label, or open follow-up changes.

That creates new prompt-to-agent and prompt-to-script paths inside CI.

3/ awi-scan detects:

AWI001: untrusted text reaches an agent prompt
AWI002: untrusted text reaches shell/GitHub API calls
AWI003: agent output reaches scripts/mutations
AWI004: external-user triggers plus write-token AI workflows

4/ I validated it across 20 public repos with AI-looking GitHub Actions.

The first pass exposed both useful findings and noise, then I tuned severity with source confidence and trusted-user gate detection.

Validation log: https://github.com/legacy-ev/awi-scan/blob/main/VALIDATION.md

5/ I’d love feedback from anyone running Claude, Gemini, OpenAI, Codex, or Copilot-style actions in GitHub workflows.
```

## Dev.to / Blog Draft

Title:

```text
The AI GitHub Actions risk hiding in issue comments
```

Outline:

```text
1. AI workflows are moving into CI.
2. GitHub event text is often attacker-controlled.
3. Prompt injection becomes more serious when the agent can mutate the repo.
4. Define P2A and P2S with small workflow snippets.
5. Show awi-scan output.
6. Explain validation on 20 public repos and what was noisy.
7. Invite maintainers to contribute fixtures and sink patterns.
```

Opening:

```text
AI coding agents are no longer just local assistants. They are increasingly embedded in GitHub Actions, where they read issues, PRs, and comments, then triage, review, label, or even open changes.

That creates a new security question for maintainers: can an outside user write text that becomes instructions for an AI agent running inside your CI?
```

## Awesome List Targets

Manual PR candidates:

- https://github.com/ottosulin/awesome-ai-security
- Awesome GitHub Actions lists that include security or workflow tools.
- Awesome DevSecOps lists that accept open-source scanners.
- Awesome prompt-injection / LLM security lists.

PR blurb:

```text
- [awi-scan](https://github.com/legacy-ev/awi-scan) - CLI and GitHub Action for detecting Agentic Workflow Injection risks in AI-powered GitHub Actions, including prompt-to-agent and agent-output-to-script paths.
```

## Reddit Guidance

Do not mass-post. Use only communities or recurring threads that explicitly allow project showcases or free OSS tools. Lead with the security lesson, disclose that you built it, and ask for workflow examples/feedback rather than votes.

Safer post:

```text
I built a small OSS scanner after noticing a pattern in AI GitHub Actions: issue/PR/comment text often gets passed into an AI prompt, and sometimes the agent output is used later by shell or GitHub API steps.

The tool is awi-scan: https://github.com/legacy-ev/awi-scan

It is early and heuristic, but I validated it against 20 public repos and documented where it was useful vs noisy. I’m looking for feedback from maintainers who run AI workflows in CI.
```

## Product Hunt

Wait until there is:

- A short screen recording or GIF.
- A GitHub release page with screenshots.
- At least a few external stars or comments.
- A clear install path through npm or GitHub Actions.

Product name:

```text
awi-scan
```

Tagline:

```text
Scan AI GitHub Actions for prompt-to-agent injection
```

Description:

```text
awi-scan is an open-source CLI and GitHub Action that detects where untrusted GitHub issue, PR, or comment text can steer AI agents and reach scripts or repository mutations.
```

## Codex OSS Application Support

Use this repo evidence in the application:

- Public repo: https://github.com/legacy-ev/awi-scan
- Website: https://raw.githack.com/legacy-ev/awi-scan/main/docs/index.html
- Release tag: https://github.com/legacy-ev/awi-scan/releases/tag/v0.1.0
- Validation: https://github.com/legacy-ev/awi-scan/blob/main/VALIDATION.md
- Maintainer workflow: https://github.com/legacy-ev/awi-scan/blob/main/MAINTAINER_WORKFLOWS.md
