# Validation Log

## 2026-06-02: 20 Real AI GitHub Actions Repos

Goal: test whether `awi-scan` is useful outside fixtures by scanning public repos that appear to use AI-related GitHub Actions.

Method:

- Candidate discovery used unauthenticated GitHub repository search for Claude, Gemini, OpenAI, ChatGPT, and AI code-review action keywords.
- Repos were shallow-cloned into `.validation-targets/`, which is ignored by git.
- The top 20 repos with at least one AI-looking workflow were scanned with:

```powershell
node .\dist\cli.js <repo-path> --format json --fail-on none
```

### Summary

`awi-scan` is useful as a triage lens: it quickly points at workflows worth manual review. It is not yet precise enough to send findings directly to maintainers without review.

- Repos scanned: 20
- Repos with findings: 6
- Repos with no findings: 14
- Total findings: 49
- Highest-signal finding classes: direct comment/title/body into agent prompt; agent output used by shell or GitHub mutation.
- Main noise classes: job-level `if:` expressions, status comments using `github.actor`, label/branch/title values used in ordinary shell plumbing, and action test workflows that intentionally inspect action outputs.

### Raw Scan Table

| Repo | Workflows | Findings | Critical | High | Medium | Rules |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| sipyourdrink-ltd/bernstein | 76 | 9 | 2 | 6 | 1 | AWI003:2, AWI002:7 |
| anthropics/claude-code-action | 13 | 14 | 0 | 12 | 2 | AWI004:2, AWI003:12 |
| google-github-actions/run-gemini-cli | 11 | 20 | 0 | 5 | 15 | AWI001:12, AWI002:8 |
| ChrisWiles/claude-code-showcase | 4 | 1 | 0 | 0 | 1 | AWI004:1 |
| danny-avila/LibreChat | 27 | 1 | 0 | 1 | 0 | AWI002:1 |
| TechNickAI/AICodeBot | 4 | 0 | 0 | 0 | 0 | none |
| kosukesaigusa/claude-code-action-access-control | 3 | 0 | 0 | 0 | 0 | none |
| albertusreza/pr-pilot | 3 | 0 | 0 | 0 | 0 | none |
| fitomad/github-chatgpt-integration | 2 | 0 | 0 | 0 | 0 | none |
| anthropics/claude-code-security-review | 2 | 0 | 0 | 0 | 0 | none |
| ca-dp/code-butler | 6 | 3 | 0 | 2 | 1 | AWI001:2, AWI004:1 |
| adshao/chatgpt-code-review-action | 2 | 0 | 0 | 0 | 0 | none |
| cawcaw253/ai-review-action | 2 | 0 | 0 | 0 | 0 | none |
| touwaeriol/claude-code-plus | 2 | 0 | 0 | 0 | 0 | none |
| aa0101181514/tw-legal-rag | 2 | 0 | 0 | 0 | 0 | none |
| alokemajumder/Auto-PR-Content-Generator | 1 | 1 | 0 | 1 | 0 | AWI002:1 |
| chenhg5/agencycli | 1 | 0 | 0 | 0 | 0 | none |
| appleboy/codegpt-action | 1 | 0 | 0 | 0 | 0 | none |
| sshnaidm/gpt-code-review-action | 1 | 0 | 0 | 0 | 0 | none |
| TurboKach/ai-reviewer | 1 | 0 | 0 | 0 | 0 | none |

### Manual Signal / Noise Notes

Likely useful findings:

- `google-github-actions/run-gemini-cli`: many `AWI001` hits show issue/PR title/body/comment data feeding Gemini workflows. These are exactly the P2A paths the tool should highlight, although some workflows include author-association gates that should lower severity.
- `ca-dp/code-butler`: `comment_body: ${{ github.event.comment.body }}` reaches an OpenAI-backed action on `issue_comment`; this is a clean P2A-shaped finding.
- `anthropics/claude-code-action`: `AWI004` notices external-user triggers with write permissions in Claude workflows; useful as a configuration smell.

Noisy or needs better modeling:

- `anthropics/claude-code-action`: most `AWI003` hits are action test workflows reading structured outputs or execution files; they are probably intentional tests, not exploitable P2S paths.
- `sipyourdrink-ltd/bernstein`: several findings came from job-level outputs or `if:` expressions rather than actual shell use. Good place to inspect, but too broad for maintainer-facing output.
- `google-github-actions/run-gemini-cli`: some `github.actor` findings are status comments, not agent prompts. Actor mentions should not be treated the same as PR body/comment text.
- `danny-avila/LibreChat` and `alokemajumder/Auto-PR-Content-Generator`: branch/user values in shell workflows are generic GitHub Actions risks, but not always AWI-specific.

### Product Conclusions

`awi-scan` has a real wedge, but the next version should reduce noise before public outreach:

1. Add a trust-gate detector for `author_association` checks, fork checks, and explicit collaborator/member/owner conditions; lower severity or annotate as gated.
2. Split source confidence: PR/issue/comment body should be high-signal; actor, label, and branch name should be lower-signal unless they enter an agent prompt or unquoted shell.
3. Improve block modeling so `if:` conditions and job outputs do not inherit every later `run:` sink in the same broad block.
4. Distinguish agent-action test workflows from production workflows, or lower severity when the workflow name/path starts with `test-`.
5. Add custom sink config for wrapper actions like `ca-dp/code-butler`, `gemini-ai-code-reviewer`, and project-specific AI actions.
6. Add a `--strict` mode for broad security triage and make the default mode narrower and maintainer-friendly.

### Usefulness Verdict

Useful for: security researchers, maintainers auditing AI workflows, and demo-driven launch content.

Not ready for: automatically filing issues against maintainers without manual review.

Best next milestone: implement the noise reductions above, rerun this same 20-repo set, and aim for fewer than 15 total findings while preserving the clearest P2A cases.
