import fs from "node:fs";
import path from "node:path";
export const VERSION = "0.1.0";
const WORKFLOW_EXTENSIONS = new Set([".yml", ".yaml"]);
const SEVERITY_ORDER = {
    none: 99,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
};
const UNTRUSTED_SOURCES = [
    { id: "pr-title", label: "pull request title", pattern: /github\.event\.pull_request\.title|github\.event\.pull_request\[['"]title['"]\]/i },
    { id: "pr-body", label: "pull request body", pattern: /github\.event\.pull_request\.body|github\.event\.pull_request\[['"]body['"]\]/i },
    { id: "pr-head-ref", label: "pull request branch name", pattern: /github\.event\.pull_request\.head\.ref|github\.head_ref/i },
    { id: "issue-title", label: "issue title", pattern: /github\.event\.issue\.title|github\.event\.issue\[['"]title['"]\]/i },
    { id: "issue-body", label: "issue body", pattern: /github\.event\.issue\.body|github\.event\.issue\[['"]body['"]\]/i },
    { id: "comment-body", label: "issue or PR comment body", pattern: /github\.event\.comment\.body|github\.event\.comment\[['"]body['"]\]/i },
    { id: "review-body", label: "review body", pattern: /github\.event\.review\.body|github\.event\.review\[['"]body['"]\]/i },
    { id: "label-name", label: "label name", pattern: /github\.event\.label\.name/i },
    { id: "sender-login", label: "sender username", pattern: /github\.event\.sender\.login|github\.actor/i }
];
const AGENT_PATTERNS = [
    /anthropic|claude|claude-code/i,
    /google.*gemini|gemini-cli|gemini/i,
    /openai|codex|gpt-|chatgpt/i,
    /copilot/i,
    /\bllm\b|ai-agent|agentic|autonomous agent/i
];
const PROMPT_KEYS = /\b(prompt|instruction|instructions|message|messages|query|input|task|system_prompt|user_prompt)\b/i;
const SCRIPT_SINKS = /\brun:\s|actions\/github-script|github-script|\bgh\s+(issue|pr|api|workflow|repo|release)\b|curl\s+.*api\.github\.com/i;
const MUTATING_GH_COMMAND = /\bgh\s+(issue|pr|api|workflow|repo|release)\b|curl\s+.*api\.github\.com/i;
const DANGEROUS_TRIGGERS = /\bpull_request_target\b|\bissue_comment\b|\bissues:\s*[\s\S]*\bopened\b|\bpull_request_review\b/i;
const WRITE_PERMISSIONS = /\bpermissions:\s*write-all\b|\b(contents|issues|pull-requests|actions|checks|statuses|deployments|packages|repository-projects):\s*write\b/i;
export function scanPath(targetPath = ".", options = {}) {
    const absoluteTarget = path.resolve(targetPath);
    const files = findWorkflowFiles(absoluteTarget);
    const findings = files.flatMap((file) => scanFile(file, options));
    return {
        tool: "awi-scan",
        version: VERSION,
        targetPath: absoluteTarget,
        scannedFiles: files,
        findings
    };
}
export function scanFile(filePath, options = {}) {
    const absolutePath = path.resolve(filePath);
    const content = fs.readFileSync(absolutePath, "utf8");
    return analyzeWorkflow(content, {
        filePath: absolutePath,
        rootPath: options.rootPath ? path.resolve(options.rootPath) : process.cwd()
    });
}
export function analyzeWorkflow(content, context = {}) {
    const filePath = context.filePath || "<memory>";
    const rootPath = context.rootPath || process.cwd();
    const relativePath = path.relative(rootPath, filePath) || filePath;
    const lines = content.split(/\r?\n/);
    const blocks = collectStepBlocks(lines);
    const findings = [];
    const agentBlocks = blocks.filter((block) => hasAgentSink(block.text));
    const agentStepIds = agentBlocks.map(extractStepId).filter(Boolean);
    const hasDangerousTrigger = DANGEROUS_TRIGGERS.test(content);
    const hasWritePermissions = WRITE_PERMISSIONS.test(content);
    for (const block of blocks) {
        const source = findUntrustedSource(block.text);
        const sourceLine = source ? findLineInBlock(block, source.pattern) : block.startLine;
        if (source && hasAgentSink(block.text) && (PROMPT_KEYS.test(block.text) || block.text.includes("${{"))) {
            findings.push(makeFinding({
                ruleId: "AWI001",
                kind: "P2A",
                severity: hasDangerousTrigger || hasWritePermissions ? "high" : "medium",
                title: "Untrusted GitHub event text reaches an AI-agent prompt",
                filePath,
                relativePath,
                line: sourceLine,
                evidence: trimEvidence(lineAt(lines, sourceLine)),
                source: source.label,
                sink: firstAgentSink(block.text),
                why: "Attackers can write issues, comments, PR bodies, or branch names that are later treated as instructions by an AI agent.",
                fix: "Do not interpolate this value directly into the prompt. Save it as quoted data, tell the agent it is untrusted user content, and gate privileged follow-up actions to trusted actors."
            }));
        }
        if (source && hasScriptSink(block.text)) {
            findings.push(makeFinding({
                ruleId: "AWI002",
                kind: "P2S",
                severity: MUTATING_GH_COMMAND.test(block.text) || hasWritePermissions ? "high" : "medium",
                title: "Untrusted GitHub event text reaches a script or GitHub mutation step",
                filePath,
                relativePath,
                line: sourceLine,
                evidence: trimEvidence(lineAt(lines, sourceLine)),
                source: source.label,
                sink: "script/action execution",
                why: "Shell steps and GitHub API commands can turn untrusted event text into command injection, unexpected API calls, or repository changes.",
                fix: "Pass event text through files or environment variables with strict quoting, avoid eval-like shell expansion, and require maintainer approval before write-token commands."
            }));
        }
        const agentOutputRef = findAgentOutputReference(block.text, agentStepIds);
        if (agentOutputRef && hasScriptSink(block.text)) {
            const line = findLineInBlock(block, agentOutputRef.pattern);
            findings.push(makeFinding({
                ruleId: "AWI003",
                kind: "P2S",
                severity: MUTATING_GH_COMMAND.test(block.text) || hasWritePermissions ? "critical" : "high",
                title: "AI-agent output reaches a script or GitHub mutation step",
                filePath,
                relativePath,
                line,
                evidence: trimEvidence(lineAt(lines, line)),
                source: `AI-agent step output (${agentOutputRef.stepId})`,
                sink: "script/action execution",
                why: "If an attacker can steer the agent prompt, the agent output becomes attacker-influenced data that may drive shell commands or GitHub API mutations.",
                fix: "Treat agent output as untrusted. Validate it against a strict schema, require human approval for mutations, and avoid feeding it directly into shell, gh, or github-script steps."
            }));
        }
    }
    if (agentBlocks.length > 0 && hasDangerousTrigger && hasWritePermissions) {
        const line = findDangerousTriggerLine(lines);
        findings.push(makeFinding({
            ruleId: "AWI004",
            kind: "CONFIG",
            severity: "medium",
            title: "AI workflow combines external-user triggers with write permissions",
            filePath,
            relativePath,
            line,
            evidence: trimEvidence(lineAt(lines, line)),
            source: "external GitHub event trigger",
            sink: "write-token workflow",
            why: "External-user triggers plus repository write permissions make prompt-to-agent findings more likely to become repository-changing incidents.",
            fix: "Prefer pull_request over pull_request_target for untrusted code, reduce permissions to read-only by default, and grant write scopes only in reviewed follow-up jobs."
        }));
    }
    return dedupeFindings(findings);
}
export function formatReport(result, format = "terminal") {
    if (format === "json")
        return `${JSON.stringify(result, null, 2)}\n`;
    if (format === "markdown")
        return formatMarkdown(result);
    if (format === "sarif")
        return `${JSON.stringify(toSarif(result), null, 2)}\n`;
    return formatTerminal(result);
}
export function shouldFail(findings, threshold = "high") {
    const normalized = String(threshold || "high").toLowerCase();
    if (normalized === "none")
        return false;
    const min = SEVERITY_ORDER[normalized] || SEVERITY_ORDER.high;
    return findings.some((finding) => (SEVERITY_ORDER[finding.severity] || 0) >= min);
}
export function toSarif(result) {
    const rules = new Map();
    for (const finding of result.findings) {
        rules.set(finding.ruleId, {
            id: finding.ruleId,
            name: finding.kind,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.why },
            help: { text: finding.fix }
        });
    }
    return {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
            {
                tool: {
                    driver: {
                        name: "awi-scan",
                        informationUri: "https://github.com/your-org/awi-scan",
                        version: VERSION,
                        rules: [...rules.values()]
                    }
                },
                results: result.findings.map((finding) => ({
                    ruleId: finding.ruleId,
                    level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "note",
                    message: { text: `${finding.title}. ${finding.fix}` },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: { uri: finding.relativePath.replaceAll("\\", "/") },
                                region: { startLine: finding.line || 1 }
                            }
                        }
                    ],
                    properties: {
                        kind: finding.kind,
                        severity: finding.severity,
                        source: finding.source,
                        sink: finding.sink
                    }
                }))
            }
        ]
    };
}
function findWorkflowFiles(targetPath) {
    if (!fs.existsSync(targetPath))
        throw new Error(`Path does not exist: ${targetPath}`);
    const stat = fs.statSync(targetPath);
    if (stat.isFile())
        return WORKFLOW_EXTENSIONS.has(path.extname(targetPath).toLowerCase()) ? [targetPath] : [];
    const workflowRoot = path.join(targetPath, ".github", "workflows");
    if (fs.existsSync(workflowRoot) && fs.statSync(workflowRoot).isDirectory())
        return walk(workflowRoot).filter(isWorkflowFile);
    return walk(targetPath).filter((file) => {
        if (!isWorkflowFile(file))
            return false;
        const normalized = file.replaceAll("\\", "/");
        return normalized.includes("/.github/workflows/") || normalized.includes("/fixtures/");
    });
}
function walk(directory) {
    const files = [];
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
            if ([".git", "node_modules", "dist", "coverage"].includes(entry.name))
                continue;
            files.push(...walk(fullPath));
        }
        else {
            files.push(fullPath);
        }
    }
    return files;
}
function isWorkflowFile(filePath) {
    return WORKFLOW_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}
function collectStepBlocks(lines) {
    const blocks = [];
    for (let index = 0; index < lines.length; index += 1) {
        const startMatch = lines[index].match(/^(\s*)-\s+(name:|uses:|run:|id:)/);
        if (!startMatch)
            continue;
        const indent = startMatch[1].length;
        let end = index + 1;
        while (end < lines.length) {
            const nextStep = lines[end].match(/^(\s*)-\s+(name:|uses:|run:|id:)/);
            if (nextStep && nextStep[1].length === indent)
                break;
            end += 1;
        }
        blocks.push({ startLine: index + 1, endLine: end, text: lines.slice(index, end).join("\n") });
        index = end - 1;
    }
    return blocks;
}
function hasAgentSink(text) {
    return AGENT_PATTERNS.some((pattern) => pattern.test(text));
}
function firstAgentSink(text) {
    const line = text.split(/\r?\n/).find((candidate) => hasAgentSink(candidate));
    return line ? trimEvidence(line) : "AI-agent prompt/action";
}
function hasScriptSink(text) {
    return SCRIPT_SINKS.test(text);
}
function findUntrustedSource(text) {
    return UNTRUSTED_SOURCES.find((source) => source.pattern.test(text));
}
function findAgentOutputReference(text, agentStepIds) {
    for (const stepId of agentStepIds) {
        const escaped = escapeRegex(stepId);
        const pattern = new RegExp(`steps\\.${escaped}\\.outputs|steps\\[['"]${escaped}['"]\\]\\.outputs`, "i");
        if (pattern.test(text))
            return { stepId, pattern };
    }
    return null;
}
function extractStepId(block) {
    const match = block.text.match(/^\s*(?:-\s*)?id:\s*([A-Za-z0-9_-]+)/m);
    return match ? match[1] : null;
}
function findLineInBlock(block, pattern) {
    const lines = block.text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
        if (pattern.test(lines[index]))
            return block.startLine + index;
    }
    return block.startLine;
}
function findFirstLine(lines, pattern) {
    for (let index = 0; index < lines.length; index += 1) {
        if (pattern.test(lines[index]))
            return index + 1;
    }
    return 1;
}
function findDangerousTriggerLine(lines) {
    return findFirstLine(lines, /\bpull_request_target\b|\bissue_comment\b|\bissues:\s*$|\bissues:\s*[\[{]|\bpull_request_review\b/i);
}
function lineAt(lines, lineNumber) {
    return lines[Math.max(0, lineNumber - 1)] || "";
}
function makeFinding(input) {
    return input;
}
function dedupeFindings(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
        const key = `${finding.ruleId}:${finding.relativePath}:${finding.line}:${finding.source}:${finding.sink}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
function formatTerminal(result) {
    if (result.findings.length === 0)
        return `awi-scan: no AWI findings in ${result.scannedFiles.length} workflow file(s).\n`;
    const lines = [`awi-scan found ${result.findings.length} finding(s) in ${result.scannedFiles.length} workflow file(s).`, ""];
    for (const finding of result.findings) {
        lines.push(`[${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.kind}: ${finding.title}`, `  at ${finding.relativePath}:${finding.line}`, `  source: ${finding.source}`, `  sink: ${finding.sink}`, `  why: ${finding.why}`, `  fix: ${finding.fix}`, finding.evidence ? `  evidence: ${finding.evidence}` : "", "");
    }
    return `${lines.filter((line) => line !== "").join("\n")}\n`;
}
function formatMarkdown(result) {
    if (result.findings.length === 0)
        return `## awi-scan\n\nNo Agentic Workflow Injection findings in ${result.scannedFiles.length} workflow file(s).\n`;
    const lines = [
        "## awi-scan",
        "",
        `Found ${result.findings.length} Agentic Workflow Injection finding(s) in ${result.scannedFiles.length} workflow file(s).`,
        "",
        "| Severity | Rule | Type | Location | Finding |",
        "| --- | --- | --- | --- | --- |",
        ...result.findings.map((finding) => `| ${[finding.severity, finding.ruleId, finding.kind, `${finding.relativePath.replaceAll("\\", "/")}:${finding.line}`, finding.title].map(escapeMarkdownCell).join(" | ")} |`),
        ""
    ];
    for (const finding of result.findings) {
        lines.push(`### ${finding.ruleId} ${finding.kind}: ${finding.title}`, "", `- Location: \`${finding.relativePath.replaceAll("\\", "/")}:${finding.line}\``, `- Source: ${finding.source}`, `- Sink: ${finding.sink}`, `- Why this matters: ${finding.why}`, `- Safer rewrite: ${finding.fix}`, finding.evidence ? `- Evidence: \`${finding.evidence.replaceAll("`", "'")}\`` : "", "");
    }
    return `${lines.filter((line) => line !== "").join("\n")}\n`;
}
function trimEvidence(value) {
    return String(value || "").trim().replace(/\s+/g, " ").slice(0, 220);
}
function escapeMarkdownCell(value) {
    return String(value).replaceAll("|", "\\|");
}
function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
