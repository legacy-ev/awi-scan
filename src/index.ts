import fs from "node:fs";
import path from "node:path";

export const VERSION = "0.1.0";

export type Severity = "low" | "medium" | "high" | "critical";
export type FindingKind = "P2A" | "P2S" | "CONFIG";

export interface Finding {
  ruleId: string;
  kind: FindingKind;
  severity: Severity;
  title: string;
  filePath: string;
  relativePath: string;
  line: number;
  evidence: string;
  source: string;
  sink: string;
  why: string;
  fix: string;
}

export interface ScanResult {
  tool: "awi-scan";
  version: string;
  targetPath: string;
  scannedFiles: string[];
  findings: Finding[];
}

export interface ScanOptions {
  rootPath?: string;
}

type SourcePattern = {
  id: string;
  label: string;
  pattern: RegExp;
  confidence: "high" | "medium" | "low";
};

type StepBlock = {
  startLine: number;
  endLine: number;
  text: string;
};

const WORKFLOW_EXTENSIONS = new Set([".yml", ".yaml"]);
const SEVERITY_ORDER: Record<string, number> = {
  none: 99,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const UNTRUSTED_SOURCES: SourcePattern[] = [
  { id: "pr-title", label: "pull request title", pattern: /github\.event\.pull_request\.title|github\.event\.pull_request\[['"]title['"]\]/i, confidence: "medium" },
  { id: "pr-body", label: "pull request body", pattern: /github\.event\.pull_request\.body|github\.event\.pull_request\[['"]body['"]\]/i, confidence: "high" },
  { id: "pr-head-ref", label: "pull request branch name", pattern: /github\.event\.pull_request\.head\.ref|github\.head_ref/i, confidence: "low" },
  { id: "issue-title", label: "issue title", pattern: /github\.event\.issue\.title|github\.event\.issue\[['"]title['"]\]/i, confidence: "medium" },
  { id: "issue-body", label: "issue body", pattern: /github\.event\.issue\.body|github\.event\.issue\[['"]body['"]\]/i, confidence: "high" },
  { id: "comment-body", label: "issue or PR comment body", pattern: /github\.event\.comment\.body|github\.event\.comment\[['"]body['"]\]/i, confidence: "high" },
  { id: "review-body", label: "review body", pattern: /github\.event\.review\.body|github\.event\.review\[['"]body['"]\]/i, confidence: "high" },
  { id: "label-name", label: "label name", pattern: /github\.event\.label\.name/i, confidence: "low" },
  { id: "sender-login", label: "sender username", pattern: /github\.event\.sender\.login|github\.actor/i, confidence: "low" }
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
const TRUST_GATE = /author_association.*\b(OWNER|MEMBER|COLLABORATOR)\b|\b(OWNER|MEMBER|COLLABORATOR)\b.*author_association|head\.repo\.fork\s*==\s*false|github\.event\.sender\.type\s*==\s*['"]User['"]/i;

export function scanPath(targetPath = ".", options: ScanOptions = {}): ScanResult {
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

export function scanFile(filePath: string, options: ScanOptions = {}): Finding[] {
  const absolutePath = path.resolve(filePath);
  const content = fs.readFileSync(absolutePath, "utf8");
  return analyzeWorkflow(content, {
    filePath: absolutePath,
    rootPath: options.rootPath ? path.resolve(options.rootPath) : process.cwd()
  });
}

export function analyzeWorkflow(content: string, context: { filePath?: string; rootPath?: string } = {}): Finding[] {
  const filePath = context.filePath || "<memory>";
  const rootPath = context.rootPath || process.cwd();
  const relativePath = path.relative(rootPath, filePath) || filePath;
  const lines = content.split(/\r?\n/);
  const blocks = collectStepBlocks(lines);
  const findings: Finding[] = [];
  const agentBlocks = blocks.filter((block) => hasAgentSink(block.text));
  const agentStepIds = agentBlocks.map(extractStepId).filter(Boolean) as string[];
  const hasDangerousTrigger = DANGEROUS_TRIGGERS.test(content);
  const hasWritePermissions = WRITE_PERMISSIONS.test(content);
  const hasTrustedGate = TRUST_GATE.test(content);
  const testWorkflow = isTestWorkflow(relativePath);

  for (const block of blocks) {
    const source = findUntrustedSource(block.text);
    const sourceLine = source ? findLineInBlock(block, source.pattern) : block.startLine;

    if (source && hasAgentSink(block.text) && isPromptLikeUse(block.text, source)) {
      const severity = downgradeForTrustGate(
        p2aSeverity(source, hasDangerousTrigger, hasWritePermissions),
        hasTrustedGate
      );
      findings.push(makeFinding({
        ruleId: "AWI001",
        kind: "P2A",
        severity,
        title: "Untrusted GitHub event text reaches an AI-agent prompt",
        filePath,
        relativePath,
        line: sourceLine,
        evidence: trimEvidence(lineAt(lines, sourceLine)),
        source: source.label,
        sink: firstAgentSink(block.text),
        why: hasTrustedGate ? "This workflow appears to gate requests to trusted users, but trusted-user text can still become AI-agent instructions if it is interpolated directly." : "Attackers can write issues, comments, PR bodies, or branch names that are later treated as instructions by an AI agent.",
        fix: "Do not interpolate this value directly into the prompt. Save it as quoted data, tell the agent it is untrusted user content, and gate privileged follow-up actions to trusted actors."
      }));
    }

    if (source && hasScriptSink(block.text)) {
      if (source.id === "sender-login" && !MUTATING_GH_COMMAND.test(block.text)) continue;
      if (source.id === "sender-login" && isStatusCommentOnly(block.text)) continue;
      findings.push(makeFinding({
        ruleId: "AWI002",
        kind: "P2S",
        severity: downgradeForTrustGate(p2sSeverity(source, block.text, hasWritePermissions), hasTrustedGate),
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
      if (isConditionOnlyReference(lineAt(lines, line))) continue;
      findings.push(makeFinding({
        ruleId: "AWI003",
        kind: "P2S",
        severity: testWorkflow ? "medium" : MUTATING_GH_COMMAND.test(block.text) || hasWritePermissions ? "critical" : "high",
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

export function formatReport(result: ScanResult, format = "terminal"): string {
  if (format === "json") return `${JSON.stringify(result, null, 2)}\n`;
  if (format === "markdown") return formatMarkdown(result);
  if (format === "sarif") return `${JSON.stringify(toSarif(result), null, 2)}\n`;
  return formatTerminal(result);
}

export function shouldFail(findings: Finding[], threshold = "high"): boolean {
  const normalized = String(threshold || "high").toLowerCase();
  if (normalized === "none") return false;
  const min = SEVERITY_ORDER[normalized] || SEVERITY_ORDER.high;
  return findings.some((finding) => (SEVERITY_ORDER[finding.severity] || 0) >= min);
}

export function toSarif(result: ScanResult): object {
  const rules = new Map<string, object>();
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
            informationUri: "https://github.com/legacy-ev/awi-scan",
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

function findWorkflowFiles(targetPath: string): string[] {
  if (!fs.existsSync(targetPath)) throw new Error(`Path does not exist: ${targetPath}`);
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) return WORKFLOW_EXTENSIONS.has(path.extname(targetPath).toLowerCase()) ? [targetPath] : [];

  const workflowRoot = path.join(targetPath, ".github", "workflows");
  if (fs.existsSync(workflowRoot) && fs.statSync(workflowRoot).isDirectory()) return walk(workflowRoot).filter(isWorkflowFile);

  return walk(targetPath).filter((file) => {
    if (!isWorkflowFile(file)) return false;
    const normalized = file.replaceAll("\\", "/");
    return normalized.includes("/.github/workflows/") || normalized.includes("/fixtures/");
  });
}

function walk(directory: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if ([".git", "node_modules", "dist", "coverage"].includes(entry.name)) continue;
      files.push(...walk(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function isWorkflowFile(filePath: string): boolean {
  return WORKFLOW_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function collectStepBlocks(lines: string[]): StepBlock[] {
  const blocks: StepBlock[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const startMatch = lines[index].match(/^(\s*)-\s+(name:|uses:|run:|id:)/);
    if (!startMatch) continue;
    const indent = startMatch[1].length;
    let end = index + 1;
    while (end < lines.length) {
      const nextStep = lines[end].match(/^(\s*)-\s+(name:|uses:|run:|id:)/);
      if (nextStep && nextStep[1].length === indent) break;
      end += 1;
    }
    blocks.push({ startLine: index + 1, endLine: end, text: lines.slice(index, end).join("\n") });
    index = end - 1;
  }
  return blocks;
}

function hasAgentSink(text: string): boolean {
  return AGENT_PATTERNS.some((pattern) => pattern.test(text));
}

function firstAgentSink(text: string): string {
  const line = text.split(/\r?\n/).find((candidate) => hasAgentSink(candidate));
  return line ? trimEvidence(line) : "AI-agent prompt/action";
}

function hasScriptSink(text: string): boolean {
  return SCRIPT_SINKS.test(text);
}

function findUntrustedSource(text: string): SourcePattern | undefined {
  return UNTRUSTED_SOURCES.find((source) => source.pattern.test(text));
}

function isPromptLikeUse(text: string, source: SourcePattern): boolean {
  if (source.id === "sender-login") return false;
  if (source.confidence === "low" && !PROMPT_KEYS.test(text)) return false;
  return PROMPT_KEYS.test(text) || text.includes("${{");
}

function p2aSeverity(source: SourcePattern, hasDangerousTrigger: boolean, hasWritePermissions: boolean): Severity {
  if (source.confidence === "low") return "low";
  if (source.confidence === "medium") return hasDangerousTrigger || hasWritePermissions ? "medium" : "low";
  return hasDangerousTrigger || hasWritePermissions ? "high" : "medium";
}

function p2sSeverity(source: SourcePattern, text: string, hasWritePermissions: boolean): Severity {
  if (source.confidence === "low") return MUTATING_GH_COMMAND.test(text) || hasWritePermissions ? "medium" : "low";
  return MUTATING_GH_COMMAND.test(text) || hasWritePermissions ? "high" : "medium";
}

function downgradeForTrustGate(severity: Severity, hasTrustedGate: boolean): Severity {
  if (!hasTrustedGate) return severity;
  if (severity === "critical") return "high";
  if (severity === "high") return "medium";
  if (severity === "medium") return "low";
  return severity;
}

function isConditionOnlyReference(line: string): boolean {
  return /^\s*if:\s/.test(line);
}

function isStatusCommentOnly(text: string): boolean {
  return /\bgh\s+issue\s+comment\b[\s\S]*github\.actor/i.test(text) && !/\b(eval|bash|sh|pwsh|powershell|gh\s+(api|pr|repo|workflow|release))\b/i.test(text);
}

function isTestWorkflow(relativePath: string): boolean {
  return /(^|[\\/])test[-_].*\.ya?ml$|(^|[\\/]).*[-_]test(s)?\.ya?ml$/i.test(relativePath);
}

function findAgentOutputReference(text: string, agentStepIds: string[]): { stepId: string; pattern: RegExp } | null {
  for (const stepId of agentStepIds) {
    const escaped = escapeRegex(stepId);
    const pattern = new RegExp(`steps\\.${escaped}\\.outputs|steps\\[['"]${escaped}['"]\\]\\.outputs`, "i");
    if (pattern.test(text)) return { stepId, pattern };
  }
  return null;
}

function extractStepId(block: StepBlock): string | null {
  const match = block.text.match(/^\s*(?:-\s*)?id:\s*([A-Za-z0-9_-]+)/m);
  return match ? match[1] : null;
}

function findLineInBlock(block: StepBlock, pattern: RegExp): number {
  const lines = block.text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index])) return block.startLine + index;
  }
  return block.startLine;
}

function findFirstLine(lines: string[], pattern: RegExp): number {
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index])) return index + 1;
  }
  return 1;
}

function findDangerousTriggerLine(lines: string[]): number {
  return findFirstLine(lines, /\bpull_request_target\b|\bissue_comment\b|\bissues:\s*$|\bissues:\s*[\[{]|\bpull_request_review\b/i);
}

function lineAt(lines: string[], lineNumber: number): string {
  return lines[Math.max(0, lineNumber - 1)] || "";
}

function makeFinding(input: Finding): Finding {
  return input;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.relativePath}:${finding.line}:${finding.source}:${finding.sink}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatTerminal(result: ScanResult): string {
  if (result.findings.length === 0) return `awi-scan: no AWI findings in ${result.scannedFiles.length} workflow file(s).\n`;
  const lines = [`awi-scan found ${result.findings.length} finding(s) in ${result.scannedFiles.length} workflow file(s).`, ""];
  for (const finding of result.findings) {
    lines.push(
      `[${finding.severity.toUpperCase()}] ${finding.ruleId} ${finding.kind}: ${finding.title}`,
      `  at ${finding.relativePath}:${finding.line}`,
      `  source: ${finding.source}`,
      `  sink: ${finding.sink}`,
      `  why: ${finding.why}`,
      `  fix: ${finding.fix}`,
      finding.evidence ? `  evidence: ${finding.evidence}` : "",
      ""
    );
  }
  return `${lines.filter((line) => line !== "").join("\n")}\n`;
}

function formatMarkdown(result: ScanResult): string {
  if (result.findings.length === 0) return `## awi-scan\n\nNo Agentic Workflow Injection findings in ${result.scannedFiles.length} workflow file(s).\n`;
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
    lines.push(
      `### ${finding.ruleId} ${finding.kind}: ${finding.title}`,
      "",
      `- Location: \`${finding.relativePath.replaceAll("\\", "/")}:${finding.line}\``,
      `- Source: ${finding.source}`,
      `- Sink: ${finding.sink}`,
      `- Why this matters: ${finding.why}`,
      `- Safer rewrite: ${finding.fix}`,
      finding.evidence ? `- Evidence: \`${finding.evidence.replaceAll("`", "'")}\`` : "",
      ""
    );
  }
  return `${lines.filter((line) => line !== "").join("\n")}\n`;
}

function trimEvidence(value: string): string {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, 220);
}

function escapeMarkdownCell(value: unknown): string {
  return String(value).replaceAll("|", "\\|");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
