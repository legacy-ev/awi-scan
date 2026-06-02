import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { formatReport, scanFile, scanPath, shouldFail, toSarif } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const fixture = (name) => path.join(root, "fixtures", name);

test("detects prompt-to-agent injection in an unsafe Claude workflow", () => {
  const findings = scanFile(fixture("unsafe-claude.yml"), { rootPath: root });
  assert.ok(findings.some((finding) => finding.ruleId === "AWI001" && finding.kind === "P2A"));
  assert.ok(findings.some((finding) => finding.ruleId === "AWI003" && finding.kind === "P2S"));
});

test("detects shell and agent-output risks in an unsafe Gemini workflow", () => {
  const findings = scanFile(fixture("unsafe-gemini.yml"), { rootPath: root });
  assert.ok(findings.some((finding) => finding.ruleId === "AWI001"));
  assert.ok(findings.some((finding) => finding.ruleId === "AWI002"));
  assert.ok(findings.some((finding) => finding.ruleId === "AWI003"));
});

test("does not flag the safe fixture", () => {
  const findings = scanFile(fixture("safe.yml"), { rootPath: root });
  assert.equal(findings.length, 0);
});

test("does not treat actor-only status comments as prompt injection", () => {
  const findings = scanFile(fixture("noisy-status-comment.yml"), { rootPath: root });
  assert.equal(findings.some((finding) => finding.ruleId === "AWI001"), false);
  assert.equal(findings.length, 0);
});

test("downgrades trusted-user gated prompt paths", () => {
  const findings = scanFile(fixture("trusted-gemini.yml"), { rootPath: root });
  const p2a = findings.find((finding) => finding.ruleId === "AWI001");
  const p2s = findings.find((finding) => finding.ruleId === "AWI002");
  assert.ok(p2a);
  assert.equal(p2a.severity, "medium");
  assert.ok(p2s);
  assert.equal(p2s.severity, "medium");
});

test("formats markdown and SARIF reports", () => {
  const result = scanPath(path.join(root, "fixtures"), { rootPath: root });
  const markdown = formatReport(result, "markdown");
  const sarif = toSarif(result);

  assert.match(markdown, /AWI001/);
  assert.equal(sarif.runs[0].tool.driver.name, "awi-scan");
  assert.ok(sarif.runs[0].results.length > 0);
});

test("fail threshold respects severity", () => {
  const result = scanPath(path.join(root, "fixtures"), { rootPath: root });
  assert.equal(shouldFail(result.findings, "critical"), true);
  assert.equal(shouldFail(result.findings, "none"), false);
});
