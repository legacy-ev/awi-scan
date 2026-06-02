#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { formatReport, scanPath, shouldFail } from "./index.js";

try {
  const targetPath = input("path") || ".";
  const format = input("format") || "markdown";
  const output = input("output");
  const failOn = input("fail-on") || "high";

  const result = scanPath(targetPath, { rootPath: process.cwd() });
  const report = formatReport(result, format);

  if (output) {
    const outputPath = path.resolve(output);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, report);
    process.stdout.write(`awi-scan report written to ${output}\n`);
  } else {
    process.stdout.write(report);
  }

  writeOutput("findings", String(result.findings.length));
  writeOutput("report", report);

  if (shouldFail(result.findings, failOn)) {
    process.stderr.write(`awi-scan found findings at or above '${failOn}'.\n`);
    process.exit(1);
  }
} catch (error) {
  process.stderr.write(`awi-scan action failed: ${(error as Error).message}\n`);
  process.exit(2);
}

function input(name: string): string {
  return process.env[`INPUT_${name.toUpperCase().replaceAll("-", "_")}`] || "";
}

function writeOutput(name: string, value: string): void {
  if (!process.env.GITHUB_OUTPUT) return;
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}<<AWI_SCAN_EOF\n${value}\nAWI_SCAN_EOF\n`);
}
