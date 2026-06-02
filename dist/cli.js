#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { formatReport, scanPath, shouldFail, VERSION } from "./index.js";
const args = process.argv.slice(2);
try {
    const options = parseArgs(args);
    if (options.help) {
        process.stdout.write(helpText());
        process.exit(0);
    }
    if (options.version) {
        process.stdout.write(`${VERSION}\n`);
        process.exit(0);
    }
    const result = scanPath(options.path, { rootPath: process.cwd() });
    const report = formatReport(result, options.format);
    if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.mkdirSync(path.dirname(outputPath), { recursive: true });
        fs.writeFileSync(outputPath, report);
    }
    else {
        process.stdout.write(report);
    }
    process.exit(shouldFail(result.findings, options.failOn) ? 1 : 0);
}
catch (error) {
    process.stderr.write(`awi-scan: ${error.message}\n`);
    process.exit(2);
}
function parseArgs(args) {
    const options = {
        path: ".",
        format: "terminal",
        failOn: "high",
        output: ""
    };
    for (let index = 0; index < args.length; index += 1) {
        const arg = args[index];
        if (arg === "--help" || arg === "-h")
            options.help = true;
        else if (arg === "--version" || arg === "-v")
            options.version = true;
        else if (arg === "--format")
            options.format = takeValue(args, ++index, "--format");
        else if (arg.startsWith("--format="))
            options.format = arg.slice("--format=".length);
        else if (arg === "--output" || arg === "-o")
            options.output = takeValue(args, ++index, "--output");
        else if (arg.startsWith("--output="))
            options.output = arg.slice("--output=".length);
        else if (arg === "--fail-on")
            options.failOn = takeValue(args, ++index, "--fail-on");
        else if (arg.startsWith("--fail-on="))
            options.failOn = arg.slice("--fail-on=".length);
        else if (arg.startsWith("-"))
            throw new Error(`Unknown option: ${arg}`);
        else
            options.path = arg;
    }
    if (!["terminal", "markdown", "json", "sarif"].includes(options.format)) {
        throw new Error("--format must be terminal, markdown, json, or sarif");
    }
    return options;
}
function takeValue(args, index, flag) {
    const value = args[index];
    if (!value || value.startsWith("-"))
        throw new Error(`${flag} needs a value`);
    return value;
}
function helpText() {
    return `awi-scan ${VERSION}

Scan AI-powered GitHub Actions for prompt-to-agent injection risks.

Usage:
  awi-scan [path] [--format terminal|markdown|json|sarif] [--output file] [--fail-on high]

Examples:
  npx awi-scan
  npx awi-scan . --format markdown --output awi-report.md
  npx awi-scan . --format sarif --output awi.sarif --fail-on medium

`;
}
