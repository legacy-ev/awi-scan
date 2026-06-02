export declare const VERSION = "0.1.0";
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
export declare function scanPath(targetPath?: string, options?: ScanOptions): ScanResult;
export declare function scanFile(filePath: string, options?: ScanOptions): Finding[];
export declare function analyzeWorkflow(content: string, context?: {
    filePath?: string;
    rootPath?: string;
}): Finding[];
export declare function formatReport(result: ScanResult, format?: string): string;
export declare function shouldFail(findings: Finding[], threshold?: string): boolean;
export declare function toSarif(result: ScanResult): object;
