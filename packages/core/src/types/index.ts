export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "likely" | "possible";
export type RuleCategory = "secret" | "diff" | "config" | "permission" | "mcp";

export interface DiffLine {
  type: "add" | "remove" | "context";
  lineNumber: number;
  originalLineNumber: number;
  content: string;
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
  startLine: number;
  endLine: number;
}

export interface FileDiff {
  filePath: string;
  originalPath: string;
  isNew: boolean;
  isDeleted: boolean;
  isRenamed: boolean;
  isBinary: boolean;
  hunks: DiffHunk[];
  rawContent?: string;
}

export interface PolicyConfig {
  failOn: Severity;
}

export interface RuleOverride {
  ruleId: string;
  enabled?: boolean;
  severity?: Severity;
}

export interface CustomRuleConfig {
  id: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  pattern: string;
  message: string;
  explanation: string;
  remediation: string;
}

export interface GuardDiffConfig {
  version: "1";
  policy: PolicyConfig;
  rules?: {
    packs?: string[];
    overrides?: RuleOverride[];
    custom?: CustomRuleConfig[];
  };
  ignore?: {
    paths?: string[];
    rules?: string[];
  };
}

export interface RuleContext {
  fileDiff: FileDiff;
  config: GuardDiffConfig;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: RuleCategory;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  matchedContent?: string;
  message: string;
  explanation: string;
  remediation: string;
  docsUrl?: string;
  suppressed?: boolean;
  suppressReason?: string;
}

export interface Rule {
  id: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  defaultSeverity?: Severity;
  defaultConfidence: Confidence;
  description: string;
  enabled: boolean;
  ruleVersion: string;
  experimental?: boolean;
  detect(ctx: RuleContext): Finding[];
}

export interface ScanStats {
  filesScanned: number;
  linesScanned: number;
  rulesRun: number;
  totalFindings: number;
  suppressedFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<RuleCategory, number>;
  durationMs: number;
}

export interface ScanResult {
  scannedAt: string;
  guarddiffVersion: string;
  inputType: "staged" | "diff" | "path" | "stdin";
  findings: Finding[];
  stats: ScanStats;
  passed: boolean;
  policyViolations: string[];
}
