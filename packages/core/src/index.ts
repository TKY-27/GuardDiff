import { performance } from "node:perf_hooks";

import { PolicyEvaluator } from "./engine/policy-evaluator.js";
import { ScanEngine } from "./engine/scan-engine.js";
import { SuppressionFilter } from "./engine/suppression-filter.js";
import { builtInRules, buildRuleSet } from "./rules/index.js";
import type { FileDiff, Finding, GuardDiffConfig, Rule, RuleCategory, ScanResult, ScanStats, Severity } from "./types/index.js";

export * from "./config/config-parser.js";
export * from "./engine/policy-evaluator.js";
export * from "./engine/scan-engine.js";
export * from "./engine/suppression-filter.js";
export * from "./entropy/shannon.js";
export * from "./ignore/gitignore.js";
export * from "./parser/diff-parser.js";
export * from "./parser/file-diff-factory.js";
export * from "./reporters/json-reporter.js";
export * from "./reporters/markdown-reporter.js";
export * from "./reporters/sarif-reporter.js";
export * from "./reporters/terminal-reporter.js";
export * from "./rules/index.js";
export * from "./types/index.js";

export async function runScan(params: {
  fileDiffs: FileDiff[];
  config: GuardDiffConfig;
  inputType: ScanResult["inputType"];
  ignorePaths?: string[];
  suppressions?: {
    inline?: boolean;
  };
  rules?: Rule[];
  version?: string;
}): Promise<ScanResult> {
  const startedAt = performance.now();
  const rules = params.rules ?? buildRuleSet(params.config);
  const engine = new ScanEngine(rules, params.config);
  const suppressionFilter = new SuppressionFilter(params.config, params.ignorePaths ?? [], params.suppressions);
  const evaluator = new PolicyEvaluator();

  const findings = suppressionFilter.apply(await engine.scan(params.fileDiffs), params.fileDiffs);
  const evaluation = evaluator.evaluate(findings, params.config.policy);
  const durationMs = performance.now() - startedAt;

  return {
    scannedAt: new Date().toISOString(),
    guarddiffVersion: params.version ?? "1.0.0",
    inputType: params.inputType,
    findings,
    stats: buildStats(params.fileDiffs, findings, rules.length, durationMs),
    passed: evaluation.passed,
    policyViolations: evaluation.violations
  };
}

function buildStats(fileDiffs: FileDiff[], findings: Finding[], rulesRun: number, durationMs: number): ScanStats {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  const byCategory: Record<RuleCategory, number> = {
    secret: 0,
    diff: 0,
    config: 0,
    permission: 0,
    mcp: 0
  };

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] += 1;
  }

  return {
    filesScanned: fileDiffs.length,
    linesScanned: fileDiffs.reduce(
      (sum, fileDiff) => sum + fileDiff.hunks.reduce((hunkSum, hunk) => hunkSum + hunk.lines.length, 0),
      0
    ),
    rulesRun: rulesRun * fileDiffs.length,
    totalFindings: findings.length,
    suppressedFindings: findings.filter((finding) => finding.suppressed).length,
    bySeverity,
    byCategory,
    durationMs
  };
}

export { builtInRules };
