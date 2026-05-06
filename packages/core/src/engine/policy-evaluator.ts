import type { Finding, PolicyConfig, Severity } from "../types/index.js";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export class PolicyEvaluator {
  evaluate(findings: Finding[], policy: PolicyConfig): { passed: boolean; violations: string[] } {
    const activeFindings = findings.filter((finding) => !finding.suppressed);
    const failIndex = SEVERITY_ORDER.indexOf(policy.failOn);

    const violations = activeFindings
      .filter((finding) => SEVERITY_ORDER.indexOf(finding.severity) >= failIndex)
      .map(
        (finding) =>
          `[${finding.severity.toUpperCase()}] ${finding.ruleId}: ${finding.message} (${finding.filePath}:${finding.lineStart})`
      );

    return {
      passed: violations.length === 0,
      violations
    };
  }
}

export function compareSeverity(left: Severity, right: Severity): number {
  return SEVERITY_ORDER.indexOf(left) - SEVERITY_ORDER.indexOf(right);
}
