import { compareSeverity } from "../engine/policy-evaluator.js";
import type { ScanResult } from "../types/index.js";

export class MarkdownReporter {
  render(result: ScanResult): string {
    const findings = result.findings
      .filter((finding) => !finding.suppressed)
      .sort((left, right) => compareSeverity(right.severity, left.severity));
    const lines = [
      "# GuardDiff Report",
      "",
      `Policy: **${result.passed ? "PASS" : "FAIL"}**`,
      "",
      `- Active findings: ${findings.length}`,
      `- Critical: ${findings.filter((finding) => finding.severity === "critical").length}`,
      `- High: ${findings.filter((finding) => finding.severity === "high").length}`,
      `- Suppressed: ${result.stats.suppressedFindings}`,
      ""
    ];

    if (findings.length === 0) {
      lines.push("No active findings.");
      return lines.join("\n");
    }

    lines.push("## Findings", "");
    for (const finding of findings) {
      lines.push(`- \`${finding.severity.toUpperCase()}\` \`${finding.ruleId}\` \`${finding.filePath}:${finding.lineStart}\``);
      lines.push(`  ${finding.message}`);
      if (finding.matchedContent) {
        lines.push(`  Match: \`${finding.matchedContent}\``);
      }
    }

    return lines.join("\n");
  }
}
