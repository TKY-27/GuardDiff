import { isPathIgnored } from "../ignore/gitignore.js";
import type { FileDiff, Finding, GuardDiffConfig } from "../types/index.js";

const SUPPRESSION_PATTERN = /guarddiff-ignore:\s*([\w\/,\-\s]+)/;

export class SuppressionFilter {
  constructor(
    private readonly config: GuardDiffConfig,
    private readonly ignorePaths: string[],
    private readonly options: { inline?: boolean } = {}
  ) {}

  apply(findings: Finding[], fileDiffs: FileDiff[]): Finding[] {
    return findings.map((finding) => {
      const inlineReason = this.options.inline === false ? null : this.checkInlineSuppression(finding, fileDiffs);
      if (inlineReason) {
        return { ...finding, suppressed: true, suppressReason: inlineReason };
      }

      if (this.config.ignore?.rules?.includes(finding.ruleId)) {
        return { ...finding, suppressed: true, suppressReason: "rule_ignored" };
      }

      if (this.isConfigPathIgnored(finding.filePath)) {
        return { ...finding, suppressed: true, suppressReason: "config_path_ignored" };
      }

      if (this.isIgnoreFilePathIgnored(finding.filePath)) {
        return { ...finding, suppressed: true, suppressReason: "ignore_file_path_ignored" };
      }

      return finding;
    });
  }

  private isConfigPathIgnored(filePath: string): boolean {
    return matchesAnyIgnorePattern(filePath, this.config.ignore?.paths ?? []);
  }

  private isIgnoreFilePathIgnored(filePath: string): boolean {
    return matchesAnyIgnorePattern(filePath, this.ignorePaths);
  }

  private checkInlineSuppression(finding: Finding, fileDiffs: FileDiff[]): string | null {
    const fileDiff = fileDiffs.find((candidate) => candidate.filePath === finding.filePath);
    if (!fileDiff) {
      return null;
    }

    for (const hunk of fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        if (line.lineNumber !== finding.lineStart) {
          continue;
        }

        const match = line.content.match(SUPPRESSION_PATTERN);
        if (!match) {
          continue;
        }

        const suppressedRules = match[1].split(",").map((ruleId) => ruleId.trim());
        if (suppressedRules.includes("all") || suppressedRules.includes(finding.ruleId)) {
          return `inline_suppression:${finding.ruleId}`;
        }
      }
    }

    return null;
  }
}

function matchesAnyIgnorePattern(filePath: string, patterns: string[]): boolean {
  return isPathIgnored(filePath, patterns);
}
