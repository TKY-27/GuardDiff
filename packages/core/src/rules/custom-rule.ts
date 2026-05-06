import type { CustomRuleConfig, Finding, GuardDiffConfig, Rule, RuleContext } from "../types/index.js";

export function buildCustomRules(config: GuardDiffConfig): Rule[] {
  return (config.rules?.custom ?? []).map((customRule) => buildCustomRule(customRule));
}

function buildCustomRule(customRule: CustomRuleConfig): Rule {
  const pattern = new RegExp(customRule.pattern, "i");

  return {
    id: customRule.id,
    title: customRule.title,
    category: customRule.category,
    severity: customRule.severity,
    defaultConfidence: "possible",
    description: customRule.message,
    enabled: true,
    ruleVersion: "1.0.0",
    detect(ctx: RuleContext): Finding[] {
      const findings: Finding[] = [];
      for (const hunk of ctx.fileDiff.hunks) {
        for (const line of hunk.lines) {
          if (line.type !== "add" || !pattern.test(line.content)) {
            continue;
          }

          findings.push({
            ruleId: customRule.id,
            title: customRule.title,
            severity: customRule.severity,
            confidence: "possible",
            category: customRule.category,
            filePath: ctx.fileDiff.filePath,
            lineStart: line.lineNumber,
            lineEnd: line.lineNumber,
            matchedContent: maskCustomRuleMatch(line.content),
            message: customRule.message,
            explanation: customRule.explanation,
            remediation: customRule.remediation
          });
        }
      }

      return findings;
    }
  };
}

function maskCustomRuleMatch(content: string): string {
  const trimmed = content.trim();
  if (trimmed.length === 0) {
    return "[redacted]";
  }

  const redacted = trimmed
    .replace(/(["'`])([^"'`]{8,})\1/g, "$1****$1")
    .replace(/(=\s*)([^\s,;)]{8,})/g, "$1****")
    .replace(/(:\s*)([^\s,;)]{8,})/g, "$1****");

  return redacted.length > 120 ? `${redacted.slice(0, 117)}...` : redacted;
}
