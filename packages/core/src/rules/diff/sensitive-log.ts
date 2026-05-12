import type { Finding, Rule, RuleContext } from "../../types/index.js";

const LOG_PATTERN = /\b(console\.(log|info|debug)|logger\.(info|debug|warn)|print)\s*\(/i;
const SENSITIVE_PATTERN = /\b(password|token|secret|api[_-]?key|authorization|cookie|session)\b/i;

export const sensitiveLogRule: Rule = {
  id: "diff/sensitive-log",
  title: "Sensitive Data Logged",
  category: "diff",
  severity: "medium",
  defaultConfidence: "likely",
  description: "機密情報のログ出力が追加されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        if (!LOG_PATTERN.test(line.content) || !SENSITIVE_PATTERN.test(stripQuotedStrings(line.content))) {
          continue;
        }

        findings.push({
          ruleId: this.id,
          title: this.title,
          severity: "medium",
          confidence: "likely",
          category: this.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: line.content.trim().slice(0, 120),
          message: "機密情報を含むログ出力が追加されています。",
          explanation: "ログは集約・共有されやすく、機密値を含めると二次漏えいの温床になります。",
          remediation: "値はマスクし、必要ならメタ情報だけを記録してください。",
          docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
        });
      }
    }
    return findings;
  }
};

function stripQuotedStrings(value: string): string {
  return value.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, "\"\"");
}
