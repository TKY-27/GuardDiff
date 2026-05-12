import type { Finding, Rule, RuleContext } from "../../types/index.js";

export const evalInjectionRule: Rule = {
  id: "diff/eval-injection",
  title: "eval Usage Added",
  category: "diff",
  severity: "high",
  defaultConfidence: "likely",
  description: "eval の使用が追加されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add" || !/\beval\s*\(/.test(line.content)) {
          continue;
        }

        findings.push({
          ruleId: this.id,
          title: this.title,
          severity: "high",
          confidence: "likely",
          category: this.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: line.content.trim().slice(0, 120),
          message: "eval の使用が追加されています。",
          explanation: "eval は入力の流入経路によって任意コード実行を招きやすく、保守性も大きく下げます。",
          remediation: "構文解析や明示的なマップ処理に置き換えてください。",
          docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
        });
      }
    }
    return findings;
  }
};
