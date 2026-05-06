import type { Finding, Rule, RuleContext } from "../../types/index.js";

const EXEC_PATTERN = /\b(exec|spawn|execSync|spawnSync)\s*\((.+)\)/;
const USER_INPUT_PATTERN = /\b(req\.|request\.|ctx\.request|userInput|input|command|argv|query|body|params)/i;

export const dangerousShellRule: Rule = {
  id: "diff/dangerous-shell",
  title: "Dangerous Shell Execution",
  category: "diff",
  severity: "critical",
  defaultConfidence: "likely",
  description: "ユーザー入力起点の shell 実行が追加されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const match = line.content.match(EXEC_PATTERN);
        if (!match) {
          continue;
        }

        if (!USER_INPUT_PATTERN.test(match[2])) {
          continue;
        }

        findings.push({
          ruleId: this.id,
          title: this.title,
          severity: "critical",
          confidence: "likely",
          category: this.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: line.content.trim().slice(0, 120),
          message: "ユーザー入力に依存する shell 実行が追加されています。",
          explanation: "未検証入力をそのまま shell に渡すとコマンドインジェクションに直結します。",
          remediation: "shell を避けて API を直接呼ぶか、引数リストを使って厳格にバリデーションしてください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
