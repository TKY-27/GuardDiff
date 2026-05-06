import type { Finding, Rule, RuleContext } from "../../types/index.js";

const DANGEROUS_PATTERNS = [
  /\bapproval_policy\s*[:=]\s*["']?never["']?/i,
  /\brequire_approval\s*[:=]\s*false\b/i,
  /\bexecute_without_approval\s*[:=]\s*true\b/i,
  /\bauto_execute\s*[:=]\s*true\b/i
];

export const mcpAutoExecWithoutApprovalRule: Rule = {
  id: "mcp/auto-exec-without-approval",
  title: "MCP Auto-Execution Without Approval",
  category: "mcp",
  severity: "high",
  defaultConfidence: "likely",
  description: "承認なしでコマンド実行が可能な設定です。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const matchedPattern = DANGEROUS_PATTERNS.find((pattern) => pattern.test(line.content));
        if (!matchedPattern) {
          continue;
        }

        findings.push({
          ruleId: this.id,
          title: this.title,
          severity: this.severity,
          confidence: this.defaultConfidence,
          category: this.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: line.content.trim().slice(0, 120),
          message: "承認なしの自動実行設定が追加されています。",
          explanation: "エージェントが人間の承認なしにコマンドを実行できると、誤操作やプロンプト注入がそのまま破壊的操作につながります。",
          remediation: "承認ポリシーを有効に戻し、自動実行は限定された安全なサブセットにのみ許可してください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
