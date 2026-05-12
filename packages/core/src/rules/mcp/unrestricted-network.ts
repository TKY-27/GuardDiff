import type { Finding, Rule, RuleContext } from "../../types/index.js";

const NETWORK_PATTERNS = [
  /\bnetwork_access\s*[:=]\s*true\b/i,
  /\ballow_network\s*[:=]\s*true\b/i,
  /\bunrestricted_network\s*[:=]\s*true\b/i,
  /\bnetwork\s*[:=]\s*["']?(?:all|full|unrestricted)["']?/i
];

export const mcpUnrestrictedNetworkRule: Rule = {
  id: "mcp/unrestricted-network",
  title: "MCP Unrestricted Network Access",
  category: "mcp",
  severity: "high",
  defaultConfidence: "likely",
  description: "無制限のネットワークアクセス設定が追加されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const matchedPattern = NETWORK_PATTERNS.find((pattern) => pattern.test(line.content));
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
          message: "無制限のネットワークアクセス設定が追加されています。",
          explanation: "外部送信が自由な状態で強権限ツールを組み合わせると、機密情報の持ち出しや外部への不正操作を招きやすくなります。",
          remediation: "必要な宛先だけに絞るか、デフォルトはネットワーク無効にして明示的に許可する形へ戻してください。",
          docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
