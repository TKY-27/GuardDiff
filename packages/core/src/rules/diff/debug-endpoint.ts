import type { Finding, Rule, RuleContext } from "../../types/index.js";

const ENDPOINT_PATTERN = /\b(app|router)\.(get|post|put|delete|use)\s*\(\s*["'`](\/(?:debug|test|dev)(?:\/[^"'`]*)?)["'`]/i;

export const debugEndpointRule: Rule = {
  id: "diff/debug-endpoint",
  title: "Debug Endpoint Added",
  category: "diff",
  severity: "high",
  defaultConfidence: "likely",
  description: "デバッグ用エンドポイントが追加されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const match = line.content.match(ENDPOINT_PATTERN);
        if (!match) {
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
          matchedContent: match[3],
          message: `デバッグ用エンドポイント ${match[3]} が追加されています。`,
          explanation: "一時的なデバッグ API は本番に残ると情報漏えい、内部状態露出、認証漏れの入り口になります。",
          remediation: "ローカル専用の開発ツールに移すか、本番ビルドでは必ず除外してください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
