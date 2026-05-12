import type { Finding, Rule, RuleContext } from "../../types/index.js";

const CORS_PATTERNS = [/Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*/i, /origin\s*:\s*["']\*/i];

export const corsWildcardRule: Rule = {
  id: "diff/cors-wildcard",
  title: "CORS Wildcard Detected",
  category: "diff",
  severity: "high",
  defaultConfidence: "likely",
  description: "CORS が全開放されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        if (!CORS_PATTERNS.some((pattern) => pattern.test(line.content))) {
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
          message: "CORS がワイルドカードで開放されています。",
          explanation: "認証付き API や管理系エンドポイントで CORS を全開放すると、意図しないオリジンからの利用を許すおそれがあります。",
          remediation: "許可するオリジンを明示し、本番と開発で設定を分離してください。",
          docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
