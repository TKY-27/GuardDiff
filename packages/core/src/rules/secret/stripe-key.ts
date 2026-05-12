import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { maskSecret } from "./anthropic-key.js";

const PATTERN = /\bsk_live_[A-Za-z0-9]{24,}\b/g;
const DUMMY_PATTERNS = [/example/i, /placeholder/i, /your/i];

export const stripeKeyRule: Rule = {
  id: "secret/stripe-key",
  title: "Stripe Secret Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "Stripe シークレットキーがコードに含まれています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        for (const match of line.content.matchAll(PATTERN)) {
          const raw = match[0];
          if (DUMMY_PATTERNS.some((pattern) => pattern.test(raw))) {
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
            matchedContent: maskSecret(raw),
            message: "Stripe シークレットキーがコードに含まれています。",
            explanation: "決済系の秘密鍵は課金操作や顧客情報アクセスに直結するため、漏えい時の被害が大きい値です。",
            remediation: "環境変数に移し、公開済みなら即時ローテーションしてください。",
            docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }
    return findings;
  }
};
