import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { maskSecret } from "./anthropic-key.js";

const PATTERN = /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g;
const DUMMY_PATTERNS = [/example/i, /placeholder/i, /your/i];

export const githubTokenRule: Rule = {
  id: "secret/github-token",
  title: "GitHub Token Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "GitHub トークンがコードに含まれています。",
  enabled: true,
  ruleVersion: "1.0.0",
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
            message: "GitHub トークンがコードに含まれています。",
            explanation: "GitHub PAT はソース閲覧、変更、Actions 実行などの権限を持ちうるため、漏えい時の影響が大きい値です。",
            remediation: "GitHub Secrets や環境変数に移し、露出済みなら失効してください。",
            docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }
    return findings;
  }
};
