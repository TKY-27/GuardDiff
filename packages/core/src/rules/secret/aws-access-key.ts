import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { maskSecret } from "./anthropic-key.js";

const PATTERN = /\bAKIA[0-9A-Z]{16}\b/g;
const DUMMY_PATTERNS = [/example/i, /placeholder/i, /your/i];

export const awsAccessKeyRule: Rule = {
  id: "secret/aws-access-key",
  title: "AWS Access Key ID Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "AWS Access Key ID がコードに含まれています。",
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
            message: "AWS Access Key ID がコードに含まれています。",
            explanation: "AWS 資格情報のハードコードは、不正 API 呼び出しやインフラ乗っ取りの起点になります。",
            remediation: "IAM ロールや環境変数へ移し、漏えいした可能性がある場合は無効化してください。",
            docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }
    return findings;
  }
};
