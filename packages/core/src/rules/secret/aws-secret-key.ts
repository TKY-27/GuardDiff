import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { maskSecret } from "./anthropic-key.js";

const CONTEXT_PATTERN = /(aws_secret_access_key|awsSecretAccessKey|secretAccessKey)/;
const VALUE_PATTERN = /["']([A-Za-z0-9/+=]{40})["']/g;
const DUMMY_PATTERNS = [/example/i, /placeholder/i, /your/i];

export const awsSecretKeyRule: Rule = {
  id: "secret/aws-secret-key",
  title: "AWS Secret Access Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "possible",
  description: "AWS Secret Access Key がコードに含まれています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add" || !CONTEXT_PATTERN.test(line.content)) {
          continue;
        }

        for (const match of line.content.matchAll(VALUE_PATTERN)) {
          const raw = match[1];
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
            message: "AWS Secret Access Key がコードに含まれています。",
            explanation: "Access Key ID と対になる秘密鍵は流出時の権限悪用リスクが非常に高い値です。",
            remediation: "コードから削除し、秘密管理ストアに移動してください。",
            docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }

    return findings;
  }
};
