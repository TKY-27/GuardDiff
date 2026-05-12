import type { Finding, Rule, RuleContext } from "../../types/index.js";

const PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

export const privateKeyRule: Rule = {
  id: "secret/private-key",
  title: "Private Key Material Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "confirmed",
  description: "秘密鍵がコードに含まれています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add" || !PATTERN.test(line.content)) {
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
          matchedContent: "-----BEGIN **** PRIVATE KEY-----",
          message: "秘密鍵がコードに含まれています。",
          explanation: "秘密鍵は即座に第三者になりすましや復号を許すため、コミットしてはいけない代表例です。",
          remediation: "直ちに削除し、すでに露出した場合は鍵を再発行してください。",
          docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
        });
      }
    }
    return findings;
  }
};
