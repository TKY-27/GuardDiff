import type { Finding, Rule, RuleContext } from "../../types/index.js";

const PATTERN = /sk-ant-[A-Za-z0-9-]{30,100}/g;
const DUMMY_PATTERNS = [/sk-ant-your/i, /placeholder/i, /example/i];

export const anthropicKeyRule: Rule = {
  id: "secret/anthropic-key",
  title: "Anthropic API Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "Anthropic API キーがコードに含まれています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    return detectPatternMatches(ctx, this, PATTERN, DUMMY_PATTERNS, "Anthropic API キーがコードに含まれています。");
  }
};

function detectPatternMatches(
  ctx: RuleContext,
  rule: Rule,
  pattern: RegExp,
  dummyPatterns: RegExp[],
  message: string
): Finding[] {
  const findings: Finding[] = [];

  for (const hunk of ctx.fileDiff.hunks) {
    for (const line of hunk.lines) {
      if (line.type !== "add") {
        continue;
      }

      for (const match of line.content.matchAll(pattern)) {
        const raw = match[0];
        if (dummyPatterns.some((dummyPattern) => dummyPattern.test(raw))) {
          continue;
        }

        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.defaultConfidence,
          category: rule.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: maskSecret(raw),
          message,
          explanation: "生成 AI 系の API キーを直書きすると、公開リポジトリや CI ログから第三者に利用されるおそれがあります。",
          remediation: "環境変数または secret manager に移動し、露出した可能性があればローテーションしてください。",
          docsUrl: `https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md`
        });
      }
    }
  }

  return findings;
}

export function maskSecret(value: string): string {
  if (value.length <= 8) {
    return "****";
  }
  return `${value.slice(0, 4)}****${value.slice(-4)}`;
}
