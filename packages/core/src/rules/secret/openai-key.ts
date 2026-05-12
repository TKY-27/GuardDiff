import type { Finding, Rule, RuleContext } from "../../types/index.js";

const OPENAI_KEY_PATTERN = /sk-[A-Za-z0-9]{20,60}/g;
const DUMMY_PATTERNS = [/sk-xxx/i, /sk-your/i, /sk-test/i, /sk-sample/i, /sk-\*+/i, /placeholder/i];

export const openaiKeyRule: Rule = {
  id: "secret/openai-key",
  title: "OpenAI API Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "OpenAI API キーがコードに含まれています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        for (const match of line.content.matchAll(OPENAI_KEY_PATTERN)) {
          const raw = match[0];
          if (DUMMY_PATTERNS.some((pattern) => pattern.test(raw))) {
            continue;
          }

          findings.push({
            ruleId: this.id,
            title: this.title,
            severity: "critical",
            confidence: "likely",
            category: this.category,
            filePath: ctx.fileDiff.filePath,
            lineStart: line.lineNumber,
            lineEnd: line.lineNumber,
            matchedContent: maskOpenAIKey(raw),
            message: "OpenAI API キーがコードに含まれています。",
            explanation:
              "コードに API キーを直書きすると、リポジトリ共有や公開時にそのまま漏えいします。漏えいしたキーは不正利用と課金事故の起点になります。",
            remediation:
              "キーを環境変数に移し、漏えいした可能性がある場合は即時ローテーションしてください。",
            docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
          });
        }
      }
    }

    return findings;
  }
};

export function maskOpenAIKey(value: string): string {
  if (value.length <= 8) {
    return "sk-****";
  }
  return `${value.slice(0, 3)}${"*".repeat(8)}...`;
}
