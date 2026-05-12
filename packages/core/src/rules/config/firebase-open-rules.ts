import type { Finding, Rule, RuleContext } from "../../types/index.js";

const OPEN_RULES_PATTERN = /allow\s+read\s*,\s*write\s*:\s*if\s+true\s*;/i;
export const firebaseOpenRulesRule: Rule = {
  id: "config/firebase-open-rules",
  title: "Firebase Rules Open to Everyone",
  category: "config",
  severity: "critical",
  defaultConfidence: "confirmed",
  description: "Firebase/Firestore ルールが全開放されています。",
  enabled: true,
  ruleVersion: "0.1.0",
  detect(ctx: RuleContext): Finding[] {
    const addedContent = addedLinesToContent(ctx);
    const scanContent = addedContent.length > 0 ? addedContent : (ctx.fileDiff.rawContent ?? "");
    const fileContext = ctx.fileDiff.rawContent ?? scanContent;

    if (!/(firestore|rules_version|match\s+\/databases)/i.test(fileContext)) {
      return [];
    }

    if (!OPEN_RULES_PATTERN.test(scanContent)) {
      return [];
    }

    return [
      {
        ruleId: this.id,
        title: this.title,
        severity: "critical",
        confidence: "confirmed",
        category: this.category,
        filePath: ctx.fileDiff.filePath,
        lineStart: locateLine(scanContent, OPEN_RULES_PATTERN),
        lineEnd: locateLine(scanContent, OPEN_RULES_PATTERN),
        matchedContent: "allow read, write: if true;",
        message: "Firebase/Firestore ルールが全公開されています。",
        explanation: "読み書きを無条件に許可すると、認証なしでデータの改ざんと漏えいが可能になります。",
        remediation: "認証条件と所有者条件を明示し、少なくとも `request.auth != null` を基準に絞ってください。",
        docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
      }
    ];
  }
};

function addedLinesToContent(ctx: RuleContext): string {
  return ctx.fileDiff.hunks
    .flatMap((hunk) => hunk.lines)
    .filter((line) => line.type === "add")
    .map((line) => line.content)
    .join("\n");
}

function locateLine(content: string, pattern: RegExp): number {
  const lines = content.split(/\r?\n/);
  return Math.max(
    1,
    lines.findIndex((line) => pattern.test(line)) + 1
  );
}
