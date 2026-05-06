import type { Finding, Rule, RuleContext } from "../../types/index.js";

const OPEN_READ_PATTERN = /allow\s+read\s*:\s*if\s+true\s*;/i;

export const firestoreOpenReadRule: Rule = {
  id: "config/firestore-open-read",
  title: "Firestore Read Rules Open to Everyone",
  category: "config",
  severity: "high",
  defaultConfidence: "confirmed",
  description: "Firestore の read ルールが全開放されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const addedContent = ctx.fileDiff.hunks
      .flatMap((hunk) => hunk.lines)
      .filter((line) => line.type === "add")
      .map((line) => line.content)
      .join("\n");
    const scanContent = addedContent.length > 0 ? addedContent : (ctx.fileDiff.rawContent ?? "");
    const fileContext = ctx.fileDiff.rawContent ?? scanContent;

    if (!/(firestore|rules_version|match\s+\/databases)/i.test(fileContext) || !OPEN_READ_PATTERN.test(scanContent)) {
      return [];
    }

    const lineNumber = Math.max(
      1,
      scanContent.split(/\r?\n/).findIndex((line) => OPEN_READ_PATTERN.test(line)) + 1
    );

    return [
      {
        ruleId: this.id,
        title: this.title,
        severity: "high",
        confidence: "confirmed",
        category: this.category,
        filePath: ctx.fileDiff.filePath,
        lineStart: lineNumber,
        lineEnd: lineNumber,
        matchedContent: "allow read: if true;",
        message: "Firestore の read ルールが全公開されています。",
        explanation: "read を無条件に許可すると、機密データが未認証で取得可能になります。",
        remediation: "必要なコレクションだけを対象にし、認証済みユーザーや所有者に絞ってください。",
        docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
      }
    ];
  }
};
