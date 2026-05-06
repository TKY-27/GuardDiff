import type { Finding, Rule, RuleContext } from "../../types/index.js";

export const firebaseConfigRule: Rule = {
  id: "secret/firebase-config",
  title: "Firebase Config Object Detected",
  category: "secret",
  severity: "high",
  defaultConfidence: "possible",
  description: "Firebase 設定オブジェクトが追加されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const addedLines = ctx.fileDiff.hunks.flatMap((hunk) => hunk.lines).filter((line) => line.type === "add");
    const addedContent = addedLines.map((line) => line.content).join("\n");
    const content = ctx.fileDiff.rawContent ?? addedContent;

    if (!/apiKey\s*:\s*["'`]/.test(addedContent) && !/projectId\s*:\s*["'`]/.test(addedContent)) {
      return [];
    }

    if (!/apiKey\s*:\s*["'`]/.test(content) || !/projectId\s*:\s*["'`]/.test(content)) {
      return [];
    }

    const firstRelevantLine = addedLines.find((line) => /apiKey\s*:\s*["'`]|projectId\s*:\s*["'`]/.test(line.content))?.lineNumber ?? 1;

    return [
      {
        ruleId: this.id,
        title: this.title,
        severity: "high",
        confidence: "possible",
        category: this.category,
        filePath: ctx.fileDiff.filePath,
        lineStart: firstRelevantLine,
        lineEnd: firstRelevantLine,
        matchedContent: "{ apiKey: ****, projectId: ... }",
        message: "Firebase 設定オブジェクトが追加されています。",
        explanation: "Firebase のクライアント設定自体は常に秘密ではありませんが、誤って管理用設定や関連鍵が混在しやすい領域です。",
        remediation: "クライアント公開前提の値かを確認し、管理権限のある鍵は含めないでください。",
        docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
      }
    ];
  }
};
