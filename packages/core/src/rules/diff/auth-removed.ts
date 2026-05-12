import type { Finding, Rule, RuleContext } from "../../types/index.js";

const AUTH_KEYWORDS = [
  "requireAuth",
  "authenticate",
  "authorize",
  "verifyToken",
  "isAuthenticated",
  "checkAuth",
  "validateSession",
  "authMiddleware",
  "passport.authenticate"
];

const AUTH_PATH_PATTERN = /(^|\/)(auth|authentication|authorize|middleware|guard|session|token|jwt|passport|protected)(\/|\.|$)/i;
const AUTH_CONTEXT_PATTERN =
  /\b(auth|authentication|authorization|middleware|guard|session|token|jwt|passport|protected|login|signin|role|permission|access)\b/i;
const CONTEXT_WINDOW_SIZE = 3;

export const authRemovedRule: Rule = {
  id: "diff/auth-removed",
  title: "Authentication Check Removed",
  category: "diff",
  severity: "critical",
  defaultConfidence: "likely",
  description: "認証チェックが削除されています。",
  enabled: true,
  ruleVersion: "2.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const addedContent = ctx.fileDiff.hunks
      .flatMap((hunk) => hunk.lines)
      .filter((line) => line.type === "add")
      .map((line) => line.content)
      .join("\n");

    for (const hunk of ctx.fileDiff.hunks) {
      for (const [index, line] of hunk.lines.entries()) {
        if (line.type !== "remove") {
          continue;
        }

        const matchedKeyword = AUTH_KEYWORDS.find((keyword) => line.content.includes(keyword));
        if (!matchedKeyword) {
          continue;
        }

        const isRefactoring = addedContent.includes(matchedKeyword);
        const hasAuthContext = hasAuthenticationContext(ctx, hunk.lines, index);

        findings.push(
          isRefactoring
            ? {
                ruleId: this.id,
                title: "Authentication Code Moved",
                severity: "info",
                confidence: "possible",
                category: this.category,
                filePath: ctx.fileDiff.filePath,
                lineStart: line.originalLineNumber,
                lineEnd: line.originalLineNumber,
                matchedContent: line.content.slice(0, 80),
                message: `認証コードが移動された可能性があります（${matchedKeyword}）。`,
                explanation:
                  "同一差分内に同じ認証キーワードの追加があるため、単純削除ではなくリファクタリングの可能性があります。",
                remediation: "移動先でも認証が確実に実行されているかを確認してください。",
                docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
              }
            : hasAuthContext
              ? {
                  ruleId: this.id,
                  title: this.title,
                  severity: "critical",
                  confidence: "likely",
                  category: this.category,
                  filePath: ctx.fileDiff.filePath,
                  lineStart: line.originalLineNumber,
                  lineEnd: line.originalLineNumber,
                  matchedContent: line.content.slice(0, 80),
                  message: `認証チェック（${matchedKeyword}）が削除されています。`,
                  explanation:
                    "認証ロジックの削除は保護対象への不正アクセスに直結する重大な変更です。AI のデバッグ変更として紛れ込みやすい典型例でもあります。",
                  remediation: "削除が意図的なら代替認証の存在を確認し、不要な削除なら即時に戻してください。",
                  docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
                }
              : {
                  ruleId: this.id,
                  title: "Authentication-Like Check Removed",
                  severity: "high",
                  confidence: "possible",
                  category: this.category,
                  filePath: ctx.fileDiff.filePath,
                  lineStart: line.originalLineNumber,
                  lineEnd: line.originalLineNumber,
                  matchedContent: line.content.slice(0, 80),
                  message: `認証らしきチェック（${matchedKeyword}）が削除されています。`,
                  explanation:
                    "認証キーワードを含む削除ですが、周辺の認証文脈が不足しているため重大度を一段下げて報告しています。",
                  remediation:
                    "この削除が実際の認証ガードに当たるか、周辺コードと移動先を確認してください。認証削除なら元に戻すか代替保護を追加してください。",
                  docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
                }
        );
      }
    }

    return findings;
  }
};

function hasAuthenticationContext(ctx: RuleContext, lines: RuleContext["fileDiff"]["hunks"][number]["lines"], index: number): boolean {
  if (AUTH_PATH_PATTERN.test(ctx.fileDiff.filePath)) {
    return true;
  }

  const start = Math.max(0, index - CONTEXT_WINDOW_SIZE);
  const end = Math.min(lines.length, index + CONTEXT_WINDOW_SIZE + 1);
  const nearbyContext = lines.slice(start, end).filter((line, nearbyIndex) => {
    const absoluteIndex = start + nearbyIndex;
    return absoluteIndex !== index && line.type === "context";
  });

  return nearbyContext.some((line) => AUTH_CONTEXT_PATTERN.test(line.content));
}
