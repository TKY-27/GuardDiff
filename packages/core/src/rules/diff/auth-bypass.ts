import type { Finding, Rule, RuleContext } from "../../types/index.js";

const AUTH_CONTEXT = /(auth|authorize|authentication|requireAuth|verifyToken|middleware)/i;
const CONTEXT_WINDOW_SIZE = 3;
const BYPASS_PATTERNS = [
  /\breturn\s+true\s*;?/,
  /\bnext\s*\(\s*\)\s*;?\s*(\/\/.*)?$/,
  /\bauthDisabled\s*=\s*true\b/i,
  /\bskip(Auth|Authentication)\b/i
];

export const authBypassRule: Rule = {
  id: "diff/auth-bypass",
  title: "Authentication Bypass Added",
  category: "diff",
  severity: "critical",
  defaultConfidence: "likely",
  description: "認証バイパスが追加されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const fileSuggestsAuth = AUTH_CONTEXT.test(ctx.fileDiff.filePath);

    for (const hunk of ctx.fileDiff.hunks) {
      for (const [index, line] of hunk.lines.entries()) {
        if (line.type !== "add") {
          continue;
        }

        if (!BYPASS_PATTERNS.some((pattern) => pattern.test(line.content))) {
          continue;
        }

        if (!fileSuggestsAuth && !hasNearbyAuthContext(hunk.lines, index)) {
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
          matchedContent: line.content.trim().slice(0, 120),
          message: "認証処理を迂回するコードが追加されています。",
          explanation: "認証ミドルウェアや認証関数内で早期に通してしまうと、保護対象へのアクセス制御が無効化されます。",
          remediation: "デバッグ目的の通し処理を削除し、必要なら明示的な feature flag を追加してください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};

function hasNearbyAuthContext(lines: RuleContext["fileDiff"]["hunks"][number]["lines"], index: number): boolean {
  const start = Math.max(0, index - CONTEXT_WINDOW_SIZE);
  const end = Math.min(lines.length, index + CONTEXT_WINDOW_SIZE + 1);

  return lines.slice(start, end).some((line, nearbyIndex) => {
    const absoluteIndex = start + nearbyIndex;
    return absoluteIndex !== index && AUTH_CONTEXT.test(line.content);
  });
}
