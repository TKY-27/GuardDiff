import type { Finding, Rule, RuleContext } from "../../types/index.js";

const HOME_PATH_PATTERN = /(?:^|[\s:[-])(?:["'`])?(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/"'`\s]+|\/home\/[^/"'`\s]+)\/?(?:["'`])?(?=$|[\s,\]])/;
const PATH_CONTEXT_PATTERN = /\b(allow(?:ed)?(?:Directories|Paths)?|workspace|root(?:s)?|mount(?:s)?|cwd|directory|path)\b/i;
const STRUCTURED_CONFIG_FILE_PATTERN = /\.(?:json|jsonc|ya?ml|toml)$/i;

export const mcpFullHomeAccessRule: Rule = {
  id: "mcp/full-home-access",
  title: "MCP Full Home Access Granted",
  category: "mcp",
  severity: "critical",
  defaultConfidence: "likely",
  description: "MCP またはエージェント設定でホームディレクトリ全体へのアクセスが許可されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const fileContext = ctx.fileDiff.rawContent ?? ctx.fileDiff.hunks.flatMap((hunk) => hunk.lines.map((line) => line.content)).join("\n");
    const canUseFileContext = STRUCTURED_CONFIG_FILE_PATTERN.test(ctx.fileDiff.filePath) && PATH_CONTEXT_PATTERN.test(fileContext);

    return detectMcpFinding(
      ctx,
      this,
      (line) =>
        HOME_PATH_PATTERN.test(line.content) &&
        (PATH_CONTEXT_PATTERN.test(line.content) || canUseFileContext),
      "ホームディレクトリ全体へのアクセスが許可されています。",
      "ホームディレクトリ全体を許可すると、SSH キー、シェル履歴、各種秘密情報まで横断的に読み書きされるリスクがあります。",
      "必要なプロジェクトディレクトリだけに絞り、`~/` や `/Users/<name>` / `/home/<name>` 直下の許可は避けてください。"
    );
  }
};

function detectMcpFinding(
  ctx: RuleContext,
  rule: Rule,
  matcher: (line: { content: string }) => boolean,
  message: string,
  explanation: string,
  remediation: string
): Finding[] {
  const findings: Finding[] = [];

  for (const hunk of ctx.fileDiff.hunks) {
    for (const line of hunk.lines) {
      if (line.type !== "add" || !matcher(line)) {
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
        matchedContent: line.content.trim().slice(0, 120),
        message,
        explanation,
        remediation,
        docsUrl: `https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md`
      });
    }
  }

  return findings;
}
