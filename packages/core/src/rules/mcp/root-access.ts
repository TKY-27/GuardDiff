import type { Finding, Rule, RuleContext } from "../../types/index.js";

const ROOT_VALUE_PATTERN = /(?:[:=]\s*|\[\s*|,\s*|^\s*-\s*|^\s*)(?:["'`])?\/(?:["'`])?(?=\s*(?:,|\]|$))/;
const PATH_CONTEXT_PATTERN = /\b(allow(?:ed)?(?:Directories|Paths)?|workspace|root(?:s)?|mount(?:s)?|cwd|directory|path)\b/i;
const STRUCTURED_CONFIG_FILE_PATTERN = /\.(?:json|jsonc|ya?ml|toml)$/i;

export const mcpRootAccessRule: Rule = {
  id: "mcp/root-access",
  title: "MCP Root Filesystem Access Granted",
  category: "mcp",
  severity: "critical",
  defaultConfidence: "likely",
  description: "MCP またはエージェント設定で `/` へのアクセスが許可されています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const fileContext = ctx.fileDiff.rawContent ?? ctx.fileDiff.hunks.flatMap((hunk) => hunk.lines.map((line) => line.content)).join("\n");
    const canUseFileContext = STRUCTURED_CONFIG_FILE_PATTERN.test(ctx.fileDiff.filePath) && PATH_CONTEXT_PATTERN.test(fileContext);

    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        if (!ROOT_VALUE_PATTERN.test(line.content)) {
          continue;
        }

        if (!PATH_CONTEXT_PATTERN.test(line.content) && !canUseFileContext) {
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
          matchedContent: line.content.trim().slice(0, 120),
          message: "ルートディレクトリ `/` へのアクセスが許可されています。",
          explanation: "ルート全体を許可すると OS 設定、システム秘密情報、他ユーザー領域まで触れる設定になり、事故時の影響範囲が極端に広がります。",
          remediation: "必要最小限のディレクトリだけを明示し、`/` を直接許可しないでください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
