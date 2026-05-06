import path from "node:path";

import type { Finding, Rule, RuleContext } from "../../types/index.js";

const SAFE_ENV_EXAMPLE_NAMES = new Set([".env.example", ".env.sample", ".env.template"]);

export const envCommittedRule: Rule = {
  id: "config/env-committed",
  title: ".env File Committed",
  category: "config",
  severity: "high",
  defaultConfidence: "confirmed",
  description: ".env ファイルが差分に含まれています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    if (ctx.fileDiff.isDeleted) {
      return [];
    }

    const basename = path.basename(ctx.fileDiff.filePath);
    if (!basename.startsWith(".env") || SAFE_ENV_EXAMPLE_NAMES.has(basename)) {
      return [];
    }

    return [
      {
        ruleId: this.id,
        title: this.title,
        severity: "high",
        confidence: "confirmed",
        category: this.category,
        filePath: ctx.fileDiff.filePath,
        lineStart: 1,
        lineEnd: 1,
        matchedContent: ctx.fileDiff.filePath,
        message: ".env ファイルがコミット対象に含まれています。",
        explanation: ".env には実運用シークレットが含まれることが多く、誤って共有リポジトリへ入ると被害が大きくなります。",
        remediation: ".gitignore に追加し、必要なら .env.example を別途用意してください。",
        docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
      }
    ];
  }
};
