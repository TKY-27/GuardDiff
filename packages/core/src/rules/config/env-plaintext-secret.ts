import path from "node:path";

import type { Finding, Rule, RuleContext } from "../../types/index.js";
import { calculateShannonEntropy } from "../../entropy/shannon.js";

const KEY_NAME_PATTERN = /(secret|token|password|key|credential|passwd|pwd)/i;
const VALUE_PATTERN = /^[A-Za-z0-9+/_=-]{20,}$/;
const DUMMY_PATTERNS = [/example/i, /placeholder/i, /change[-_]?me/i, /your[-_]?key/i, /localhost/i];

export const envPlaintextSecretRule: Rule = {
  id: "config/env-plaintext-secret",
  title: "Plaintext Secret in .env",
  category: "config",
  severity: "high",
  defaultConfidence: "likely",
  description: ".env に秘密情報らしき値が含まれています。",
  enabled: true,
  ruleVersion: "1.0.0",
  detect(ctx: RuleContext): Finding[] {
    if (!path.basename(ctx.fileDiff.filePath).startsWith(".env")) {
      return [];
    }

    const findings: Finding[] = [];
    for (const hunk of ctx.fileDiff.hunks) {
      for (const line of hunk.lines) {
        if (line.type !== "add") {
          continue;
        }

        const separatorIndex = line.content.indexOf("=");
        if (separatorIndex < 1) {
          continue;
        }

        const key = line.content.slice(0, separatorIndex).trim();
        const value = line.content.slice(separatorIndex + 1).trim().replace(/^['"]|['"]$/g, "");
        if (!KEY_NAME_PATTERN.test(key)) {
          continue;
        }

        if (!VALUE_PATTERN.test(value)) {
          continue;
        }

        if (DUMMY_PATTERNS.some((pattern) => pattern.test(value))) {
          continue;
        }

        if (calculateShannonEntropy(value) < 4) {
          continue;
        }

        findings.push({
          ruleId: this.id,
          title: this.title,
          severity: "high",
          confidence: "likely",
          category: this.category,
          filePath: ctx.fileDiff.filePath,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          matchedContent: `${key}=****`,
          message: ".env に平文の秘密情報らしき値が含まれています。",
          explanation: ".env は共有や誤コミットの対象になりやすく、実値のまま置くと漏えい時の影響が大きくなります。",
          remediation: "`.env.example` にはダミー値のみを置き、実シークレットはローカルまたはシークレットマネージャーで管理してください。",
          docsUrl: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md"
        });
      }
    }

    return findings;
  }
};
