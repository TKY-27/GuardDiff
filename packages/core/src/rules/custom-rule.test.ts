import { describe, expect, it } from "vitest";

import { createSyntheticFileDiff } from "../parser/file-diff-factory.js";
import type { GuardDiffConfig } from "../types/index.js";
import { buildCustomRules } from "./custom-rule.js";

describe("custom rules", () => {
  it("redacts long matched values before exposing custom rule findings", () => {
    const config: GuardDiffConfig = {
      version: "1",
      policy: {
        failOn: "high"
      },
      rules: {
        custom: [
          {
            id: "custom/no-inline-token",
            title: "No inline token",
            category: "secret",
            severity: "high",
            pattern: "apiKey",
            message: "Inline token-like value found.",
            explanation: "Custom rules must not leak raw matched secret-like lines.",
            remediation: "Move the value to a secret manager."
          }
        ]
      }
    };

    const [rule] = buildCustomRules(config);
    const [finding] = rule.detect({
      config,
      fileDiff: createSyntheticFileDiff("src/app.ts", 'const apiKey = "abcdefghijklmnopqrstuvwxyz123456";\n')
    });

    expect(finding.matchedContent).toBe('const apiKey = "****";');
    expect(finding.matchedContent).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
  });
});
