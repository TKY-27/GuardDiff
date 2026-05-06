import { describe, expect, it } from "vitest";

import type { FileDiff, GuardDiffConfig } from "../../types/index.js";
import { envPlaintextSecretRule } from "./env-plaintext-secret.js";

const config: GuardDiffConfig = { version: "1", policy: { failOn: "high" } };

describe("config/env-plaintext-secret", () => {
  it("detects secret-like values in .env files", () => {
    const fileDiff: FileDiff = {
      filePath: ".env",
      originalPath: ".env",
      isNew: true,
      isDeleted: false,
      isRenamed: false,
      isBinary: false,
      hunks: [
        {
          header: "@@ -0,0 +1,1 @@",
          startLine: 1,
          endLine: 1,
          lines: [
            {
              type: "add",
              lineNumber: 1,
              originalLineNumber: 0,
              content: "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"
            }
          ]
        }
      ]
    };

    const findings = envPlaintextSecretRule.detect({ fileDiff, config });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("detects nested .env files by basename", () => {
    const fileDiff: FileDiff = {
      filePath: "apps/web/.env.local",
      originalPath: "apps/web/.env.local",
      isNew: true,
      isDeleted: false,
      isRenamed: false,
      isBinary: false,
      hunks: [
        {
          header: "@@ -0,0 +1,1 @@",
          startLine: 1,
          endLine: 1,
          lines: [
            {
              type: "add",
              lineNumber: 1,
              originalLineNumber: 0,
              content: "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"
            }
          ]
        }
      ]
    };

    const findings = envPlaintextSecretRule.detect({ fileDiff, config });
    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe("apps/web/.env.local");
  });
});
