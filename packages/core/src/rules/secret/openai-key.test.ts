import { describe, expect, it } from "vitest";

import type { FileDiff, GuardDiffConfig } from "../../types/index.js";
import { openaiKeyRule } from "./openai-key.js";

const config: GuardDiffConfig = { version: "1", policy: { failOn: "high" } };

function buildFileDiff(addedLines: string[] = [], removedLines: string[] = []): FileDiff {
  return {
    filePath: "src/openai.ts",
    originalPath: "src/openai.ts",
    isNew: false,
    isDeleted: false,
    isRenamed: false,
    isBinary: false,
    hunks: [
      {
        header: "@@ -1,1 +1,1 @@",
        startLine: 1,
        endLine: Math.max(addedLines.length, removedLines.length),
        lines: [
          ...removedLines.map((content, index) => ({
            type: "remove" as const,
            lineNumber: 0,
            originalLineNumber: index + 1,
            content
          })),
          ...addedLines.map((content, index) => ({
            type: "add" as const,
            lineNumber: index + 1,
            originalLineNumber: 0,
            content
          }))
        ]
      }
    ]
  };
}

describe("secret/openai-key", () => {
  it("detects a real OpenAI key", () => {
    const findings = openaiKeyRule.detect({
      fileDiff: buildFileDiff(['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']),
      config
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not detect dummy values", () => {
    const findings = openaiKeyRule.detect({
      fileDiff: buildFileDiff(['const key = "sk-your-api-key-here";']),
      config
    });
    expect(findings).toHaveLength(0);
  });

  it("does not detect removed lines", () => {
    const findings = openaiKeyRule.detect({
      fileDiff: buildFileDiff([], ['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']),
      config
    });
    expect(findings).toHaveLength(0);
  });

  it("does not leak the original key in matched content", () => {
    const findings = openaiKeyRule.detect({
      fileDiff: buildFileDiff(['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']),
      config
    });
    expect(findings[0].matchedContent).not.toContain("abcdefghijklmnopqrstuvwxyz");
  });
});
