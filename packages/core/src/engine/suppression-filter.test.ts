import { describe, expect, it } from "vitest";

import { SuppressionFilter } from "./suppression-filter.js";

describe("SuppressionFilter", () => {
  it("suppresses matching inline comments", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, []).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      [
        {
          filePath: "src/openai.ts",
          originalPath: "src/openai.ts",
          isNew: false,
          isDeleted: false,
          isRenamed: false,
          isBinary: false,
          hunks: [
            {
              header: "@@ -1 +1 @@",
              startLine: 1,
              endLine: 1,
              lines: [
                {
                  type: "add",
                  lineNumber: 1,
                  originalLineNumber: 1,
                  content: 'const key = "sk-abc"; // guarddiff-ignore: secret/openai-key'
                }
              ]
            }
          ]
        }
      ]
    );

    expect(filtered[0].suppressed).toBe(true);
  });

  it("suppresses matching all inline comments", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, []).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      [
        {
          filePath: "src/openai.ts",
          originalPath: "src/openai.ts",
          isNew: false,
          isDeleted: false,
          isRenamed: false,
          isBinary: false,
          hunks: [
            {
              header: "@@ -1 +1 @@",
              startLine: 1,
              endLine: 1,
              lines: [
                {
                  type: "add",
                  lineNumber: 1,
                  originalLineNumber: 1,
                  content: 'const key = "sk-abc"; // guarddiff-ignore: all'
                }
              ]
            }
          ]
        }
      ]
    );

    expect(filtered[0].suppressed).toBe(true);
    expect(filtered[0].suppressReason).toBe("inline_suppression:secret/openai-key");
  });

  it("can disable inline suppression for untrusted CI diffs", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, [], { inline: false }).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      [
        {
          filePath: "src/openai.ts",
          originalPath: "src/openai.ts",
          isNew: false,
          isDeleted: false,
          isRenamed: false,
          isBinary: false,
          hunks: [
            {
              header: "@@ -1 +1 @@",
              startLine: 1,
              endLine: 1,
              lines: [
                {
                  type: "add",
                  lineNumber: 1,
                  originalLineNumber: 1,
                  content: 'const key = "sk-abc"; // guarddiff-ignore: all'
                }
              ]
            }
          ]
        }
      ]
    );

    expect(filtered[0].suppressed).toBeUndefined();
  });

  it("suppresses ignored rules from config", () => {
    const filtered = new SuppressionFilter(
      { version: "1", policy: { failOn: "high" }, ignore: { rules: ["secret/openai-key"] } },
      []
    ).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      []
    );

    expect(filtered[0].suppressed).toBe(true);
    expect(filtered[0].suppressReason).toBe("rule_ignored");
  });

  it("suppresses ignored paths", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, ["examples/**"]).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "examples/leaked-api-key/src-openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      []
    );

    expect(filtered[0].suppressed).toBe(true);
    expect(filtered[0].suppressReason).toBe("ignore_file_path_ignored");
  });

  it("gives inline suppression priority over ignored paths", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, ["src/**"]).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      [
        {
          filePath: "src/openai.ts",
          originalPath: "src/openai.ts",
          isNew: false,
          isDeleted: false,
          isRenamed: false,
          isBinary: false,
          hunks: [
            {
              header: "@@ -1 +1 @@",
              startLine: 1,
              endLine: 1,
              lines: [
                {
                  type: "add",
                  lineNumber: 1,
                  originalLineNumber: 1,
                  content: 'const key = "sk-abc"; // guarddiff-ignore: secret/openai-key'
                }
              ]
            }
          ]
        }
      ]
    );

    expect(filtered[0].suppressed).toBe(true);
    expect(filtered[0].suppressReason).toBe("inline_suppression:secret/openai-key");
  });

  it("treats trailing-slash ignore entries as directory globs", () => {
    const filtered = new SuppressionFilter({ version: "1", policy: { failOn: "high" } }, ["fixtures/"]).apply(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "tests/fixtures/openai.ts",
          lineStart: 1,
          lineEnd: 1,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      []
    );

    expect(filtered[0].suppressed).toBe(true);
    expect(filtered[0].suppressReason).toBe("ignore_file_path_ignored");
  });
});
