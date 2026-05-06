import { describe, expect, it } from "vitest";

import type { FileDiff, GuardDiffConfig } from "../../types/index.js";
import { dangerousShellRule } from "./dangerous-shell.js";

const config: GuardDiffConfig = { version: "1", policy: { failOn: "high" } };

describe("diff/dangerous-shell", () => {
  it("detects exec with request input", () => {
    const fileDiff: FileDiff = {
      filePath: "src/handler.ts",
      originalPath: "src/handler.ts",
      isNew: false,
      isDeleted: false,
      isRenamed: false,
      isBinary: false,
      hunks: [
        {
          header: "@@ -1,1 +1,2 @@",
          startLine: 1,
          endLine: 2,
          lines: [
            {
              type: "add",
              lineNumber: 2,
              originalLineNumber: 0,
              content: "exec(req.body.command);"
            }
          ]
        }
      ]
    };

    const findings = dangerousShellRule.detect({ fileDiff, config });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });
});
