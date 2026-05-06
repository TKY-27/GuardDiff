import { describe, expect, it } from "vitest";

import { runScan } from "./index.js";
import { buildFileDiff, TEST_CONFIG } from "./test-helpers.js";

describe("runScan", () => {
  it("marks .guarddiffignore matches as suppressed instead of dropping findings", async () => {
    const result = await runScan({
      fileDiffs: [
        buildFileDiff({
          filePath: "tests/fixtures/openai.ts",
          addedLines: ['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']
        })
      ],
      config: TEST_CONFIG,
      inputType: "diff",
      ignorePaths: ["tests/fixtures/**"]
    });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every((finding) => finding.suppressed)).toBe(true);
    expect(result.stats.suppressedFindings).toBe(result.findings.length);
    expect(result.passed).toBe(true);
  });

  it("marks config ignore paths as suppressed instead of dropping findings", async () => {
    const result = await runScan({
      fileDiffs: [
        buildFileDiff({
          filePath: "docs/examples/openai.ts",
          addedLines: ['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']
        })
      ],
      config: {
        ...TEST_CONFIG,
        ignore: {
          paths: ["docs/examples/**"]
        }
      },
      inputType: "diff"
    });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every((finding) => finding.suppressed)).toBe(true);
    expect(result.stats.suppressedFindings).toBe(result.findings.length);
    expect(result.passed).toBe(true);
  });
});
