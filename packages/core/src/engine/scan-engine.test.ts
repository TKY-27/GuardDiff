import { describe, expect, it, vi } from "vitest";

import { buildFileDiff, TEST_CONFIG } from "../test-helpers.js";
import type { Finding, Rule } from "../types/index.js";
import { ScanEngine } from "./scan-engine.js";

function buildRule(overrides: Partial<Rule> = {}): Rule {
  const finding: Finding = {
    ruleId: "diff/example",
    title: "Example Rule",
    severity: "high",
    confidence: "likely",
    category: "diff",
    filePath: "src/example.ts",
    lineStart: 1,
    lineEnd: 1,
    message: "boom",
    explanation: "bad",
    remediation: "fix"
  };

  return {
    id: "diff/example",
    title: "Example Rule",
    category: "diff",
    severity: "high",
    defaultConfidence: "likely",
    description: "example",
    enabled: true,
    ruleVersion: "0.1.0",
    detect: vi.fn(() => [finding]),
    ...overrides
  };
}

describe("ScanEngine", () => {
  it("runs enabled rules and returns their findings", async () => {
    const rule = buildRule();
    const findings = await new ScanEngine([rule], TEST_CONFIG).scan([buildFileDiff({ addedLines: ["const ok = true;"] })]);

    expect(findings).toHaveLength(1);
    expect(rule.detect).toHaveBeenCalledOnce();
  });

  it("skips disabled rules", async () => {
    const rule = buildRule({ enabled: false });
    const findings = await new ScanEngine([rule], TEST_CONFIG).scan([buildFileDiff({ addedLines: ["const ok = true;"] })]);

    expect(findings).toHaveLength(0);
    expect(rule.detect).not.toHaveBeenCalled();
  });

  it("runs only env-committed for binary files", async () => {
    const skippedRule = buildRule({ id: "secret/openai-key" });
    const binaryRule = buildRule({ id: "config/env-committed" });
    const binaryDiff = {
      ...buildFileDiff({ filePath: ".env", addedLines: ["SECRET=value"] }),
      isBinary: true
    };

    const findings = await new ScanEngine([skippedRule, binaryRule], TEST_CONFIG).scan([binaryDiff]);

    expect(findings).toHaveLength(1);
    expect(skippedRule.detect).not.toHaveBeenCalled();
    expect(binaryRule.detect).toHaveBeenCalledOnce();
  });

  it("isolates rule failures so other rules can still report", async () => {
    const brokenRule = buildRule({
      id: "diff/broken",
      detect: vi.fn(() => {
        throw new Error("bad rule");
      })
    });
    const workingRule = buildRule({ id: "diff/working" });

    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const findings = await new ScanEngine([brokenRule, workingRule], TEST_CONFIG).scan([
        buildFileDiff({ addedLines: ["const ok = true;"] })
      ]);

      expect(findings).toHaveLength(1);
      expect(errorSpy).toHaveBeenCalledWith("Rule diff/broken failed: bad rule");
    } finally {
      errorSpy.mockRestore();
    }
  });
});
