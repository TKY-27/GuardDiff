import { describe, expect, it } from "vitest";

import { PolicyEvaluator } from "./policy-evaluator.js";

describe("PolicyEvaluator", () => {
  it("fails when a finding meets the configured threshold", () => {
    const evaluation = new PolicyEvaluator().evaluate(
      [
        {
          ruleId: "secret/openai-key",
          title: "OpenAI API Key Detected",
          severity: "critical",
          confidence: "likely",
          category: "secret",
          filePath: "src/index.ts",
          lineStart: 4,
          lineEnd: 4,
          message: "boom",
          explanation: "bad",
          remediation: "fix"
        }
      ],
      { failOn: "high" }
    );

    expect(evaluation.passed).toBe(false);
    expect(evaluation.violations).toHaveLength(1);
  });
});
