import { describe, expect, it } from "vitest";

import type { Finding, Rule, ScanResult } from "../types/index.js";
import { SarifReporter } from "./sarif-reporter.js";

const rule: Rule = {
  id: "secret/openai-key",
  title: "OpenAI API Key Detected",
  category: "secret",
  severity: "critical",
  defaultConfidence: "likely",
  description: "OpenAI key.",
  enabled: true,
  ruleVersion: "1.0.0",
  detect: () => []
};

function buildFinding(lineStart: number): Finding {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: "critical",
    confidence: "likely",
    category: "secret",
    filePath: "src/openai.ts",
    lineStart,
    lineEnd: lineStart,
    matchedContent: "sk-********...",
    message: "OpenAI API key detected.",
    explanation: "bad",
    remediation: "fix"
  };
}

function buildResult(finding: Finding): ScanResult {
  return {
    scannedAt: "2026-04-30T00:00:00.000Z",
    guarddiffVersion: "1.0.0",
    inputType: "diff",
    findings: [finding],
    stats: {
      filesScanned: 1,
      linesScanned: 1,
      rulesRun: 1,
      totalFindings: 1,
      suppressedFindings: 0,
      bySeverity: {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      byCategory: {
        secret: 1,
        diff: 0,
        config: 0,
        permission: 0,
        mcp: 0
      },
      durationMs: 1
    },
    passed: false,
    policyViolations: []
  };
}

describe("SarifReporter", () => {
  it("keeps fingerprints stable when a finding moves lines", () => {
    const reporter = new SarifReporter();
    const first = JSON.parse(reporter.render(buildResult(buildFinding(4)), [rule]));
    const second = JSON.parse(reporter.render(buildResult(buildFinding(12)), [rule]));

    expect(first.runs[0].results[0].partialFingerprints.primaryLocationLineHash).toBe(
      second.runs[0].results[0].partialFingerprints.primaryLocationLineHash
    );
    expect(second.runs[0].results[0].partialFingerprints.guarddiffFingerprint).toBeDefined();
    expect(second.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(12);
    expect(second.runs[0].tool.driver.rules[0].properties["security-severity"]).toBe("9.0");
    expect(second.runs[0].tool.driver.rules[0].properties.precision).toBe("high");
  });
});
