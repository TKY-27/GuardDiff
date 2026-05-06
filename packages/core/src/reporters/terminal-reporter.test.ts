import { describe, expect, it } from "vitest";

import type { ScanResult } from "../types/index.js";
import { TerminalReporter } from "./terminal-reporter.js";

function buildResult(): ScanResult {
  return {
    scannedAt: new Date().toISOString(),
    guarddiffVersion: "1.0.0",
    inputType: "staged",
    passed: false,
    policyViolations: ["[CRITICAL] secret/openai-key: boom (src/openai.ts:1)"],
    findings: [
      {
        ruleId: "secret/openai-key",
        title: "OpenAI API Key Detected",
        severity: "critical",
        confidence: "likely",
        category: "secret",
        filePath: "src/openai.ts",
        lineStart: 1,
        lineEnd: 1,
        matchedContent: "sk-********...",
        message: "boom",
        explanation: "bad",
        remediation: "fix"
      }
    ],
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
      durationMs: 10
    }
  };
}

describe("TerminalReporter", () => {
  it("renders full output by default", () => {
    const rendered = new TerminalReporter().render(buildResult(), { color: false });

    expect(rendered).toContain("GuardDiff v1.0.0");
    expect(rendered).toContain("Summary:");
    expect(rendered).toContain("CRITICAL  secret/openai-key");
    expect(rendered).toContain("なぜ危険か:");
    expect(rendered).toContain("修正方法:");
    expect(rendered).toContain("To suppress: add  # guarddiff-ignore: secret/openai-key  to the line");
  });

  it("renders findings only in quiet mode", () => {
    const rendered = new TerminalReporter().render(buildResult(), { quiet: true, color: false });

    expect(rendered).toContain("CRITICAL  secret/openai-key");
    expect(rendered).not.toContain("GuardDiff v1.0.0");
    expect(rendered).not.toContain("Summary:");
  });

  it("keeps quiet mode color controllable", () => {
    const reporter = new TerminalReporter();
    const noColor = process.env.NO_COLOR;
    delete process.env.NO_COLOR;

    try {
      const colored = reporter.render(buildResult(), { quiet: true, color: true });
      const plain = reporter.render(buildResult(), { quiet: true, color: false });

      expect(colored).toContain("\u001B[31m");
      expect(plain).not.toContain("\u001B[31m");
    } finally {
      if (noColor === undefined) {
        delete process.env.NO_COLOR;
      } else {
        process.env.NO_COLOR = noColor;
      }
    }
  });

  it("wraps long finding text to the configured width", () => {
    const result = buildResult();
    result.findings[0].explanation = "This sentence is deliberately long so the terminal reporter has to wrap it across multiple lines cleanly.";

    const rendered = new TerminalReporter().render(result, { color: false, width: 54 });

    expect(rendered).toContain("This sentence is deliberately long so the terminal");
    expect(rendered).toContain("reporter has to wrap it across multiple lines");
    expect(rendered).toContain("cleanly.");
  });

  it("marks suppressed findings as shown in verbose mode", () => {
    const result = buildResult();
    result.stats.suppressedFindings = 1;
    result.findings.push({
      ...result.findings[0],
      suppressed: true,
      suppressReason: "ignore_file_path_ignored"
    });

    const rendered = new TerminalReporter().render(result, { color: false, verbose: true });

    expect(rendered).toContain("1 suppressed finding shown because --verbose is enabled");
    expect(rendered).toContain("suppressed by ignore file path ignored");
  });

  it("adds ANSI color by default and disables it with no-color options", () => {
    const reporter = new TerminalReporter();
    const noColor = process.env.NO_COLOR;
    delete process.env.NO_COLOR;

    try {
      expect(reporter.render(buildResult())).toContain("\u001B[31m");
      expect(reporter.render(buildResult(), { color: false })).not.toContain("\u001B[31m");
    } finally {
      if (noColor === undefined) {
        delete process.env.NO_COLOR;
      } else {
        process.env.NO_COLOR = noColor;
      }
    }
  });
});
