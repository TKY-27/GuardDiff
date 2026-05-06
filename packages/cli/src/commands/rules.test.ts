import process from "node:process";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runRulesCommand } from "./rules.js";

describe("runRulesCommand", () => {
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

  afterEach(() => {
    writeSpy.mockClear();
  });

  it("filters rules by category and severity in text output", async () => {
    const code = await runRulesCommand({
      category: "mcp",
      severity: "high"
    });

    expect(code).toBe(0);
    const output = writeSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(output).toContain("mcp/auto-exec-without-approval");
    expect(output).toContain("mcp/unrestricted-network");
    expect(output).not.toContain("secret/openai-key");
    expect(output).not.toContain("mcp/full-home-access");
    expect(output).not.toContain("mcp/root-access");
  });

  it("renders filtered rules as json", async () => {
    const code = await runRulesCommand({
      category: "diff",
      severity: "critical",
      json: true
    });

    expect(code).toBe(0);
    const payload = JSON.parse(writeSpy.mock.calls.at(-1)?.[0] as string) as Array<{ id: string; category: string; severity: string }>;
    expect(payload.length).toBeGreaterThan(0);
    expect(payload.every((rule) => rule.category === "diff" && rule.severity === "critical")).toBe(true);
  });

  it("keeps rules json limited to stable metadata fields", async () => {
    const code = await runRulesCommand({
      category: "secret",
      severity: "critical",
      json: true
    });

    expect(code).toBe(0);
    const payload = JSON.parse(writeSpy.mock.calls.at(-1)?.[0] as string) as Array<Record<string, unknown>>;
    expect(payload[0]).toEqual({
      id: expect.any(String),
      title: expect.any(String),
      category: "secret",
      severity: "critical",
      defaultSeverity: expect.any(String),
      defaultConfidence: expect.any(String),
      description: expect.any(String),
      enabled: expect.any(Boolean),
      ruleVersion: expect.any(String),
      experimental: expect.any(Boolean)
    });
    expect(Object.keys(payload[0]).sort()).toEqual(
      [
        "category",
        "defaultConfidence",
        "defaultSeverity",
        "description",
        "enabled",
        "experimental",
        "id",
        "ruleVersion",
        "severity",
        "title"
      ].sort()
    );
  });
});
