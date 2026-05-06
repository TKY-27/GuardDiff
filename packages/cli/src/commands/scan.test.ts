import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runScanCommand } from "./scan.js";

describe("runScanCommand", () => {
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../");

  afterEach(() => {
    writeSpy.mockClear();
  });

  it("scans a directory and detects open firestore rules", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-scan-"));
    const rulesPath = path.join(tempDir, "firestore.rules");
    fs.writeFileSync(
      rulesPath,
      `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`
    );

    const code = await runScanCommand(tempDir, { format: "json" });
    expect(code).toBe(1);
    const output = writeSpy.mock.calls.at(-1)?.[0];
    expect(String(output)).toContain("config/firebase-open-rules");
  });

  it("detects insecure MCP permissions from a fixture directory", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-scan-config-"));
    const configPath = path.join(tempDir, "guarddiff.config.yaml");
    fs.writeFileSync(
      configPath,
      `version: "1"

policy:
  failOn: high
`,
      "utf8"
    );

    const code = await runScanCommand(path.join(repoRoot, "examples/insecure-mcp"), {
      format: "json",
      config: configPath
    });

    expect(code).toBe(1);
    const output = writeSpy.mock.calls.at(-1)?.[0];
    expect(String(output)).toContain("mcp/full-home-access");
    expect(String(output)).toContain("mcp/auto-exec-without-approval");
    expect(String(output)).toContain("mcp/unrestricted-network");
  });

  it("skips .guarddiffignore paths before path scans read file contents", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-scan-ignore-"));
    const configPath = path.join(tempDir, "guarddiff.config.yaml");
    fs.writeFileSync(configPath, 'version: "1"\npolicy:\n  failOn: high\n', "utf8");
    fs.writeFileSync(path.join(tempDir, ".guarddiffignore"), "fixtures/\n!fixtures/keep.ts\n", "utf8");
    fs.mkdirSync(path.join(tempDir, "fixtures"), { recursive: true });
    fs.writeFileSync(path.join(tempDir, "fixtures/leak.ts"), 'const key = "sk-abcdefghijklmnopqrstuvwxyz123456";\n', "utf8");
    fs.writeFileSync(path.join(tempDir, "fixtures/keep.ts"), 'const key = "sk-abcdefghijklmnopqrstuvwxyz123456";\n', "utf8");

    const code = await runScanCommand(path.join(tempDir, "fixtures"), { format: "json", config: configPath });
    const output = JSON.parse(String(writeSpy.mock.calls.at(-1)?.[0]));

    expect(code).toBe(1);
    expect(output.result.stats.filesScanned).toBe(1);
    expect(output.result.findings.length).toBeGreaterThan(0);
    expect(output.result.findings.some((finding: { filePath: string }) => finding.filePath === "fixtures/leak.ts")).toBe(false);
    expect(output.result.findings.some((finding: { filePath: string }) => finding.filePath === "fixtures/keep.ts")).toBe(true);
    expect(output.result.findings.every((finding: { suppressed?: boolean }) => finding.suppressed !== true)).toBe(true);
    expect(output.result.stats.suppressedFindings).toBe(0);
  });
});
