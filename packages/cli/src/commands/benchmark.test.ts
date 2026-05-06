import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runBenchmarkCommand } from "./benchmark.js";

describe("runBenchmarkCommand", () => {
  const tempDirs: string[] = [];
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

  afterEach(() => {
    writeSpy.mockClear();
    for (const tempDir of tempDirs.splice(0)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("passes a clean false-positive corpus", async () => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-benchmark-"));
    tempDirs.push(rootDir);
    const corpusDir = path.join(rootDir, "corpus");
    fs.mkdirSync(path.join(corpusDir, "safe"), { recursive: true });
    fs.writeFileSync(
      path.join(corpusDir, "manifest.json"),
      JSON.stringify(
        {
          name: "test-corpus",
          cases: [{ name: "safe docs", path: "safe", expectedRuleIds: [] }]
        },
        null,
        2
      ),
      "utf8"
    );
    fs.writeFileSync(path.join(corpusDir, "safe", "README.md"), "Use environment variables for API keys.\n", "utf8");

    const code = await runBenchmarkCommand(corpusDir, { format: "json" });
    const output = JSON.parse(String(writeSpy.mock.calls.at(-1)?.[0]));

    expect(code).toBe(0);
    expect(output.totals.falsePositiveFindings).toBe(0);
    expect(output.totals.passed).toBe(true);
  });
});
