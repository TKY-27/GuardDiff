import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runInitCommand } from "./init.js";

describe("runInitCommand", () => {
  const originalCwd = process.cwd();
  const tempDirs: string[] = [];
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

  afterEach(() => {
    process.chdir(originalCwd);
    writeSpy.mockClear();
    for (const tempDir of tempDirs.splice(0)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("generates an executable pre-commit hook without relying on repository assets", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-init-"));
    tempDirs.push(tempDir);
    fs.mkdirSync(path.join(tempDir, ".git"), { recursive: true });
    process.chdir(tempDir);

    const code = runInitCommand({ preCommit: true });
    const hookPath = path.join(tempDir, ".git", "hooks", "pre-commit");
    const hook = fs.readFileSync(hookPath, "utf8");

    expect(code).toBe(0);
    expect(hook).toContain("guarddiff staged --fail-on critical");
    expect((fs.statSync(hookPath).mode & 0o111) !== 0).toBe(true);
  });
});
