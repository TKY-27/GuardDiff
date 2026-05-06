import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runScanCommand } from "./scan.js";
import { runStagedCommand } from "./staged.js";

const originalCwd = process.cwd();

describe("git-backed command integration", () => {
  const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

  afterEach(() => {
    process.chdir(originalCwd);
    writeSpy.mockClear();
  });

  it("scans staged changes from a real git repository", async () => {
    const repoDir = createGitFixture();

    writeFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n'
    );
    git(repoDir, ["add", "src/openai.ts"]);

    process.chdir(repoDir);

    const code = await runStagedCommand({ format: "json" });

    expect(code).toBe(1);
    expect(String(writeSpy.mock.calls.at(-1)?.[0])).toContain("secret/openai-key");
  });

  it("scans git diff against a base revision from a real git repository", async () => {
    const repoDir = createGitFixture();

    writeFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n');
    git(repoDir, ["add", "src/openai.ts"]);
    git(repoDir, ["commit", "-m", "add safe openai integration"]);

    writeFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n'
    );
    git(repoDir, ["add", "src/openai.ts"]);
    git(repoDir, ["commit", "-m", "introduce leaked key"]);

    process.chdir(repoDir);

    const code = await runScanCommand("src", { diff: "HEAD~1", format: "json" });

    expect(code).toBe(1);
    expect(String(writeSpy.mock.calls.at(-1)?.[0])).toContain("secret/openai-key");
  });
});

function createGitFixture(): string {
  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-git-"));

  git(repoDir, ["init"]);
  git(repoDir, ["config", "user.name", "GuardDiff Test"]);
  git(repoDir, ["config", "user.email", "guarddiff@example.com"]);

  writeFile(repoDir, "README.md", "# GuardDiff Fixture\n");
  git(repoDir, ["add", "README.md"]);
  git(repoDir, ["commit", "-m", "initial commit"]);

  return repoDir;
}

function writeFile(repoDir: string, relativePath: string, content: string): void {
  const absolutePath = path.join(repoDir, relativePath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  fs.writeFileSync(absolutePath, content, "utf8");
}

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}
