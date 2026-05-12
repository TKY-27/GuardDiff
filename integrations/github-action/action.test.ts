import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runAction } from "./src/lib.ts";

describe("github action integration", () => {
  const tempDirs: string[] = [];
  const originalCwd = process.cwd();
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.restoreAllMocks();
    process.chdir(originalCwd);
    process.env = { ...originalEnv };
    process.env.INPUT_RULES_UPDATE_CHECK = "false";
    process.exitCode = 0;
  });

  afterEach(() => {
    process.chdir(originalCwd);
    process.env = { ...originalEnv };
    process.exitCode = 0;

    while (tempDirs.length > 0) {
      const tempDir = tempDirs.pop();
      if (tempDir && fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    }
  });

  it("writes outputs and SARIF for failing findings", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 42, base: { sha: baseSha } } }), "utf8");

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_SARIF = "true";
    process.env.INPUT_SARIF_FILE = "reports/guarddiff.sarif";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    const outputs = fs.readFileSync(outputPath, "utf8");
    expect(outputs).toContain("findings-count=2");
    expect(outputs).toContain("critical-count=1");
    expect(outputs).toContain("passed=false");
    expect(fs.existsSync(path.join(repoDir, "reports/guarddiff.sarif"))).toBe(true);
  });

  it("creates a PR comment when enabled", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 7, base: { sha: baseSha } } }), "utf8");

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);

      if (init?.method === "GET" && url.includes("/repos/acme/guarddiff/issues/7/comments")) {
        return new Response("[]", {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      if (init?.method === "POST" && url.includes("/repos/acme/guarddiff/issues/7/comments")) {
        return new Response(JSON.stringify({ id: 1, body: init?.body }), {
          status: 201,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    process.chdir(repoDir);
    process.env.GITHUB_API_URL = "https://api.example.test";
    process.env.GITHUB_REPOSITORY = "acme/guarddiff";
    process.env.GITHUB_TOKEN = "test-token";
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "true";
    process.env.INPUT_SARIF = "false";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).toContain("guarddiff-report");
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).toContain("secret/openai-key");
  });

  it("adds rule update notices to PR comments when update checks are enabled", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 8, base: { sha: baseSha } } }), "utf8");

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);

      if (url === "https://registry.example.test/rules.json") {
        return new Response(
          JSON.stringify({
            rules: [
              {
                id: "secret/openai-key",
                ruleVersion: "1.1.0",
                title: "OpenAI API Key Detected",
                summary: "Improved OpenAI project key coverage.",
                docsUrl: "https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md"
              }
            ]
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        );
      }

      if (init?.method === "GET" && url.includes("/repos/acme/guarddiff/issues/8/comments")) {
        return new Response("[]", {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      if (init?.method === "POST" && url.includes("/repos/acme/guarddiff/issues/8/comments")) {
        return new Response(JSON.stringify({ id: 1, body: init?.body }), {
          status: 201,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    process.chdir(repoDir);
    process.env.GITHUB_API_URL = "https://api.example.test";
    process.env.GITHUB_REPOSITORY = "acme/guarddiff";
    process.env.GITHUB_TOKEN = "test-token";
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "true";
    process.env.INPUT_SARIF = "false";
    process.env.INPUT_FAIL_ON = "high";
    process.env.INPUT_RULES_UPDATE_CHECK = "true";
    process.env.INPUT_RULES_REGISTRY_URL = "https://registry.example.test/rules.json";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fs.readFileSync(outputPath, "utf8")).toContain("rule-update-count=1");
    expect(String(fetchMock.mock.calls[2]?.[1]?.body)).toContain("Rule Updates Available");
    expect(String(fetchMock.mock.calls[2]?.[1]?.body)).toContain("Improved OpenAI project key coverage.");
  });

  it("includes remediation and docs in workflow annotations", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 10, base: { sha: baseSha } } }), "utf8");

    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_SARIF = "false";
    process.env.INPUT_FAIL_ON = "high";
    process.env.INPUT_ANNOTATIONS = "true";

    await runAction();

    const output = stdoutSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(output).toContain("::error file=src/openai.ts");
    expect(output).toContain("Remediation:");
    expect(output).toContain("Docs: https://github.com/TKY-27/GuardDiff/blob/main/docs/rules/README.md");
  });

  it("updates an existing GuardDiff PR comment instead of posting a new one", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 9, base: { sha: baseSha } } }), "utf8");

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);

      if (init?.method === "GET" && url.includes("/repos/acme/guarddiff/issues/9/comments")) {
        return new Response(JSON.stringify([{ id: 99, body: "<!-- guarddiff-report -->\n\nold" }]), {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      if (init?.method === "PATCH" && url.includes("/repos/acme/guarddiff/issues/comments/99")) {
        return new Response(JSON.stringify({ id: 99, body: init?.body }), {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        });
      }

      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    process.chdir(repoDir);
    process.env.GITHUB_API_URL = "https://api.example.test";
    process.env.GITHUB_REPOSITORY = "acme/guarddiff";
    process.env.GITHUB_TOKEN = "test-token";
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "true";
    process.env.INPUT_SARIF = "false";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[1]?.method).toBe("PATCH");
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).toContain("secret/openai-key");
  });

  it("does not post a PR comment when post-comment is false", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 11, base: { sha: baseSha } } }), "utf8");

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    process.chdir(repoDir);
    process.env.GITHUB_API_URL = "https://api.example.test";
    process.env.GITHUB_REPOSITORY = "acme/guarddiff";
    process.env.GITHUB_TOKEN = "test-token";
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_SARIF = "false";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("blocks external rule packs by default in the GitHub Action", async () => {
    const repoDir = createGitFixture(tempDirs);
    writeFile(
      repoDir,
      "guarddiff.config.yaml",
      'version: "1"\nrules:\n  packs:\n    - "./rules/custom.mjs"\n'
    );
    git(repoDir, ["add", "guarddiff.config.yaml"]);
    git(repoDir, ["commit", "-m", "config"]);
    const baseSha = commitFile(repoDir, "src/app.ts", "export const ok = true;\n", "safe");
    commitFile(repoDir, "src/app.ts", "export const ok = false;\n", "changed");

    const eventPath = path.join(repoDir, "event.json");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 12, base: { sha: baseSha } } }), "utf8");

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.INPUT_POST_COMMENT = "false";

    await expect(runAction()).rejects.toThrow("External GuardDiff rule packs are disabled");
  });

  it("uses base-ref config so pull requests cannot disable introduced findings", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    writeFile(
      repoDir,
      "guarddiff.config.yaml",
      'version: "1"\nrules:\n  overrides:\n    - ruleId: secret/openai-key\n      enabled: false\n'
    );
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" });\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 14, base: { sha: baseSha } } }), "utf8");

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fs.readFileSync(outputPath, "utf8")).toContain("critical-count=1");
  });

  it("does not honor inline suppressions by default in pull request diffs", async () => {
    const repoDir = createGitFixture(tempDirs);
    const baseSha = commitFile(repoDir, "src/openai.ts", 'export const apiKey = process.env.OPENAI_API_KEY;\n', "safe");
    commitFile(
      repoDir,
      "src/openai.ts",
      'export const client = new OpenAI({ apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" }); // guarddiff-ignore: all\n',
      "unsafe"
    );

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 15, base: { sha: baseSha } } }), "utf8");

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_FAIL_ON = "high";

    await runAction();

    expect(process.exitCode).toBe(1);
    expect(fs.readFileSync(outputPath, "utf8")).toContain("critical-count=1");
  });

  it("loads external rule packs when explicitly allowed", async () => {
    const repoDir = createGitFixture(tempDirs);
    writeFile(
      repoDir,
      "guarddiff.config.yaml",
      'version: "1"\nrules:\n  packs:\n    - "./rules/custom.mjs"\n'
    );
    writeFile(
      repoDir,
      "rules/custom.mjs",
      `export const rules = [{
  id: "custom/noop",
  title: "Noop",
  category: "diff",
  severity: "info",
  defaultConfidence: "possible",
  description: "Test-only external rule pack.",
  enabled: true,
  ruleVersion: "0.1.0",
  detect: () => []
}];
`
    );
    git(repoDir, ["add", "guarddiff.config.yaml", "rules/custom.mjs"]);
    git(repoDir, ["commit", "-m", "config"]);
    const baseSha = commitFile(repoDir, "src/app.ts", "export const ok = true;\n", "safe");
    commitFile(repoDir, "src/app.ts", "export const ok = false;\n", "changed");

    const eventPath = path.join(repoDir, "event.json");
    const outputPath = path.join(repoDir, "github-output.txt");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 13, base: { sha: baseSha } } }), "utf8");

    process.chdir(repoDir);
    process.env.GITHUB_EVENT_PATH = eventPath;
    process.env.GITHUB_OUTPUT = outputPath;
    process.env.INPUT_POST_COMMENT = "false";
    process.env.INPUT_ALLOW_RULE_PACKS = "true";

    await runAction();

    expect(process.exitCode).toBe(0);
    expect(fs.readFileSync(outputPath, "utf8")).toContain("passed=true");
  });

  it("documents the real PR smoke workflow permissions and SARIF upload", () => {
    const workflow = fs.readFileSync(path.join(originalCwd, ".github/workflows/guarddiff-smoke.yml"), "utf8");

    expect(workflow).toContain("pull-requests: write");
    expect(workflow).toContain("security-events: write");
    expect(workflow).toContain("sarif: true");
    expect(workflow).toContain("github/codeql-action/upload-sarif@0daab03d71ff584ef619d027a3fd9146679c5d84");
    expect(workflow).toContain("sarif_file: guarddiff-results.sarif");
  });
});

function createGitFixture(tempDirs: string[]): string {
  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-action-"));
  tempDirs.push(repoDir);

  git(repoDir, ["init"]);
  git(repoDir, ["config", "user.name", "GuardDiff Test"]);
  git(repoDir, ["config", "user.email", "guarddiff@example.com"]);
  writeFile(repoDir, "README.md", "# fixture\n");
  git(repoDir, ["add", "README.md"]);
  git(repoDir, ["commit", "-m", "initial"]);

  return repoDir;
}

function commitFile(repoDir: string, relativePath: string, content: string, message: string): string {
  writeFile(repoDir, relativePath, content);
  git(repoDir, ["add", relativePath]);
  git(repoDir, ["commit", "-m", message]);
  return git(repoDir, ["rev-parse", "HEAD"]).trim();
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
