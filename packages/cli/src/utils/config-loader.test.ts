import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "./config-loader.js";

describe("loadConfig", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const tempDir of tempDirs.splice(0)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("stops implicit config discovery at the package root", () => {
    const workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-config-"));
    tempDirs.push(workspaceDir);
    const packageDir = path.join(workspaceDir, "packages", "app");
    const nestedDir = path.join(packageDir, "src");
    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, "guarddiff.config.yaml"), 'version: "1"\npolicy:\n  failOn: low\n', "utf8");
    fs.writeFileSync(path.join(packageDir, "package.json"), '{"name":"app"}\n', "utf8");

    const loaded = loadConfig(nestedDir);

    expect(loaded.rootDir).toBe(nestedDir);
    expect(loaded.config.policy.failOn).toBe("high");
  });
});
