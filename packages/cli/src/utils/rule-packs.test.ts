import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { loadConfiguredRules } from "./rule-packs.js";

describe("loadConfiguredRules", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const tempDir of tempDirs.splice(0)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("blocks external rule packs by default", async () => {
    await expect(
      loadConfiguredRules(
        {
          version: "1",
          policy: { failOn: "high" },
          rules: {
            packs: ["./rules-pack.mjs"]
          }
        },
        "/repo"
      )
    ).rejects.toThrow("External GuardDiff rule packs are disabled by default");
  });

  it("loads external rule packs relative to the config root when explicitly allowed", async () => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-pack-"));
    tempDirs.push(rootDir);
    fs.writeFileSync(
      path.join(rootDir, "rules-pack.mjs"),
      `export const rules = [{
  id: "terraform/public-s3-bucket",
  title: "Public S3 Bucket",
  category: "config",
  severity: "high",
  defaultConfidence: "likely",
  description: "Detects public S3 bucket policies.",
  enabled: true,
  ruleVersion: "1.0.0",
  detect() { return []; }
}];\n`,
      "utf8"
    );

    const rules = await loadConfiguredRules(
      {
        version: "1",
        policy: { failOn: "high" },
        rules: {
          packs: ["./rules-pack.mjs"],
          overrides: [{ ruleId: "terraform/public-s3-bucket", severity: "medium" }]
        }
      },
      rootDir,
      true
    );

    expect(rules.find((rule) => rule.id === "terraform/public-s3-bucket")?.severity).toBe("medium");
  });

  it("rejects allowed rule packs without a rules export", async () => {
    const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "guarddiff-pack-invalid-"));
    tempDirs.push(rootDir);
    fs.writeFileSync(path.join(rootDir, "invalid-pack.mjs"), "export const nope = [];\n", "utf8");

    await expect(
      loadConfiguredRules(
        {
          version: "1",
          policy: { failOn: "high" },
          rules: {
            packs: ["./invalid-pack.mjs"]
          }
        },
        rootDir,
        true
      )
    ).rejects.toThrow("rule pack ./invalid-pack.mjs must export a rules array");
  });
});
