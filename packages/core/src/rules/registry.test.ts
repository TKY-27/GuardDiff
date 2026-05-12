import { describe, expect, it } from "vitest";

import { buildRuleContext } from "../test-helpers.js";
import type { Rule } from "../types/index.js";
import { authRemovedRule } from "./diff/auth-removed.js";
import { buildRuleSet, builtInRules, resolveRuleMetadata } from "./registry.js";

describe("buildRuleSet metadata", () => {
  it("defaults experimental rules to info severity until overridden", () => {
    const experimentalRule: Rule = {
      id: "diff/experimental-risk",
      title: "Experimental Risk",
      category: "diff",
      severity: "high",
      defaultConfidence: "possible",
      description: "Experimental detector.",
      enabled: true,
      ruleVersion: "0.1.0",
      experimental: true,
      detect(ctx) {
        return [
          {
            ruleId: this.id,
            title: this.title,
            severity: this.severity,
            confidence: this.defaultConfidence,
            category: this.category,
            filePath: ctx.fileDiff.filePath,
            lineStart: 1,
            lineEnd: 1,
            message: "experimental",
            explanation: "experimental",
            remediation: "review"
          }
        ];
      }
    };

    const resolved = buildRuleSet({
      version: "1",
      policy: { failOn: "high" },
      rules: {
        custom: [],
        overrides: [{ ruleId: "secret/openai-key", severity: "low" }]
      }
    });

    expect(resolved.find((rule) => rule.id === "secret/openai-key")?.defaultSeverity).toBe("critical");

    const customResolved = resolveRuleMetadata(experimentalRule);
    expect(customResolved.severity).toBe("info");
    expect(customResolved.defaultSeverity).toBe("info");

    const overridden = resolveRuleMetadata(experimentalRule, { ruleId: experimentalRule.id, severity: "high" });
    expect(overridden.severity).toBe("high");
  });

  it("preserves per-finding severity unless an override is configured", () => {
    const resolved = resolveRuleMetadata(authRemovedRule);
    const findings = resolved.detect(
      buildRuleContext({
        filePath: "src/auth.ts",
        removedLines: ["requireAuth(req, res, next);"],
        addedLines: ["requireAuth(req, res, next);"]
      })
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");

    const overridden = resolveRuleMetadata(authRemovedRule, { ruleId: authRemovedRule.id, severity: "low" });
    expect(
      overridden.detect(
        buildRuleContext({
          filePath: "src/auth.ts",
          removedLines: ["requireAuth(req, res, next);"],
          addedLines: ["requireAuth(req, res, next);"]
        })
      )[0].severity
    ).toBe("low");
  });

  it("applies overrides to external rule packs", () => {
    const externalRule: Rule = {
      id: "terraform/public-s3-bucket",
      title: "Public S3 Bucket",
      category: "config",
      severity: "high",
      defaultConfidence: "likely",
      description: "Detects public S3 bucket policies.",
      enabled: true,
      ruleVersion: "0.1.0",
      detect: () => []
    };

    const rules = buildRuleSet(
      {
        version: "1",
        policy: { failOn: "high" },
        rules: {
          packs: ["@guarddiff-community/rules-terraform"],
          overrides: [{ ruleId: externalRule.id, severity: "medium" }]
        }
      },
      [externalRule]
    );

    expect(rules.find((rule) => rule.id === externalRule.id)?.severity).toBe("medium");
  });

  it("rejects duplicate rule ids from rule packs", () => {
    expect(() =>
      buildRuleSet(
        {
          version: "1",
          policy: { failOn: "high" }
        },
        [authRemovedRule]
      )
    ).toThrow("duplicate rule id: diff/auth-removed");
  });

  it("registers the dangerous package.json lifecycle script rule", () => {
    expect(builtInRules.map((rule) => rule.id)).toContain("config/package-json-dangerous-script");
  });
});
