import { createHash } from "node:crypto";

import type { Rule, ScanResult } from "../types/index.js";

export class SarifReporter {
  render(result: ScanResult, rules: Rule[]): string {
    const activeFindings = result.findings.filter((finding) => !finding.suppressed);
    const ruleMap = new Map(rules.map((rule) => [rule.id, rule]));

    return JSON.stringify(
      {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
          {
            tool: {
              driver: {
                name: "GuardDiff",
                version: result.guarddiffVersion,
                informationUri: "https://github.com/guarddiff/guarddiff",
                rules: rules.map((rule) => ({
                  id: rule.id,
                  name: rule.title,
                  defaultConfiguration: {
                    level: toSarifLevel(rule.severity)
                  },
                  helpUri: "https://github.com/guarddiff/guarddiff/blob/main/docs/rules/README.md",
                  properties: {
                    ruleVersion: rule.ruleVersion,
                    defaultSeverity: rule.defaultSeverity ?? rule.severity,
                    experimental: Boolean(rule.experimental),
                    "security-severity": toSecuritySeverity(rule.severity),
                    precision: toPrecision(rule.defaultConfidence)
                  }
                }))
              }
            },
            results: activeFindings.map((finding) => ({
              ruleId: finding.ruleId,
              level: toSarifLevel(finding.severity),
              message: {
                text: finding.message
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: finding.filePath
                    },
                    region: {
                      startLine: finding.lineStart
                    }
                  }
                }
              ],
              partialFingerprints: {
                primaryLocationLineHash: stableFingerprint([
                  finding.ruleId,
                  finding.filePath,
                  finding.matchedContent ?? finding.message
                ]),
                guarddiffFingerprint: stableFingerprint([
                  finding.ruleId,
                  finding.filePath,
                  finding.title,
                  finding.matchedContent ?? finding.message
                ])
              },
              properties: {
                category: finding.category,
                confidence: finding.confidence,
                ruleVersion: ruleMap.get(finding.ruleId)?.ruleVersion,
                experimental: Boolean(ruleMap.get(finding.ruleId)?.experimental)
              }
            }))
          }
        ]
      },
      null,
      2
    );
  }
}

function toSarifLevel(severity: Rule["severity"]): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium" || severity === "low") {
    return "warning";
  }
  return "note";
}

function toSecuritySeverity(severity: Rule["severity"]): string {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.0";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    case "info":
      return "1.0";
  }
}

function toPrecision(confidence: Rule["defaultConfidence"]): "high" | "medium" {
  return confidence === "possible" ? "medium" : "high";
}

function stableFingerprint(parts: Array<string | undefined>): string {
  return createHash("sha256")
    .update(parts.map((part) => part ?? "").join("\0"))
    .digest("hex");
}
