import { describe, expect, it } from "vitest";

import { parseGuardDiffConfig } from "./config-parser.js";

describe("parseGuardDiffConfig", () => {
  it("accepts configured rule packs", () => {
    const config = parseGuardDiffConfig(`version: "1"
policy:
  failOn: high
rules:
  packs:
    - "@guarddiff-community/rules-terraform"
`);

    expect(config.rules?.packs).toEqual(["@guarddiff-community/rules-terraform"]);
  });

  it("rejects invalid custom rule regex patterns during config parsing", () => {
    expect(() =>
      parseGuardDiffConfig(`version: "1"
rules:
  custom:
    - id: custom/bad-regex
      title: Bad Regex
      category: secret
      severity: high
      pattern: "[unterminated"
      message: Bad pattern
      explanation: Bad pattern
      remediation: Fix the pattern
`)
    ).toThrow("custom rule pattern must be a valid regular expression");
  });

  it("rejects custom rule regex patterns with obvious nested quantifiers", () => {
    expect(() =>
      parseGuardDiffConfig(`version: "1"
rules:
  custom:
    - id: custom/catastrophic
      title: Catastrophic
      category: secret
      severity: high
      pattern: "(a+)+$"
      message: Catastrophic pattern
      explanation: Catastrophic pattern
      remediation: Fix the pattern
`)
    ).toThrow("custom rule pattern must avoid nested quantifiers");
  });
});
