import { describe, expect, it } from "vitest";

import { filterIgnoredFileDiffs, isPathIgnored, parseGuardDiffIgnore } from "./gitignore.js";

describe("gitignore-compatible matcher", () => {
  it("supports negation with last match wins", () => {
    const rules = parseGuardDiffIgnore("secrets/**\n!secrets/fixture.env\n");

    expect(isPathIgnored("secrets/prod.env", rules)).toBe(true);
    expect(isPathIgnored("secrets/fixture.env", rules)).toBe(false);
  });

  it("supports escaped leading comment and negation markers", () => {
    const rules = parseGuardDiffIgnore("# comment\n\\#literal.env\n\\!important.env\n");

    expect(isPathIgnored("#literal.env", rules)).toBe(true);
    expect(isPathIgnored("!important.env", rules)).toBe(true);
    expect(isPathIgnored("comment", rules)).toBe(false);
  });

  it("treats anchored directory patterns as root-relative", () => {
    const rules = parseGuardDiffIgnore("/vendor/\n");

    expect(isPathIgnored("vendor/key.ts", rules)).toBe(true);
    expect(isPathIgnored("src/vendor/key.ts", rules)).toBe(false);
  });

  it("treats unanchored directory patterns as matching nested directories", () => {
    const rules = parseGuardDiffIgnore("fixtures/\n");

    expect(isPathIgnored("tests/fixtures/openai.ts", rules)).toBe(true);
  });

  it("filters file diffs before scanning", () => {
    const fileDiffs = [
      { filePath: "fixtures/leak.ts", originalPath: "fixtures/leak.ts" },
      { filePath: "src/openai.ts", originalPath: "src/openai.ts" }
    ];

    expect(filterIgnoredFileDiffs(fileDiffs, ["fixtures/"])).toEqual([{ filePath: "src/openai.ts", originalPath: "src/openai.ts" }]);
  });
});
