import { describe, expect, it } from "vitest";

import { DiffParser, normalizeDiffPath } from "./diff-parser.js";

describe("DiffParser", () => {
  it("parses added and removed lines", () => {
    const diff = [
      "diff --git a/src/auth.ts b/src/auth.ts",
      "--- a/src/auth.ts",
      "+++ b/src/auth.ts",
      "@@ -1,2 +1,2 @@",
      "-requireAuth(req, res, next);",
      "+// requireAuth moved",
      " const ok = true;"
    ].join("\n");

    const [file] = new DiffParser().parse(diff);
    expect(file.filePath).toBe("src/auth.ts");
    expect(file.hunks[0].lines).toHaveLength(3);
    expect(file.hunks[0].lines[0].type).toBe("remove");
    expect(file.hunks[0].lines[1].type).toBe("add");
  });

  it("parses renamed files", () => {
    const diff = [
      "diff --git a/src/old.ts b/src/new.ts",
      "similarity index 95%",
      "rename from src/old.ts",
      "rename to src/new.ts",
      "--- a/src/old.ts",
      "+++ b/src/new.ts",
      "@@ -1 +1 @@",
      "-export const oldName = true;",
      "+export const newName = true;"
    ].join("\n");

    const [file] = new DiffParser().parse(diff);
    expect(file.filePath).toBe("src/new.ts");
    expect(file.originalPath).toBe("src/old.ts");
    expect(file.isRenamed).toBe(true);
  });

  it("parses binary files without hunks", () => {
    const diff = ["diff --git a/public/logo.png b/public/logo.png", "Binary files a/public/logo.png and b/public/logo.png differ"].join("\n");

    const [file] = new DiffParser().parse(diff);
    expect(file.filePath).toBe("public/logo.png");
    expect(file.isBinary).toBe(true);
    expect(file.hunks).toHaveLength(0);
  });

  it("normalizes quoted git paths", () => {
    expect(normalizeDiffPath('"b/src/space file.ts"')).toBe("src/space file.ts");
  });
});
