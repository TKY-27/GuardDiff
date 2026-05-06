import { describe, expect, it } from "vitest";

import { buildFileDiff } from "../test-helpers.js";
import { attachRawContent, createSyntheticFileDiff, normalizeFilePath } from "./file-diff-factory.js";

describe("file-diff-factory", () => {
  it("creates a synthetic added-file diff from raw content", () => {
    const fileDiff = createSyntheticFileDiff("src\\openai.ts", "const a = 1;\nconst b = 2;");

    expect(fileDiff.filePath).toBe("src/openai.ts");
    expect(fileDiff.isNew).toBe(true);
    expect(fileDiff.rawContent).toBe("const a = 1;\nconst b = 2;");
    expect(fileDiff.hunks[0].header).toBe("@@ -0,0 +1,2 @@");
    expect(fileDiff.hunks[0].lines.map((line) => line.lineNumber)).toEqual([1, 2]);
  });

  it("attaches raw content using a root-relative file path", () => {
    const [attached] = attachRawContent([buildFileDiff({ filePath: "src/app.ts" })], "/repo", (absolutePath) => {
      expect(absolutePath).toBe("/repo/src/app.ts");
      return "export const ok = true;";
    });

    expect(attached.rawContent).toBe("export const ok = true;");
  });

  it("does not read deleted files or files that already have raw content", () => {
    const alreadyAttached = buildFileDiff({ rawContent: "cached" });
    const deleted = { ...buildFileDiff({ filePath: "src/deleted.ts" }), isDeleted: true };

    const attached = attachRawContent([alreadyAttached, deleted], "/repo", () => {
      throw new Error("reader should not be called");
    });

    expect(attached[0].rawContent).toBe("cached");
    expect(attached[1].rawContent).toBeUndefined();
  });

  it("does not attach raw content for diff paths outside the scan root", () => {
    const [attached] = attachRawContent([buildFileDiff({ filePath: "../../private.env" })], "/repo", () => {
      throw new Error("reader should not be called for an escaped path");
    });

    expect(attached.rawContent).toBeUndefined();
  });

  it("normalizes platform path separators", () => {
    expect(normalizeFilePath("src\\nested\\file.ts")).toBe("src/nested/file.ts");
  });
});
