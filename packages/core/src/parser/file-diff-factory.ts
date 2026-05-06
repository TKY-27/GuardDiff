import path from "node:path";

import type { DiffLine, FileDiff } from "../types/index.js";

export function createSyntheticFileDiff(filePath: string, content: string): FileDiff {
  const normalizedPath = normalizeFilePath(filePath);
  const lines = content.split(/\r?\n/);
  const diffLines: DiffLine[] = lines.map((line, index) => ({
    type: "add",
    lineNumber: index + 1,
    originalLineNumber: 0,
    content: line
  }));

  return {
    filePath: normalizedPath,
    originalPath: normalizedPath,
    isNew: true,
    isDeleted: false,
    isRenamed: false,
    isBinary: false,
    rawContent: content,
    hunks: [
      {
        header: `@@ -0,0 +1,${diffLines.length} @@`,
        startLine: 1,
        endLine: Math.max(1, diffLines.length),
        lines: diffLines
      }
    ]
  };
}

export function attachRawContent(fileDiffs: FileDiff[], rootDir: string, reader: (absolutePath: string) => string | undefined): FileDiff[] {
  return fileDiffs.map((fileDiff) => {
    if (fileDiff.rawContent !== undefined || fileDiff.isDeleted) {
      return fileDiff;
    }

    const absolutePath = resolveInsideRoot(rootDir, fileDiff.filePath);
    if (!absolutePath) {
      return fileDiff;
    }

    const rawContent = reader(absolutePath);

    return {
      ...fileDiff,
      rawContent
    };
  });
}

export function normalizeFilePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").split(path.sep).join("/");
}

function resolveInsideRoot(rootDir: string, filePath: string): string | undefined {
  const normalizedRoot = path.resolve(rootDir);
  const absolutePath = path.resolve(normalizedRoot, normalizeFilePath(filePath));
  const relative = path.relative(normalizedRoot, absolutePath);

  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    return absolutePath;
  }

  return undefined;
}
