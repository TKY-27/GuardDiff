import type { DiffLine, FileDiff, GuardDiffConfig, RuleContext } from "./types/index.js";

export interface BuildRuleContextOptions {
  filePath?: string;
  addedLines?: string[];
  removedLines?: string[];
  contextBefore?: string[];
  contextAfter?: string[];
  rawContent?: string;
  isNew?: boolean;
  isDeleted?: boolean;
  isRenamed?: boolean;
  isBinary?: boolean;
}

export const TEST_CONFIG: GuardDiffConfig = {
  version: "1",
  policy: {
    failOn: "high"
  }
};

export function buildRuleContext(options: BuildRuleContextOptions = {}): RuleContext {
  return {
    fileDiff: buildFileDiff(options),
    config: TEST_CONFIG
  };
}

export function buildFileDiff(options: BuildRuleContextOptions = {}): FileDiff {
  const {
    filePath = "src/example.ts",
    addedLines = [],
    removedLines = [],
    contextBefore = [],
    contextAfter = [],
    rawContent,
    isNew = false,
    isDeleted = false,
    isRenamed = false,
    isBinary = false
  } = options;

  let nextLineNumber = 1;
  let nextOriginalLineNumber = 1;
  const lines: DiffLine[] = [];

  for (const content of contextBefore) {
    lines.push({
      type: "context",
      lineNumber: nextLineNumber++,
      originalLineNumber: nextOriginalLineNumber++,
      content
    });
  }

  for (const content of removedLines) {
    lines.push({
      type: "remove",
      lineNumber: 0,
      originalLineNumber: nextOriginalLineNumber++,
      content
    });
  }

  for (const content of addedLines) {
    lines.push({
      type: "add",
      lineNumber: nextLineNumber++,
      originalLineNumber: 0,
      content
    });
  }

  for (const content of contextAfter) {
    lines.push({
      type: "context",
      lineNumber: nextLineNumber++,
      originalLineNumber: nextOriginalLineNumber++,
      content
    });
  }

  const originalLineCount = contextBefore.length + removedLines.length + contextAfter.length;
  const newLineCount = contextBefore.length + addedLines.length + contextAfter.length;

  return {
    filePath,
    originalPath: filePath,
    isNew,
    isDeleted,
    isRenamed,
    isBinary,
    rawContent,
    hunks: [
      {
        header: `@@ -1,${Math.max(1, originalLineCount)} +1,${Math.max(1, newLineCount)} @@`,
        startLine: 1,
        endLine: Math.max(1, newLineCount),
        lines
      }
    ]
  };
}
