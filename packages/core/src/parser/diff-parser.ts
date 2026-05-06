import parseDiff from "parse-diff";

import type { DiffHunk, DiffLine, FileDiff } from "../types/index.js";

type ParseDiffFile = {
  from?: string;
  to?: string;
  new?: boolean;
  deleted?: boolean;
  renamed?: boolean;
  binary?: boolean;
  chunks: Array<{
    content: string;
    newStart?: number;
    newLines?: number;
    changes: Array<{
      type: "add" | "del" | "normal";
      content: string;
      ln?: number;
      ln1?: number;
      ln2?: number;
    }>;
  }>;
};

export class DiffParser {
  parse(unifiedDiff: string): FileDiff[] {
    const parsed = parseDiff(unifiedDiff) as ParseDiffFile[];
    const binaryPaths = extractBinaryPaths(unifiedDiff);

    return parsed.map((file) => {
      const hunks: DiffHunk[] = file.chunks.map((chunk) => {
        const startLine = chunk.newStart ?? 0;
        const newLines = chunk.newLines ?? 0;

        return {
          header: chunk.content,
          startLine,
          endLine: Math.max(startLine, startLine + newLines - 1),
          lines: chunk.changes.map((change) => this.toDiffLine(change))
        };
      });

      return {
        filePath: normalizeDiffPath(file.to ?? file.from ?? "unknown"),
        originalPath: normalizeDiffPath(file.from ?? ""),
        isNew: file.new === true,
        isDeleted: file.deleted === true,
        isRenamed: file.renamed === true || (file.from !== file.to && Boolean(file.from) && Boolean(file.to)),
        isBinary: file.binary === true || binaryPaths.has(normalizeDiffPath(file.to ?? file.from ?? "unknown")),
        hunks
      };
    });
  }

  private toDiffLine(change: ParseDiffFile["chunks"][number]["changes"][number]): DiffLine {
    return {
      type: change.type === "add" ? "add" : change.type === "del" ? "remove" : "context",
      lineNumber: change.ln2 ?? change.ln ?? 0,
      originalLineNumber: change.ln1 ?? change.ln ?? 0,
      content: change.content.replace(/^[+\- ]/, "")
    };
  }
}

export function normalizeDiffPath(value: string): string {
  return value.replace(/^"+|"+$/g, "").replace(/^(a|b)\//, "");
}

function extractBinaryPaths(unifiedDiff: string): Set<string> {
  const paths = new Set<string>();
  for (const line of unifiedDiff.split(/\r?\n/)) {
    const match = line.match(/^Binary files (?:a\/)?(.+) and (?:b\/)?(.+) differ$/);
    if (match) {
      paths.add(normalizeDiffPath(match[1]));
      paths.add(normalizeDiffPath(match[2]));
    }
  }

  return paths;
}
