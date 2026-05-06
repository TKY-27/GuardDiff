import fs from "node:fs";
import path from "node:path";

import { attachRawContent, createSyntheticFileDiff, isPathIgnored, normalizeFilePath } from "@guarddiff/core";
import type { FileDiff } from "@guarddiff/core";

const MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024;

export function collectFilePaths(inputPath: string): string[] {
  const stats = fs.statSync(inputPath);
  if (stats.isFile()) {
    return [inputPath];
  }

  const output: string[] = [];
  for (const entry of fs.readdirSync(inputPath, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist") {
      continue;
    }

    const absolutePath = path.join(inputPath, entry.name);
    if (entry.isDirectory()) {
      output.push(...collectFilePaths(absolutePath));
      continue;
    }
    if (entry.isFile()) {
      output.push(absolutePath);
    }
  }

  return output;
}

export function createSyntheticDiffsFromPath(targetPath: string, cwd: string, ignorePaths: string[] = []): FileDiff[] {
  return collectFilePaths(targetPath).flatMap((absolutePath) => {
    const relativePath = normalizeFilePath(path.relative(cwd, absolutePath));
    if (isPathIgnored(relativePath, ignorePaths)) {
      return [];
    }

    const stats = fs.statSync(absolutePath);
    if (stats.size > MAX_TEXT_FILE_BYTES) {
      return [];
    }

    const buffer = fs.readFileSync(absolutePath);
    if (buffer.includes(0)) {
      return [];
    }

    const content = buffer.toString("utf8");
    return [createSyntheticFileDiff(relativePath, content)];
  });
}

export function enrichDiffsWithContent(fileDiffs: FileDiff[], rootDir: string): FileDiff[] {
  return attachRawContent(fileDiffs, rootDir, (absolutePath) => {
    if (!fs.existsSync(absolutePath)) {
      return undefined;
    }

    const buffer = fs.readFileSync(absolutePath);
    if (buffer.includes(0)) {
      return undefined;
    }

    return buffer.toString("utf8");
  });
}
