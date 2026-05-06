import fs from "node:fs";
import path from "node:path";

import { DEFAULT_CONFIG, parseGuardDiffConfig } from "@guarddiff/core";
import type { GuardDiffConfig } from "@guarddiff/core";

const CONFIG_NAME = "guarddiff.config.yaml";
const IGNORE_NAME = ".guarddiffignore";

export function loadConfig(startDir: string, explicitPath?: string): { config: GuardDiffConfig; rootDir: string } {
  if (explicitPath) {
    const resolved = path.resolve(startDir, explicitPath);
    return {
      config: parseGuardDiffConfig(fs.readFileSync(resolved, "utf8")),
      rootDir: path.dirname(resolved)
    };
  }

  const configPath = findUp(startDir, CONFIG_NAME);
  if (!configPath) {
    return { config: DEFAULT_CONFIG, rootDir: startDir };
  }

  return {
    config: parseGuardDiffConfig(fs.readFileSync(configPath, "utf8")),
    rootDir: path.dirname(configPath)
  };
}

export function loadIgnorePatterns(rootDir: string): string[] {
  const ignorePath = path.join(rootDir, IGNORE_NAME);
  if (!fs.existsSync(ignorePath)) {
    return [];
  }

  return fs
    .readFileSync(ignorePath, "utf8")
    .split(/\r?\n/);
}

function findUp(startDir: string, name: string): string | undefined {
  let current = path.resolve(startDir);

  while (true) {
    const candidate = path.join(current, name);
    if (fs.existsSync(candidate)) {
      return candidate;
    }

    if (fs.existsSync(path.join(current, "package.json"))) {
      return undefined;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}
