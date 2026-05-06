import path from "node:path";
import process from "node:process";

import { DiffParser, runScan, withFailOnOverride } from "@guarddiff/core";
import type { Severity } from "@guarddiff/core";

import { loadConfig, loadIgnorePatterns } from "../utils/config-loader.js";
import { createSyntheticDiffsFromPath, enrichDiffsWithContent } from "../utils/files.js";
import { getDiffAgainstBase, isInsideGitWorkTree } from "../utils/git.js";
import { renderResult } from "../utils/output.js";
import { loadConfiguredRules } from "../utils/rule-packs.js";

export interface ScanCommandOptions {
  diff?: string;
  format?: "terminal" | "json" | "sarif" | "markdown";
  failOn?: Severity;
  color?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  config?: string;
  allowRulePacks?: boolean;
}

export async function runScanCommand(scanPath: string, options: ScanCommandOptions): Promise<number> {
  const { config, rootDir } = loadConfig(process.cwd(), options.config);
  const effectiveConfig = withFailOnOverride(config, options.failOn);
  const targetPath = path.resolve(process.cwd(), scanPath);
  const ignorePaths = loadIgnorePatterns(rootDir);
  const pathIgnorePatterns = [...(effectiveConfig.ignore?.paths ?? []), ...ignorePaths];
  const rules = await loadConfiguredRules(effectiveConfig, rootDir, Boolean(options.allowRulePacks));

  const fileDiffs =
    options.diff && isInsideGitWorkTree(rootDir)
      ? enrichDiffsWithContent(new DiffParser().parse(getDiffAgainstBase(rootDir, options.diff, scanPath)), rootDir)
      : createSyntheticDiffsFromPath(targetPath, rootDir, pathIgnorePatterns);

  const result = await runScan({
    fileDiffs,
    config: effectiveConfig,
    inputType: options.diff ? "diff" : "path",
    ignorePaths,
    rules,
    version: "1.0.0"
  });

  process.stdout.write(`${renderResult(result, options.format ?? "terminal", options, rules)}\n`);
  return result.passed ? 0 : 1;
}
