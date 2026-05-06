import process from "node:process";

import { DiffParser, runScan, withFailOnOverride } from "@guarddiff/core";
import type { Severity } from "@guarddiff/core";

import { loadConfig, loadIgnorePatterns } from "../utils/config-loader.js";
import { enrichDiffsWithContent } from "../utils/files.js";
import { getStagedDiff } from "../utils/git.js";
import { renderResult } from "../utils/output.js";
import { loadConfiguredRules } from "../utils/rule-packs.js";

export interface StagedCommandOptions {
  format?: "terminal" | "json" | "sarif" | "markdown";
  failOn?: Severity;
  color?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  config?: string;
  allowRulePacks?: boolean;
}

export async function runStagedCommand(options: StagedCommandOptions): Promise<number> {
  const { config, rootDir } = loadConfig(process.cwd(), options.config);
  const effectiveConfig = withFailOnOverride(config, options.failOn);
  const rules = await loadConfiguredRules(effectiveConfig, rootDir, Boolean(options.allowRulePacks));
  const diff = getStagedDiff(rootDir);
  const parser = new DiffParser();
  const fileDiffs = enrichDiffsWithContent(parser.parse(diff), rootDir);
  const result = await runScan({
    fileDiffs,
    config: effectiveConfig,
    inputType: "staged",
    ignorePaths: loadIgnorePatterns(rootDir),
    rules,
    version: "1.0.0"
  });

  process.stdout.write(`${renderResult(result, options.format ?? "terminal", options, rules)}\n`);
  return result.passed ? 0 : 1;
}
