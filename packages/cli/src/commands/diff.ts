import fs from "node:fs";
import process from "node:process";

import { DiffParser, runScan, withFailOnOverride } from "@guarddiff/core";
import type { Severity } from "@guarddiff/core";

import { loadConfig, loadIgnorePatterns } from "../utils/config-loader.js";
import { enrichDiffsWithContent } from "../utils/files.js";
import { renderResult } from "../utils/output.js";
import { loadConfiguredRules } from "../utils/rule-packs.js";

export interface DiffCommandOptions {
  stdin?: boolean;
  file?: string;
  format?: "terminal" | "json" | "sarif" | "markdown";
  failOn?: Severity;
  color?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  config?: string;
  allowRulePacks?: boolean;
}

export async function runDiffCommand(
  options: DiffCommandOptions,
  stdinStream: AsyncIterable<string | Buffer> = process.stdin
): Promise<number> {
  const { config, rootDir } = loadConfig(process.cwd(), options.config);
  const effectiveConfig = withFailOnOverride(config, options.failOn);
  const rules = await loadConfiguredRules(effectiveConfig, rootDir, Boolean(options.allowRulePacks));
  const rawDiff = options.stdin ? await readStdin(stdinStream) : readFileDiff(options.file);
  const parser = new DiffParser();
  const fileDiffs = enrichDiffsWithContent(parser.parse(rawDiff), rootDir);
  const result = await runScan({
    fileDiffs,
    config: effectiveConfig,
    inputType: options.stdin ? "stdin" : "diff",
    ignorePaths: loadIgnorePatterns(rootDir),
    rules,
    version: "0.1.0"
  });

  process.stdout.write(`${renderResult(result, options.format ?? "terminal", options, rules)}\n`);
  return result.passed ? 0 : 1;
}

async function readStdin(stream: AsyncIterable<string | Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function readFileDiff(filePath?: string): string {
  if (!filePath) {
    throw new Error("diff command requires --stdin or --file");
  }
  return fs.readFileSync(filePath, "utf8");
}
