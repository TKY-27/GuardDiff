#!/usr/bin/env node
import { Command } from "commander";

import { runBenchmarkCommand } from "./commands/benchmark.js";
import { runDiffCommand } from "./commands/diff.js";
import { runInitCommand } from "./commands/init.js";
import { runRulesCommand } from "./commands/rules.js";
import { runScanCommand } from "./commands/scan.js";
import { runStagedCommand } from "./commands/staged.js";

const program = new Command();

program.name("guarddiff").description("Block risky AI-generated diffs before they merge.").version("0.1.0");

program
  .command("staged")
  .option("--format <format>", "terminal | json | sarif | markdown", "terminal")
  .option("--fail-on <severity>", "critical | high | medium | low | info")
  .option("--no-color", "disable color output")
  .option("--quiet", "show findings only")
  .option("-v, --verbose", "include suppressed findings")
  .option("--config <path>", "config path")
  .option("--allow-rule-packs", "load executable external rule packs from config; use only for trusted repositories")
  .action(async (options) => {
    try {
      process.exitCode = await runStagedCommand(options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("scan")
  .argument("<path>", "scan target path")
  .option("--diff <base>", "git diff base ref")
  .option("--format <format>", "terminal | json | sarif | markdown", "terminal")
  .option("--fail-on <severity>", "critical | high | medium | low | info")
  .option("--no-color", "disable color output")
  .option("--quiet", "show findings only")
  .option("-v, --verbose", "include suppressed findings")
  .option("--config <path>", "config path")
  .option("--allow-rule-packs", "load executable external rule packs from config; use only for trusted repositories")
  .action(async (scanPath, options) => {
    try {
      process.exitCode = await runScanCommand(scanPath, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("diff")
  .option("--stdin", "read unified diff from stdin")
  .option("--file <path>", "read unified diff from file")
  .option("--format <format>", "terminal | json | sarif | markdown", "terminal")
  .option("--fail-on <severity>", "critical | high | medium | low | info")
  .option("--no-color", "disable color output")
  .option("--quiet", "show findings only")
  .option("-v, --verbose", "include suppressed findings")
  .option("--config <path>", "config path")
  .option("--allow-rule-packs", "load executable external rule packs from config; use only for trusted repositories")
  .action(async (options) => {
    try {
      process.exitCode = await runDiffCommand(options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("init")
  .option("--force", "overwrite existing files")
  .option("--pre-commit", "install the pre-commit hook")
  .option("--github-action", "generate a GitHub Actions workflow")
  .action((options) => {
    try {
      process.exitCode = runInitCommand(options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("rules")
  .option("--category <category>", "secret | diff | config | mcp")
  .option("--severity <severity>", "critical | high | medium | low | info")
  .option("--json", "json output")
  .option("--config <path>", "config path")
  .option("--allow-rule-packs", "load executable external rule packs from config; use only for trusted repositories")
  .action(async (options) => {
    try {
      process.exitCode = await runRulesCommand(options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("benchmark")
  .argument("[corpus]", "benchmark corpus directory", "benchmarks/fp-corpus")
  .option("--format <format>", "terminal | json", "terminal")
  .option("--fail-on <severity>", "critical | high | medium | low | info")
  .option("--config <path>", "config path")
  .option("--allow-rule-packs", "load executable external rule packs from config; use only for trusted repositories")
  .action(async (corpus, options) => {
    try {
      process.exitCode = await runBenchmarkCommand(corpus, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`GuardDiff error: ${message}\n`);
      process.exitCode = 2;
    }
  });

await program.parseAsync(process.argv);
