import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { runScan, withFailOnOverride } from "@guarddiff/core";
import type { GuardDiffConfig, Rule, Severity } from "@guarddiff/core";

import { loadConfig, loadIgnorePatterns } from "../utils/config-loader.js";
import { createSyntheticDiffsFromPath } from "../utils/files.js";
import { loadConfiguredRules } from "../utils/rule-packs.js";

export interface BenchmarkCommandOptions {
  format?: "terminal" | "json";
  failOn?: Severity;
  config?: string;
  allowRulePacks?: boolean;
}

interface BenchmarkManifest {
  name: string;
  cases: BenchmarkCase[];
}

interface BenchmarkCase {
  name: string;
  path: string;
  expectedRuleIds?: string[];
}

interface BenchmarkCaseResult {
  name: string;
  path: string;
  expectedRuleIds: string[];
  actualRuleIds: string[];
  falsePositiveRuleIds: string[];
  missingRuleIds: string[];
  findings: number;
  falsePositiveFindings: number;
  linesScanned: number;
}

interface BenchmarkResult {
  name: string;
  cases: BenchmarkCaseResult[];
  totals: {
    cases: number;
    findings: number;
    falsePositiveFindings: number;
    missingExpectedRules: number;
    linesScanned: number;
    falsePositiveRate: number;
    falsePositiveFindingsPerKloc: number;
    passed: boolean;
  };
}

export async function runBenchmarkCommand(corpusPath = "benchmarks/fp-corpus", options: BenchmarkCommandOptions): Promise<number> {
  const { config, rootDir } = loadConfig(process.cwd(), options.config);
  const effectiveConfig = withFailOnOverride(config, options.failOn);
  const rules = await loadConfiguredRules(effectiveConfig, rootDir, Boolean(options.allowRulePacks));
  const manifestPath = path.resolve(process.cwd(), corpusPath, "manifest.json");
  const manifest = readManifest(manifestPath);
  const result = await runBenchmark(manifest, path.dirname(manifestPath), rootDir, effectiveConfig, rules);

  if (options.format === "json") {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(renderBenchmark(result));
  }

  return result.totals.passed ? 0 : 1;
}

async function runBenchmark(
  manifest: BenchmarkManifest,
  manifestDir: string,
  rootDir: string,
  config: GuardDiffConfig,
  rules: Rule[]
): Promise<BenchmarkResult> {
  const ignorePaths = loadIgnorePatterns(rootDir);
  const pathIgnorePatterns = [...(config.ignore?.paths ?? []), ...ignorePaths];
  const cases: BenchmarkCaseResult[] = [];

  for (const benchmarkCase of manifest.cases) {
    const targetPath = path.resolve(manifestDir, benchmarkCase.path);
    const fileDiffs = createSyntheticDiffsFromPath(targetPath, rootDir, pathIgnorePatterns);
    const scanResult = await runScan({
      fileDiffs,
      config,
      inputType: "path",
      ignorePaths,
      rules,
      version: "1.0.0"
    });
    const activeFindings = scanResult.findings.filter((finding) => !finding.suppressed);
    const expectedRuleIds = benchmarkCase.expectedRuleIds ?? [];
    const expected = new Set(expectedRuleIds);
    const actualRuleIds = [...new Set(activeFindings.map((finding) => finding.ruleId))].sort();
    const falsePositiveRuleIds = [...new Set(activeFindings.filter((finding) => !expected.has(finding.ruleId)).map((finding) => finding.ruleId))].sort();
    const missingRuleIds = expectedRuleIds.filter((ruleId) => !actualRuleIds.includes(ruleId));

    cases.push({
      name: benchmarkCase.name,
      path: benchmarkCase.path,
      expectedRuleIds,
      actualRuleIds,
      falsePositiveRuleIds,
      missingRuleIds,
      findings: activeFindings.length,
      falsePositiveFindings: activeFindings.filter((finding) => !expected.has(finding.ruleId)).length,
      linesScanned: scanResult.stats.linesScanned
    });
  }

  const findings = cases.reduce((sum, result) => sum + result.findings, 0);
  const falsePositiveFindings = cases.reduce((sum, result) => sum + result.falsePositiveFindings, 0);
  const missingExpectedRules = cases.reduce((sum, result) => sum + result.missingRuleIds.length, 0);
  const linesScanned = cases.reduce((sum, result) => sum + result.linesScanned, 0);

  return {
    name: manifest.name,
    cases,
    totals: {
      cases: cases.length,
      findings,
      falsePositiveFindings,
      missingExpectedRules,
      linesScanned,
      falsePositiveRate: findings === 0 ? 0 : falsePositiveFindings / findings,
      falsePositiveFindingsPerKloc: linesScanned === 0 ? 0 : (falsePositiveFindings / linesScanned) * 1000,
      passed: falsePositiveFindings === 0 && missingExpectedRules === 0
    }
  };
}

function readManifest(manifestPath: string): BenchmarkManifest {
  const parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as unknown;
  if (!isRecord(parsed) || typeof parsed.name !== "string" || !Array.isArray(parsed.cases)) {
    throw new Error(`invalid benchmark manifest: ${manifestPath}`);
  }

  for (const entry of parsed.cases) {
    if (!isRecord(entry) || typeof entry.name !== "string" || typeof entry.path !== "string") {
      throw new Error(`invalid benchmark case in ${manifestPath}`);
    }
    if (entry.expectedRuleIds !== undefined && !Array.isArray(entry.expectedRuleIds)) {
      throw new Error(`invalid expectedRuleIds for benchmark case ${entry.name}`);
    }
  }

  return {
    name: parsed.name,
    cases: parsed.cases as BenchmarkCase[]
  };
}

function renderBenchmark(result: BenchmarkResult): string {
  const lines = [
    `GuardDiff benchmark: ${result.name}`,
    `Cases: ${result.totals.cases}`,
    `Findings: ${result.totals.findings}`,
    `False positives: ${result.totals.falsePositiveFindings}`,
    `Missing expected rules: ${result.totals.missingExpectedRules}`,
    `FP rate: ${(result.totals.falsePositiveRate * 100).toFixed(2)}%`,
    `FP/KLOC: ${result.totals.falsePositiveFindingsPerKloc.toFixed(2)}`
  ];

  for (const benchmarkCase of result.cases.filter((entry) => entry.falsePositiveFindings > 0 || entry.missingRuleIds.length > 0)) {
    lines.push(
      "",
      `${benchmarkCase.name}: ${benchmarkCase.path}`,
      `  false positives: ${benchmarkCase.falsePositiveRuleIds.join(", ") || "none"}`,
      `  missing expected: ${benchmarkCase.missingRuleIds.join(", ") || "none"}`
    );
  }

  lines.push("");
  return `${lines.join("\n")}\n`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
