import type { OutputFormat } from "./output.js";
import type { RuleCategory, Severity } from "@guarddiff/core";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const RULE_CATEGORIES: RuleCategory[] = ["secret", "diff", "config", "permission", "mcp"];
const OUTPUT_FORMATS: OutputFormat[] = ["terminal", "json", "sarif", "markdown"];
const BENCHMARK_FORMATS = ["terminal", "json"] as const;

export function validateSeverity(value: string | undefined, optionName = "--fail-on"): Severity | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!SEVERITIES.includes(value as Severity)) {
    throw new Error(`${optionName} must be one of: ${SEVERITIES.join(", ")}`);
  }

  return value as Severity;
}

export function validateOutputFormat(value: string | undefined, optionName = "--format"): OutputFormat {
  const format = value ?? "terminal";
  if (!OUTPUT_FORMATS.includes(format as OutputFormat)) {
    throw new Error(`${optionName} must be one of: ${OUTPUT_FORMATS.join(", ")}`);
  }

  return format as OutputFormat;
}

export function validateRuleCategory(value: string | undefined, optionName = "--category"): RuleCategory | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!RULE_CATEGORIES.includes(value as RuleCategory)) {
    throw new Error(`${optionName} must be one of: ${RULE_CATEGORIES.join(", ")}`);
  }

  return value as RuleCategory;
}

export function validateBenchmarkFormat(value: string | undefined, optionName = "--format"): (typeof BENCHMARK_FORMATS)[number] {
  const format = value ?? "terminal";
  if (!(BENCHMARK_FORMATS as readonly string[]).includes(format)) {
    throw new Error(`${optionName} must be one of: ${BENCHMARK_FORMATS.join(", ")}`);
  }

  return format as (typeof BENCHMARK_FORMATS)[number];
}
