import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { buildRuleSet } from "@guarddiff/core";
import type { GuardDiffConfig, Rule, RuleCategory, Severity } from "@guarddiff/core";

const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
const categories: RuleCategory[] = ["secret", "diff", "config", "permission", "mcp"];

export async function loadConfiguredRules(config: GuardDiffConfig, rootDir: string, allowRulePacks = false): Promise<Rule[]> {
  assertRulePacksAllowed(config, allowRulePacks);
  const externalRules = allowRulePacks ? await loadRulePacks(config, rootDir) : [];
  return buildRuleSet(config, externalRules);
}

function assertRulePacksAllowed(config: GuardDiffConfig, allowRulePacks: boolean): void {
  const packNames = config.rules?.packs ?? [];
  if (allowRulePacks || packNames.length === 0) {
    return;
  }

  throw new Error(
    "External GuardDiff rule packs are disabled by default because they execute code from the scanned workspace. Re-run with --allow-rule-packs only for trusted repositories."
  );
}

export async function loadRulePacks(config: GuardDiffConfig, rootDir: string): Promise<Rule[]> {
  const packNames = config.rules?.packs ?? [];
  if (packNames.length === 0) {
    return [];
  }

  const requireFromRoot = createRequire(path.join(rootDir, "guarddiff.config.yaml"));
  const rules: Rule[] = [];

  for (const packName of packNames) {
    const resolvedPath = requireFromRoot.resolve(packName);
    const module = await import(pathToFileURL(resolvedPath).href);
    rules.push(...extractRules(module, packName));
  }

  return rules;
}

function extractRules(module: unknown, packName: string): Rule[] {
  const candidate = getExportedRules(module);
  if (!Array.isArray(candidate)) {
    throw new Error(`rule pack ${packName} must export a rules array`);
  }

  for (const rule of candidate) {
    assertRule(rule, packName);
  }

  return candidate;
}

function getExportedRules(module: unknown): unknown {
  if (!isRecord(module)) {
    return undefined;
  }

  if (Array.isArray(module.rules)) {
    return module.rules;
  }

  if (Array.isArray(module.default)) {
    return module.default;
  }

  if (isRecord(module.default) && Array.isArray(module.default.rules)) {
    return module.default.rules;
  }

  return undefined;
}

function assertRule(rule: unknown, packName: string): asserts rule is Rule {
  if (!isRecord(rule)) {
    throw new Error(`rule pack ${packName} exported a non-object rule`);
  }

  if (
    typeof rule.id !== "string" ||
    typeof rule.title !== "string" ||
    !categories.includes(rule.category as RuleCategory) ||
    !severities.includes(rule.severity as Severity) ||
    typeof rule.defaultConfidence !== "string" ||
    typeof rule.description !== "string" ||
    typeof rule.enabled !== "boolean" ||
    typeof rule.ruleVersion !== "string" ||
    typeof rule.detect !== "function"
  ) {
    throw new Error(`rule pack ${packName} exported invalid rule metadata`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
