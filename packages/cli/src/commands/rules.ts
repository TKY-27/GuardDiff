import process from "node:process";

import type { Rule } from "@guarddiff/core";

import { loadConfig } from "../utils/config-loader.js";
import { loadConfiguredRules } from "../utils/rule-packs.js";

export interface RulesCommandOptions {
  category?: string;
  severity?: string;
  json?: boolean;
  config?: string;
  allowRulePacks?: boolean;
}

export async function runRulesCommand(options: RulesCommandOptions): Promise<number> {
  const { config, rootDir } = loadConfig(process.cwd(), options.config);
  const rules = (await loadConfiguredRules(config, rootDir, Boolean(options.allowRulePacks))).filter(
    (rule) => (!options.category || rule.category === options.category) && (!options.severity || rule.severity === options.severity)
  );

  if (options.json) {
    process.stdout.write(`${JSON.stringify(rules.map(serializeRuleMetadata), null, 2)}\n`);
    return 0;
  }

  for (const rule of rules) {
    const experimental = rule.experimental ? "\texperimental" : "";
    process.stdout.write(
      `${rule.id}\t${rule.severity}\tdefault:${rule.defaultSeverity ?? rule.severity}\tv${rule.ruleVersion}${experimental}\t${rule.title}\n`
    );
  }
  return 0;
}

function serializeRuleMetadata(rule: Rule): Record<string, unknown> {
  return {
    id: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    defaultSeverity: rule.defaultSeverity ?? rule.severity,
    defaultConfidence: rule.defaultConfidence,
    description: rule.description,
    enabled: rule.enabled,
    ruleVersion: rule.ruleVersion,
    experimental: Boolean(rule.experimental)
  };
}
