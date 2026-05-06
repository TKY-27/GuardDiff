import { parse as parseYaml } from "yaml";
import { z } from "zod";

import type { GuardDiffConfig, Severity } from "../types/index.js";

const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);
const customRulePattern = z
  .string()
  .min(1)
  .max(500)
  .refine(isValidRegexPattern, "custom rule pattern must be a valid regular expression")
  .refine(avoidsNestedQuantifiers, "custom rule pattern must avoid nested quantifiers");

export const ConfigSchema = z.object({
  version: z.literal("1"),
  policy: z.object({
    failOn: severityEnum
  }),
  rules: z
    .object({
      packs: z.array(z.string().min(1)).optional(),
      overrides: z
        .array(
          z.object({
            ruleId: z.string(),
            enabled: z.boolean().optional(),
            severity: severityEnum.optional()
          })
        )
        .optional(),
      custom: z
        .array(
          z.object({
            id: z.string().regex(/^custom\/.+/),
            title: z.string(),
            category: z.enum(["secret", "diff", "config", "permission", "mcp"]),
            severity: severityEnum,
            pattern: customRulePattern,
            message: z.string(),
            explanation: z.string(),
            remediation: z.string()
          })
        )
        .optional()
    })
    .optional(),
  ignore: z
    .object({
      paths: z.array(z.string()).optional(),
      rules: z.array(z.string()).optional()
    })
    .optional()
});

export const DEFAULT_CONFIG: GuardDiffConfig = {
  version: "1",
  policy: {
    failOn: "high"
  }
};

export function parseGuardDiffConfig(input: string): GuardDiffConfig {
  const parsed = parseYaml(input) ?? {};
  const merged = deepMerge(DEFAULT_CONFIG, parsed);
  return ConfigSchema.parse(merged);
}

export function withFailOnOverride(config: GuardDiffConfig, failOn?: Severity): GuardDiffConfig {
  if (!failOn) {
    return config;
  }

  return {
    ...config,
    policy: {
      ...config.policy,
      failOn
    }
  };
}

function deepMerge<T extends object>(base: T, next: object): T {
  const output: Record<string, unknown> = { ...(base as Record<string, unknown>) };

  for (const [key, value] of Object.entries(next)) {
    const current = output[key];
    if (isObject(current) && isObject(value)) {
      output[key] = deepMerge(current, value);
      continue;
    }
    output[key] = value;
  }

  return output as T;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidRegexPattern(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function avoidsNestedQuantifiers(pattern: string): boolean {
  const groupWithQuantifierThenRepeated = /\((?:\\.|[^()\\])*[+*{](?:\\.|[^()\\])*\)\s*[+*?{]/;
  const repeatedWildcard = /(?:\.\*){2,}|(?:\.\+){2,}/;
  return !groupWithQuantifierThenRepeated.test(pattern) && !repeatedWildcard.test(pattern);
}
