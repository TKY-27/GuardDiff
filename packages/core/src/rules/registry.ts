import type { GuardDiffConfig, Rule, RuleOverride, Severity } from "../types/index.js";
import { buildCustomRules } from "./custom-rule.js";
import { envPlaintextSecretRule } from "./config/env-plaintext-secret.js";
import { firebaseOpenRulesRule } from "./config/firebase-open-rules.js";
import { firestoreOpenReadRule } from "./config/firestore-open-read.js";
import { envCommittedRule } from "./config/env-committed.js";
import { packageJsonDangerousScriptRule } from "./config/package-json-dangerous-script.js";
import { authBypassRule } from "./diff/auth-bypass.js";
import { authRemovedRule } from "./diff/auth-removed.js";
import { corsWildcardRule } from "./diff/cors-wildcard.js";
import { dangerousShellRule } from "./diff/dangerous-shell.js";
import { debugEndpointRule } from "./diff/debug-endpoint.js";
import { evalInjectionRule } from "./diff/eval-injection.js";
import { sensitiveLogRule } from "./diff/sensitive-log.js";
import { mcpAutoExecWithoutApprovalRule } from "./mcp/auto-exec-without-approval.js";
import { mcpFullHomeAccessRule } from "./mcp/full-home-access.js";
import { mcpRootAccessRule } from "./mcp/root-access.js";
import { mcpUnrestrictedNetworkRule } from "./mcp/unrestricted-network.js";
import { anthropicKeyRule } from "./secret/anthropic-key.js";
import { awsAccessKeyRule } from "./secret/aws-access-key.js";
import { awsSecretKeyRule } from "./secret/aws-secret-key.js";
import { firebaseConfigRule } from "./secret/firebase-config.js";
import { githubTokenRule } from "./secret/github-token.js";
import { highEntropyStringRule } from "./secret/high-entropy-string.js";
import { openaiKeyRule } from "./secret/openai-key.js";
import { privateKeyRule } from "./secret/private-key.js";
import { stripeKeyRule } from "./secret/stripe-key.js";
import { supabaseKeyRule } from "./secret/supabase-key.js";

export const builtInRules: Rule[] = [
  anthropicKeyRule,
  awsAccessKeyRule,
  awsSecretKeyRule,
  firebaseConfigRule,
  githubTokenRule,
  openaiKeyRule,
  privateKeyRule,
  stripeKeyRule,
  supabaseKeyRule,
  highEntropyStringRule,
  authBypassRule,
  authRemovedRule,
  corsWildcardRule,
  debugEndpointRule,
  dangerousShellRule,
  evalInjectionRule,
  sensitiveLogRule,
  mcpFullHomeAccessRule,
  mcpRootAccessRule,
  mcpAutoExecWithoutApprovalRule,
  mcpUnrestrictedNetworkRule,
  firebaseOpenRulesRule,
  firestoreOpenReadRule,
  envPlaintextSecretRule,
  envCommittedRule,
  packageJsonDangerousScriptRule
];

export function buildRuleSet(config: GuardDiffConfig, externalRules: Rule[] = []): Rule[] {
  const overrides = new Map((config.rules?.overrides ?? []).map((override) => [override.ruleId, override]));
  const customRules = buildCustomRules(config);
  const rules = [...builtInRules, ...externalRules, ...customRules];

  assertUniqueRuleIds(rules);

  return rules.map((rule) => resolveRuleMetadata(rule, overrides.get(rule.id)));
}

export function resolveRuleMetadata(rule: Rule, override?: RuleOverride): Rule {
  const defaultSeverity = getDefaultSeverity(rule);
  const severity = override?.severity ?? defaultSeverity;
  return {
    ...rule,
    defaultSeverity,
    enabled: override?.enabled ?? rule.enabled,
    severity,
    detect(ctx) {
      return rule.detect(ctx).map((finding) => ({
        ...finding,
        severity: override?.severity ?? (rule.experimental ? defaultSeverity : finding.severity)
      }));
    }
  };
}

function getDefaultSeverity(rule: Rule): Severity {
  return rule.defaultSeverity ?? (rule.experimental ? "info" : rule.severity);
}

function assertUniqueRuleIds(rules: Rule[]): void {
  const seen = new Set<string>();
  for (const rule of rules) {
    if (seen.has(rule.id)) {
      throw new Error(`duplicate rule id: ${rule.id}`);
    }
    seen.add(rule.id);
  }
}
