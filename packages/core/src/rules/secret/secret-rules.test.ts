import { describe, expect, it } from "vitest";

import type { BuildRuleContextOptions } from "../../test-helpers.js";
import { buildRuleContext } from "../../test-helpers.js";
import type { Rule, Severity } from "../../types/index.js";
import { anthropicKeyRule } from "./anthropic-key.js";
import { awsAccessKeyRule } from "./aws-access-key.js";
import { awsSecretKeyRule } from "./aws-secret-key.js";
import { firebaseConfigRule } from "./firebase-config.js";
import { githubTokenRule } from "./github-token.js";
import { highEntropyStringRule } from "./high-entropy-string.js";
import { openaiKeyRule } from "./openai-key.js";
import { privateKeyRule } from "./private-key.js";
import { stripeKeyRule } from "./stripe-key.js";
import { supabaseKeyRule } from "./supabase-key.js";

interface SecretRuleCase {
  title: string;
  rule: Rule;
  severity: Severity;
  truePositive: BuildRuleContextOptions;
  falsePositive: BuildRuleContextOptions;
  removedOnly: BuildRuleContextOptions;
  envReference: BuildRuleContextOptions;
  maskedValueMustNotContain: string[];
}

const secretRuleCases: SecretRuleCase[] = [
  {
    title: "secret/anthropic-key",
    rule: anthropicKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: ['const key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcd";']
    },
    falsePositive: {
      addedLines: ['const key = "sk-ant-your-anthropic-key-placeholder-placeholder-123456";']
    },
    removedOnly: {
      removedLines: ['const key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcd";']
    },
    envReference: {
      addedLines: ["const key = process.env.ANTHROPIC_API_KEY;"]
    },
    maskedValueMustNotContain: ["abcdefghijklmnopqrstuvwxyz1234567890"]
  },
  {
    title: "secret/aws-access-key",
    rule: awsAccessKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: ['const accessKeyId = "AKIA1234567890ABCDEF";']
    },
    falsePositive: {
      addedLines: ['const accessKeyId = "AKIAIOSFODNN7EXAMPLE";']
    },
    removedOnly: {
      removedLines: ['const accessKeyId = "AKIA1234567890ABCDEF";']
    },
    envReference: {
      addedLines: ["const accessKeyId = process.env.AWS_ACCESS_KEY_ID;"]
    },
    maskedValueMustNotContain: ["1234567890ABCDEF"]
  },
  {
    title: "secret/aws-secret-key",
    rule: awsSecretKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: ['const awsSecretAccessKey = "abcdEFGHijklMNOPqrstUVWXyz0123456789ABCD";']
    },
    falsePositive: {
      addedLines: ['const awsSecretAccessKey = "placeholderplaceholderplaceholderplacehol";']
    },
    removedOnly: {
      removedLines: ['const awsSecretAccessKey = "abcdEFGHijklMNOPqrstUVWXyz0123456789ABCD";']
    },
    envReference: {
      addedLines: ["const awsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;"]
    },
    maskedValueMustNotContain: ["ijklMNOPqrstUVWX"]
  },
  {
    title: "secret/firebase-config",
    rule: firebaseConfigRule,
    severity: "high",
    truePositive: {
      addedLines: [
        "const firebaseConfig = {",
        '  apiKey: "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456",',
        '  projectId: "guarddiff-prod"',
        "};"
      ],
      rawContent: [
        "const firebaseConfig = {",
        '  apiKey: "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456",',
        '  projectId: "guarddiff-prod"',
        "};"
      ].join("\n")
    },
    falsePositive: {
      addedLines: ['const config = { apiUrl: "https://example.com" };'],
      rawContent: 'const config = { apiUrl: "https://example.com" };'
    },
    removedOnly: {
      removedLines: [
        "const firebaseConfig = {",
        '  apiKey: "AIzaSyD-abcdefghijklmnopqrstuvwxyz123456",',
        '  projectId: "guarddiff-prod"',
        "};"
      ]
    },
    envReference: {
      addedLines: ['const firebaseConfig = { apiKey: process.env.FIREBASE_API_KEY, projectId: "guarddiff-prod" };'],
      rawContent: 'const firebaseConfig = { apiKey: process.env.FIREBASE_API_KEY, projectId: "guarddiff-prod" };'
    },
    maskedValueMustNotContain: ["AIzaSyD-abcdefghijklmnopqrstuvwxyz123456", "guarddiff-prod"]
  },
  {
    title: "secret/github-token",
    rule: githubTokenRule,
    severity: "critical",
    truePositive: {
      addedLines: ['const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";']
    },
    falsePositive: {
      addedLines: ['const token = "ghp_exampleexampleexampleexampleexampleexample";']
    },
    removedOnly: {
      removedLines: ['const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD";']
    },
    envReference: {
      addedLines: ["const token = process.env.GITHUB_TOKEN;"]
    },
    maskedValueMustNotContain: ["abcdefghijklmnopqrstuvwxyz1234567890"]
  },
  {
    title: "secret/high-entropy",
    rule: highEntropyStringRule,
    severity: "medium",
    truePositive: {
      addedLines: ['const api_token = "a8F2kLm9Pq3Rs7Tu1Vw4Xy6Za0Bc2De4Fg6Hi8Jk";']
    },
    falsePositive: {
      addedLines: ['const api_token = "550e8400e29b41d4a716446655440000";']
    },
    removedOnly: {
      removedLines: ['const api_token = "a8F2kLm9Pq3Rs7Tu1Vw4Xy6Za0Bc2De4Fg6Hi8Jk";']
    },
    envReference: {
      addedLines: ["const api_token = process.env.API_TOKEN;"]
    },
    maskedValueMustNotContain: ["Pq3Rs7Tu1Vw4Xy6Z"]
  },
  {
    title: "secret/openai-key",
    rule: openaiKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: ['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']
    },
    falsePositive: {
      addedLines: ['const key = "sk-your-api-key-here";']
    },
    removedOnly: {
      removedLines: ['const key = "sk-abcdefghijklmnopqrstuvwxyz123456";']
    },
    envReference: {
      addedLines: ["const key = process.env.OPENAI_API_KEY;"]
    },
    maskedValueMustNotContain: ["abcdefghijklmnopqrstuvwxyz"]
  },
  {
    title: "secret/private-key",
    rule: privateKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: ["-----BEGIN RSA PRIVATE KEY-----"]
    },
    falsePositive: {
      addedLines: ["-----BEGIN PUBLIC KEY-----"]
    },
    removedOnly: {
      removedLines: ["-----BEGIN RSA PRIVATE KEY-----"]
    },
    envReference: {
      addedLines: ["const privateKey = process.env.PRIVATE_KEY;"]
    },
    maskedValueMustNotContain: ["RSA"]
  },
  {
    title: "secret/stripe-key",
    rule: stripeKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: [`const stripeKey = "${"sk" + "_live_" + "1234567890abcdefghijklmnopqrstuvwxyz"}";`]
    },
    falsePositive: {
      addedLines: ['const stripeKey = "pk_live_1234567890abcdefghijklmnopqrstuvwxyz";']
    },
    removedOnly: {
      removedLines: [`const stripeKey = "${"sk" + "_live_" + "1234567890abcdefghijklmnopqrstuvwxyz"}";`]
    },
    envReference: {
      addedLines: ["const stripeKey = process.env.STRIPE_SECRET_KEY;"]
    },
    maskedValueMustNotContain: ["abcdefghijklmnopqrstuvwxyz"]
  },
  {
    title: "secret/supabase-key",
    rule: supabaseKeyRule,
    severity: "critical",
    truePositive: {
      addedLines: [
        'const supabaseKey = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature1234567890";'
      ]
    },
    falsePositive: {
      addedLines: ['const supabaseUrl = "https://example.supabase.co";']
    },
    removedOnly: {
      removedLines: [
        'const supabaseKey = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature1234567890";'
      ]
    },
    envReference: {
      addedLines: ["const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;"]
    },
    maskedValueMustNotContain: ["signature1234567890"]
  }
];

for (const testCase of secretRuleCases) {
  describe(testCase.title, () => {
    it("detects a real secret in added lines", () => {
      const findings = testCase.rule.detect(buildRuleContext(testCase.truePositive));

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(testCase.severity);
      expect(findings[0].matchedContent).toContain("****");
    });

    it("does not detect representative false positives", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.falsePositive))).toHaveLength(0);
    });

    it("does not detect removed-only secrets", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.removedOnly))).toHaveLength(0);
    });

    it("does not detect environment-variable references", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.envReference))).toHaveLength(0);
    });

    it("masks matched content", () => {
      const findings = testCase.rule.detect(buildRuleContext(testCase.truePositive));

      expect(findings).toHaveLength(1);
      for (const forbidden of testCase.maskedValueMustNotContain) {
        expect(findings[0].matchedContent).not.toContain(forbidden);
      }
    });
  });
}
