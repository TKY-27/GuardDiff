# GuardDiff Rules

This document lists the built-in rules, their default severity, intended remediation, and common suppression patterns.

## Metadata

Every rule exposes:

- `ruleVersion`: semantic version for detector behavior.
- `severity`: effective severity after defaults and config overrides.
- `defaultSeverity`: built-in default severity.
- `experimental`: `true` for rules still in trial. Experimental rules default to `info` unless the user overrides severity.

Use `guarddiff rules` to inspect the active metadata. Use `guarddiff rules --json` when tooling needs the full shape.

## Secret Rules

| Rule | Default | What it catches | Remediation |
|---|---:|---|---|
| `secret/openai-key` | critical | OpenAI API keys such as `sk-...` | Move the key to `OPENAI_API_KEY`, rotate exposed keys, and purge committed history when needed. |
| `secret/anthropic-key` | critical | Anthropic API keys such as `sk-ant-...` | Move the value to `ANTHROPIC_API_KEY` and rotate the exposed key. |
| `secret/aws-access-key` | critical | AWS Access Key IDs | Remove hardcoded credentials and use IAM roles, OIDC, or environment-managed credentials. |
| `secret/aws-secret-key` | critical | AWS Secret Access Keys in secret-like assignment contexts | Rotate the credential pair and load it from a secret manager. |
| `secret/github-token` | critical | GitHub personal or automation tokens | Revoke the token and use GitHub Actions permissions or repository secrets. |
| `secret/stripe-key` | critical | Stripe secret keys such as `sk_live_...` | Rotate the key in Stripe and load it from server-side environment variables. |
| `secret/supabase-key` | critical | Supabase service-role JWT-like keys | Rotate the service role key and keep it server-only. |
| `secret/private-key` | critical | PEM private key material | Remove the private key, rotate certificates, and store key material outside source control. |
| `secret/firebase-config` | high | Firebase config objects with public-looking API keys and project metadata | Confirm whether the config is intended to be public; restrict rules and keep private values out of client bundles. |
| `secret/high-entropy` | medium | Long high-entropy strings in secret-like contexts | Move the value to a secret store, or suppress only when the value is a safe generated identifier. |

Suppression example:

```ts
const example = "sk-your-documented-placeholder"; // guarddiff-ignore: secret/openai-key
```

## Diff Rules

| Rule | Default | What it catches | Remediation |
|---|---:|---|---|
| `diff/auth-bypass` | critical | Added auth bypasses such as unconditional allow flags or skipped middleware | Restore auth enforcement and add tests covering protected routes. |
| `diff/auth-removed` | critical | Removed auth checks, with refactor-aware downgrade logic | Verify the auth path was moved, not deleted. If moved, keep the moved check in the same change. |
| `diff/dangerous-shell` | critical | Shell execution fed by user-controlled input | Use argument arrays, allowlists, or remove shell execution. |
| `diff/cors-wildcard` | high | `*` origins or all-open CORS settings | Restrict origins to explicit trusted domains. |
| `diff/debug-endpoint` | high | Debug/test endpoints introduced into app routes | Gate behind local-only checks, auth, or remove before merge. |
| `diff/eval-injection` | high | `eval` and equivalent dynamic execution | Replace with structured parsing or a safe interpreter. |
| `diff/sensitive-log` | medium | Logging secrets, tokens, cookies, or credentials | Redact values before logging or remove the log statement. |

Suppression example:

```ts
logger.info("token redacted before logging"); // guarddiff-ignore: diff/sensitive-log
```

## Config Rules

| Rule | Default | What it catches | Remediation |
|---|---:|---|---|
| `config/firebase-open-rules` | critical | Firebase/Firestore rules that allow read and write for everyone | Replace `if true` with authenticated and ownership-aware conditions. |
| `config/firestore-open-read` | high | Firestore read rules open to everyone | Limit reads to authenticated users or public collections only. |
| `config/env-plaintext-secret` | high | Plaintext secret-like assignments in `.env` files | Keep local `.env` files ignored and use CI/hosting secret storage. |
| `config/env-committed` | high | `.env` files added to a diff | Remove the file from source control and commit an `.env.example` instead. |
| `config/package-json-dangerous-script` | critical | Dangerous npm lifecycle scripts such as remote download piped to shell | Remove auto-executed remote code and move reviewed setup into local scripts. |

Suppression example:

```env
EXAMPLE_TOKEN=not-a-real-secret # guarddiff-ignore: config/env-plaintext-secret
```

## MCP Rules

| Rule | Default | What it catches | Remediation |
|---|---:|---|---|
| `mcp/full-home-access` | critical | Agent or MCP config granting access to the whole home directory | Narrow filesystem access to the project directory. |
| `mcp/root-access` | critical | Filesystem access to `/` | Remove root access and grant only the exact required paths. |
| `mcp/auto-exec-without-approval` | high | Command execution without approval | Require approval for shell execution and destructive operations. |
| `mcp/unrestricted-network` | high | Unrestricted network access | Limit network hosts or disable network access for local-only tools. |

Suppression example:

```json
{ "allowedDirectories": ["./fixtures"] } // guarddiff-ignore: mcp/full-home-access
```

## .guarddiffignore Policy

`.guarddiffignore` follows gitignore-style path syntax, including:

- `!` negation with last match wins.
- Escaped leading `#` and `!` for literal filenames.
- Anchored root patterns such as `/vendor/`.
- Directory patterns such as `fixtures/`.

GuardDiff applies `.guarddiffignore` before scanning where possible, so ignored files reduce `filesScanned` and do not inflate `suppressedFindings`.

Recommended repository self-scan baseline:

```gitignore
# Intentionally insecure examples and documentation examples
examples/**
docs/examples/**

# Fixture directories and fixture-like files
**/fixtures/**
**/__fixtures__/**
**/*.fixture.*
**/*.fixtures.*

# Generated dependency, build, and coverage output
node_modules/**
dist/**
packages/*/dist/**
coverage/**
packages/*/coverage/**

# Detector/unit tests may contain representative risky literals.
# Prefer narrower fixture ignores in production repositories where possible.
**/*.test.ts
**/*.spec.ts
```

Prefer `.guarddiffignore` for known fixture directories and inline `guarddiff-ignore` comments for one-off examples that reviewers should still see in context.
