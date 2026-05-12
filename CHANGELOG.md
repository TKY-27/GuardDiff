# Changelog

## Unreleased

- No unreleased changes yet.

## 0.1.0 - 2026-05-12

- Bootstrap monorepo workspace for `@guarddiff/core` and `@guarddiff/cli`
- Add diff parsing, suppression filtering, policy evaluation, and reporting foundations
- Add initial rules for OpenAI keys, high-entropy secrets, auth removal, CORS wildcard, and committed `.env` files
- Add rules for unsafe CORS, Firebase/Firestore rules, dangerous package scripts, shell execution, sensitive logs, and MCP/agent permissions
- Add initial CLI commands: `staged`, `scan`, `diff`, `init`, `rules`, and `benchmark`
- Add GitHub Action, SARIF, PR comments, workflow annotations, pre-commit, VS Code, and rule-pack foundations
