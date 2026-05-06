# Changelog

## Unreleased

- Prepare v1.0 launch metadata across packages, CLI output, GitHub Action, docs, and VS Code extension.
- Add `rules.packs` config support and workspace-relative external rule-pack loading.
- Add `guarddiff benchmark [corpus]` and the initial false-positive regression corpus.
- Add GitHub workflow annotations for active Action findings, including remediation and docs links.
- Add Action rule-update notifications from the published rule registry manifest.
- Promote the VS Code extension to stable with status-bar scanning and optional scan-on-save.
- Add a static documentation site and rule manifest under `docs/site`.
- Add a real-PR GuardDiff smoke workflow covering `pull-requests: write`, SARIF generation, Code Scanning upload, and PR comment upsert behavior.
- Add GitHub Action README, Code Scanning workflow template, and manual smoke-test checklist.
- Formalize non-secret built-in rule tests around true positive, false positive, removed-line, environment/config reference, and matched-content masking checks.
- Tighten self-scan `.guarddiffignore` policy for examples, docs examples, fixtures, generated output, and detector tests.
- Stabilize `guarddiff rules --json` to emit metadata-only objects without runtime detector functions.

## 0.1.0

- Bootstrap monorepo workspace for `@guarddiff/core` and `@guarddiff/cli`
- Add diff parsing, suppression filtering, policy evaluation, and reporting foundations
- Add initial rules for OpenAI keys, high-entropy secrets, auth removal, CORS wildcard, and committed `.env` files
- Add initial CLI commands: `staged`, `init`, and `rules`
