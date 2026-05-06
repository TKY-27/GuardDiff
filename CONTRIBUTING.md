# Contributing

GuardDiff is intended to be a community-maintained OSS safety layer for AI-assisted coding.

## Development

1. Install dependencies with `npm install`
2. Build the workspace with `npm run build`
3. Run tests with `npm test`
4. Run the false-positive benchmark with `npm run benchmark:fp`
5. Run `npm run typecheck` when touching TypeScript APIs, reporters, CLI commands, or integrations

## Rules

- Every rule should ship with true-positive and false-positive tests
- Rule output must mask secrets by default
- Avoid cloud-dependent behavior in the core scanner
- Keep `ruleVersion` semantic and update `CHANGELOG.md` for behavior changes
- Run `npm run benchmark:fp` before changing detector patterns

## Rule Packs

- Export a plain `rules: Rule[]` array from the package entrypoint
- Use stable IDs such as `terraform/public-s3-bucket`
- Do not duplicate built-in rule IDs
- Mark experimental rules with `experimental: true` and keep their default impact low

## Integrations

- GitHub Action changes should preserve SARIF, PR comments, workflow annotations, and output variables
- GitHub Action outputs must not emit raw secret material in comments, annotations, logs, or SARIF
- Keep external rule-pack execution opt-in for trusted branches only
- VS Code beta changes should keep the extension CLI-backed and avoid cloud calls

## Changelog

- Add user-facing changes under `## Unreleased`
- Group larger releases with `Added`, `Changed`, `Fixed`, `Security`, and `Breaking` headings when useful
- Call out new rules, `ruleVersion` changes, severity changes, false-positive behavior changes, and migration notes
- Mention benchmark or fixture updates when they change detector coverage

## Pull requests

- Keep changes scoped
- Update `CHANGELOG.md` when rule behavior changes
- Add or update examples when you introduce a new detection pattern
