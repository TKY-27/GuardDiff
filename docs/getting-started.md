# Getting Started

## Install

```bash
npm install -g guarddiff
```

Before the first npm publish, use a local checkout instead:

```bash
npm install
npm run build
node packages/cli/dist/index.js staged --fail-on high
```

## List rules

```bash
guarddiff rules
```

## Scan staged changes

```bash
guarddiff staged --fail-on high
```

`staged` requires a Git work tree. In non-Git directories GuardDiff exits with code `2`.

## Scan a diff against a base revision

```bash
guarddiff scan src --diff HEAD~1 --format json
```

This path filters the Git diff to `src` while still using the real repository history.

## Scan a patch file

```bash
guarddiff diff --file examples/leaked-api-key/openai.diff
```

## Scan an MCP / agent config

```bash
guarddiff scan examples/insecure-mcp
```

## Bootstrap files

```bash
guarddiff init --github-action --pre-commit
```

`init` can generate:

- `guarddiff.config.yaml`
- `.guarddiffignore`
- `.github/workflows/guarddiff.yml`
- `.git/hooks/pre-commit`

## GitHub Action

The JavaScript action lives at `integrations/github-action` and supports:

- `fail-on`
- `post-comment`
- `sarif`
- `annotations`
- `rules-update-check`
- `rules-registry-url`
- `sarif-file`
- `config`
- outputs: `findings-count`, `critical-count`, `rule-update-count`, `passed`

When `sarif: true`, it writes `guarddiff-results.sarif` by default for `github/codeql-action/upload-sarif`. Override the path with `sarif-file`.

When `rules-update-check: true`, the Action compares active rule metadata with the published registry manifest and adds update notices to the workflow log and PR comment.

Use these permissions when comment posting and Code Scanning upload are enabled:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

The release smoke workflow in [`.github/workflows/guarddiff-smoke.yml`](../.github/workflows/guarddiff-smoke.yml) verifies PR comment update and SARIF upload against a real pull request. A reusable workflow template is available at [`docs/workflows/guarddiff-code-scanning.yml`](./workflows/guarddiff-code-scanning.yml).

## Ignore policy

`.guarddiffignore` uses gitignore-style path matching:

```gitignore
examples/**
docs/examples/**
**/fixtures/**
**/__fixtures__/**
**/*.fixture.*
dist/**
coverage/**
\#literal-file-name.env
```

Ignored files are removed before scanning where possible, so fixture directories do not inflate suppressed counts.

## Rule documentation

See [`docs/rules/README.md`](./rules/README.md) for rule metadata, remediation guidance, and suppression examples.

## pre-commit.com metadata

The repository root ships `.pre-commit-hooks.yaml`, so consumers can reference GuardDiff directly from pre-commit.
