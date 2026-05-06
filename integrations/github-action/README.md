# GuardDiff GitHub Action

Run GuardDiff on pull request diffs, optionally post a PR summary comment, and write SARIF for GitHub Code Scanning.

GuardDiff masks matched secret material in terminal output, PR comments, annotations, and SARIF. Use placeholders in examples and never paste real credentials into Action logs or issues.

## Inputs

| Input | Default | Description |
|---|---:|---|
| `fail-on` | `high` | Minimum severity that fails the job. |
| `post-comment` | `true` | Create or update a GuardDiff PR comment. |
| `sarif` | `false` | Write SARIF output for Code Scanning upload. |
| `annotations` | `true` | Emit GitHub workflow annotations for active findings. |
| `rules-update-check` | `true` | Compare active rule metadata with the published registry manifest and emit update notices. |
| `allow-rule-packs` | `false` | Allow executable external rule packs from `guarddiff.config.yaml`. Enable only for trusted branches. |
| `allow-inline-suppressions` | `false` | Allow inline `guarddiff-ignore` suppressions in PR diffs. Enable only for trusted branches after review. |
| `rules-registry-url` | `https://raw.githubusercontent.com/guarddiff/guarddiff/main/docs/site/rules/manifest.json` | JSON manifest URL used for update checks. |
| `sarif-file` | `guarddiff-results.sarif` | SARIF output path. |
| `config` | `guarddiff.config.yaml` | GuardDiff config path. |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Unsuppressed finding count. |
| `critical-count` | Unsuppressed critical finding count. |
| `rule-update-count` | Number of available rule updates reported by the registry. |
| `passed` | Whether the configured policy passed. |

## Required Permissions

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

`pull-requests: write` is required only when `post-comment: true`. `security-events: write` is required only when uploading the SARIF file with `github/codeql-action/upload-sarif`.

## Example

```yaml
name: GuardDiff Security Check

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  guarddiff:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run GuardDiff
        uses: guarddiff/guarddiff@v1
        with:
          fail-on: high
          post-comment: true
          sarif: true
          annotations: true
          rules-update-check: true
          allow-inline-suppressions: false
          sarif-file: guarddiff-results.sarif
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload GuardDiff SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guarddiff-results.sarif
```

For release validation, run the local smoke workflow in [`.github/workflows/guarddiff-smoke.yml`](../../.github/workflows/guarddiff-smoke.yml) from an in-repository branch so writable token permissions are available.

For pull requests, the Action reads GuardDiff config and `.guarddiffignore` from the trusted base ref. PR-head changes to `guarddiff.config.yaml` cannot disable findings introduced by the same PR.
