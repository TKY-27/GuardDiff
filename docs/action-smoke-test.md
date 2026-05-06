# GitHub Action Smoke Test

Use a real pull request to verify the GitHub-hosted integration path before release.

## What This Covers

- `pull-requests: write` can create or update the GuardDiff PR comment.
- `security-events: write` can upload `guarddiff-results.sarif` to Code Scanning.
- `sarif: true` writes a SARIF file even when the scan fails.
- `annotations: true` emits line-level annotations with remediation and docs links.
- `rules-update-check: true` can add rule update notices when the registry manifest reports newer detector versions.
- Re-running the workflow updates the existing `<!-- guarddiff-report -->` comment instead of posting duplicates.

## Workflow Under Test

The repository ships [`.github/workflows/guarddiff-smoke.yml`](../.github/workflows/guarddiff-smoke.yml) for this check. It uses the local action path so the PR validates the exact action code in the branch:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
```

## Manual PR Procedure

1. Open a branch in a real GitHub repository containing this workflow.
2. Add one intentionally risky line, for example an OpenAI-key-shaped fixture in a temporary file.
3. Open a pull request from a branch in the same repository.
4. Confirm the GuardDiff job fails when `fail-on: high` is exceeded.
5. Confirm the PR has exactly one GuardDiff comment.
6. Push another commit to the same PR and confirm the same comment is updated.
7. Confirm Code Scanning receives `guarddiff-results.sarif`.
8. Confirm workflow annotations include remediation text for the finding.
9. Remove the risky fixture commit or mark the PR as a smoke-test-only branch before merge.

Forked PRs may not receive writable `GITHUB_TOKEN` permissions. Run this smoke test from an in-repository branch when validating comment update and Code Scanning upload.
