# Release Checklist

Use this checklist before publishing a GuardDiff release.

## Package

- `package.json` root is publishable as `guarddiff`.
- `@guarddiff/core` is published before `@guarddiff/cli`.
- `@guarddiff/cli` is published before root `guarddiff`.
- `npm pack --dry-run`, `npm pack --dry-run -w @guarddiff/core`, and `npm pack --dry-run -w @guarddiff/cli` include only runtime files, metadata, README, and license content.
- `npm install -g guarddiff && guarddiff staged` works on Node.js 18+.

## Build And Test

- `npm ci`
- `npm run typecheck`
- `npm test`
- `npm run test:coverage`
- `npm run build`
- `npm run benchmark:fp`

## GitHub Action

- `integrations/github-action/dist/main.js` is rebuilt and tracked.
- Root `action.yml` points to `integrations/github-action/dist/main.js`; local integration `action.yml` points to `dist/main.js`.
- Default `rules-registry-url` uses the raw GitHub manifest URL.
- Smoke test runs on a real PR with comments and SARIF enabled.
- GitHub Actions in release-capable workflows are pinned to full commit SHAs.

## Repository

- `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue templates, and release workflow are present.
- Tag format is `vMAJOR.MINOR.PATCH`.
- GitHub Release notes mention rule changes, false-positive changes, and breaking changes.
- README top section shows the install command and demo images.
