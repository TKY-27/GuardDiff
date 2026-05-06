# Release Guide

Use this guide together with [docs/release-checklist.md](./release-checklist.md).

## Before Tagging

1. Run `npm install`.
2. Run `npm run build`.
3. Run `npm test`.
4. Run `npm run benchmark:fp`.
5. Run `npm run typecheck`.
6. Run `npm pack --dry-run` for the root, `@guarddiff/core`, and `@guarddiff/cli` packages.
7. Run GuardDiff against the repository and review any findings.

## Security Checks

- Confirm `.env`, `*.local`, local agent logs, terminal recordings, screenshots, and private key files are not tracked.
- Re-run repository scans for local paths, personal emails, and token-like values.
- Confirm `docs/assets/guarddiff-demo.cast` contains no usernames, hostnames, home paths, emails, or real secrets.
- If any real credential was exposed, rotate or revoke it before release. Git history cleanup alone is not enough.

## Publishing

- Publish only after package metadata, changelog, release notes, and GitHub Security Advisories settings are ready.
- Do not publish from a dirty worktree.
- Do not enable GitHub Action external rule packs on untrusted pull requests.
