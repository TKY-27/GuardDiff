# GuardDiff v0.1.0

## Highlights
- Local-first security gate for AI-generated diffs
- Detects risky changes before they reach production
- Designed for AI coding agent workflows

## What GuardDiff checks
- Potential secret leaks
- Removed or weakened authentication checks
- Risky CORS or Firebase/Firestore rules changes
- Dangerous package scripts
- Over-permissive MCP or agent permissions
- Suspicious generated-code edits

## Install
- Before npm publish:
  - `npm install`
  - `npm run build`
  - `node packages/cli/dist/index.js staged --fail-on high`
- After npm publish:
  - `npm install -g guarddiff`
  - `guarddiff staged --fail-on high`

## Notes
- GuardDiff is local-first
- No cloud service is required by default
- Review results should be treated as security assistance, not a replacement for human review

## Breaking changes
- None for initial release
