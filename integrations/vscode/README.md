# GuardDiff VS Code Extension

This stable extension shells out to the GuardDiff CLI and maps active findings to VS Code diagnostics. It also provides a status-bar scan entry and optional scan-on-save through `guarddiff.scanOnSave`.

## Development

```bash
npm install
npm run build
```

Run the extension host from this directory. The extension expects `guarddiff` to be available on `PATH`, or set `guarddiff.command` to an absolute CLI path.
