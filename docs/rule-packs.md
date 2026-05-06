# Rule Packs

GuardDiff ships built-in rules inside `@guarddiff/core` and can load external rule packs from the scanned project workspace.

External rule packs execute JavaScript from the scanned workspace, so they are disabled by default. Enable them only for repositories and branches you trust.

## Package Shape

Future first-party and community packages should export plain `Rule[]` modules:

```ts
import type { Rule } from "@guarddiff/core";

export const rules: Rule[] = [
  // package-specific rules
];
```

Expected package names:

- `@guarddiff/rules-secret`
- `@guarddiff/rules-diff`
- `@guarddiff/rules-config`
- `@guarddiff/rules-mcp`
- `@guarddiff-community/rules-*`

## Compatibility Rules

- Each rule keeps a stable `id`, `category`, `severity`, `defaultConfidence`, `description`, `enabled`, and semantic `ruleVersion`.
- `guarddiff rules --json` remains metadata-only so package managers, docs generators, and CI policy tooling do not depend on function serialization.
- Breaking detector behavior uses a `major` `ruleVersion` bump and a changelog entry.
- Experimental community rules start with `experimental: true` and default to `info` until promoted.

## Configuration

Add package names or relative modules to `guarddiff.config.yaml`:

```yaml
version: "1"
policy:
  failOn: high
rules:
  packs:
    - "@guarddiff-community/rules-terraform"
```

The loader resolves packages from the config root, rejects duplicate rule IDs by default, and applies `rules.overrides` to external rules the same way it does for built-in rules.

```yaml
rules:
  packs:
    - "@guarddiff-community/rules-terraform"
  overrides:
    - ruleId: terraform/public-s3-bucket
      severity: medium
```

## CLI Support

- `guarddiff scan`, `staged`, and `diff` load configured packs only when `--allow-rule-packs` is set.
- `guarddiff rules --config guarddiff.config.yaml --allow-rule-packs --json` includes configured pack metadata.
- `guarddiff benchmark --allow-rule-packs` uses the same configured rule set, so external packs can maintain their own FP corpus.

The GitHub Action also defaults to `allow-rule-packs: false`.
