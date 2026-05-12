# Security Policy

## Supported Versions

Security fixes are provided for the latest published minor version of GuardDiff.

GuardDiff is local-first by default. The CLI and core scanner do not require a cloud service and should not upload source code or diffs unless a surrounding integration is explicitly configured to do so.

Do not commit API keys, `.env` files, private keys, service-account files, tokens, passwords, or other secrets to repositories that use GuardDiff. Use `.env.example` for placeholder variable names only, keep real values in local secret stores or CI secret managers, and rotate any credential that is accidentally exposed.

## Reporting a Vulnerability

Please do not open a public issue for exploitable vulnerabilities, scanner bypasses that expose real credentials, private repository details, or any report containing real secret values.

Report security issues through GitHub Security Advisories for this repository. Include:

- GuardDiff version
- Node.js version
- Minimal diff, config, or rule-pack input that reproduces the issue, with real secrets replaced by placeholders
- Expected and actual result
- Whether the report involves a false negative, false positive, crash, or unsafe integration behavior

We aim to acknowledge valid reports within 72 hours and will coordinate disclosure timing for confirmed vulnerabilities.

If a credential, token, private key, or private repository detail is accidentally posted publicly, maintainers may hide or delete the content. Removing it from GitHub is not enough; rotate or invalidate any exposed credential.

## Scanner Bypasses

GuardDiff is a defensive tool and does not guarantee complete detection. Treat confirmed high-impact false negatives in built-in rules as security reports when they can lead to leaked credentials, auth bypasses, unsafe production config, or over-permissive agent access.
