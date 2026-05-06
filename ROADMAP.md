# Roadmap

GuardDiff prioritizes local-first security checks for AI-assisted coding workflows.

## Near Term

- Expand `diff/auth-removed` coverage for common web frameworks while keeping refactor false positives low.
- Grow the false-positive benchmark corpus for docs, fixtures, generated files, and framework boilerplate.
- Add more safe examples for GitHub Action, pre-commit, and VS Code workflows.
- Improve SARIF and Markdown output for large pull requests without exposing secret material.

## Later

- Publish curated first-party rule packs for common stacks.
- Add signed rule-pack distribution guidance for trusted CI environments.
- Improve docs-site navigation around rule remediation and suppression review.
- Provide more editor workflows for reviewing findings before commit.

## Non-Goals

- Uploading source code to a hosted scanner from the core CLI.
- Running untrusted external rule-pack code in GitHub Actions by default.
- Replacing full security review, threat modeling, or production secret rotation processes.
