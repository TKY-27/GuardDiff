# GuardDiff Benchmarks

The `fp-corpus` directory contains safe examples that should not produce active findings.

Run:

```bash
node packages/cli/dist/index.js benchmark benchmarks/fp-corpus
```

The command reports false-positive findings, missing expected rules, aggregate FP rate, and FP/KLOC. It exits with code `1` when the corpus does not pass.
