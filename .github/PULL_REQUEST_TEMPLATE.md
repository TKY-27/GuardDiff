## Summary

- 

## Release Safety

- [ ] Rule behavior changes are covered by true-positive and false-positive tests.
- [ ] New or changed findings mask secret material by default.
- [ ] Documentation, examples, and rule metadata are updated when behavior changes.
- [ ] `npm run benchmark:fp` has been run for detector changes.

## Verification

```text
npm run typecheck
npm test
npm run build
```
