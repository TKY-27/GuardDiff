# Safe Documentation Placeholders

This fixture keeps common documentation examples out of the false-positive path.

```bash
export OPENAI_API_KEY="$OPENAI_API_KEY"
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"
```

Use reviewed placeholders such as `sk-your-key-here`, `ghp_your_token_here`, and `AKIAIOSFODNN7EXAMPLE` in docs.
