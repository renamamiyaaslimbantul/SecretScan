# Custom rules

Add custom rules to `.secretscan.yaml`:

```yaml
custom_rules:
  - name: Internal Service Token
    pattern: 'INT_[A-Z0-9]{20}'
    confidence: 95
```

`pattern` uses Go regular-expression syntax. SecretScan validates every pattern before scanning. `confidence` accepts `0` through `100`; omitted or zero confidence defaults to `85`.

Custom-rule matches are redacted before entering report data. Keep rules specific enough to avoid matching ordinary identifiers.

Use `excluded_patterns` for known-safe values or lines:

```yaml
excluded_patterns:
  - '^SAFE_[A-Z0-9_]+$'
  - 'secrets\.example\.invalid'
```

An inline `secretscan:allow` marker also suppresses a matching line. Use it only after reviewing the value.
