## Rate Limit (BN2xx)

### BN200 — request_count must be a positive integer

**Severity:** ERROR

The `request_count` field must be a positive integer (>= 1). Boolean values are not accepted.

**Triggers on:**

```yaml
bunny_waf_rate_limit_rules:
  - ref: My rate limit
    request_count: 0
```

**Fix:**

```yaml
    request_count: 100
```

### BN201 — Invalid timeframe value

**Severity:** ERROR

The `timeframe` must be one of: `1s`, `10s`, `1m`, `5m`, `15m`, `1h`. The Basic tier only supports up to `10s`. Also fires when the `timeframe` field is entirely missing from a rate limit rule.

**Triggers on:**

```yaml
    timeframe: 30s
```

or when `timeframe` is absent:

**Fix:**

```yaml
    timeframe: 1m
```

### BN202 — Invalid block_time value

**Severity:** ERROR

The `block_time` must be one of: `30s`, `1m`, `5m`, `15m`, `30m`, `1h`. Also fires when the `block_time` field is entirely missing from a rate limit rule.

**Triggers on:**

```yaml
    block_time: 2m
```

or when `block_time` is absent:

**Fix:**

```yaml
    block_time: 5m
```

### BN203 — Invalid counter_key_type value

**Severity:** ERROR

The `counter_key_type` must be one of: `ip`, `path`, `header`, `cookie`, `query`, `body`, `fingerprint`, `global`. Also fires when the `counter_key_type` field is entirely missing from a rate limit rule.

**Triggers on:**

```yaml
    counter_key_type: user
```

or when `counter_key_type` is absent:

**Fix:**

```yaml
    counter_key_type: ip
```

### BN210 — Very short block_time

**Severity:** WARNING

A `block_time` of `30s` is very short and may not be effective for rate limiting.

**Triggers on:**

```yaml
    block_time: 30s
```

**Fix:**

```yaml
    block_time: 5m
```

---
