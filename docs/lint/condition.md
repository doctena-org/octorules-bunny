## Condition Validation (BN4xx)

### BN400 — Condition missing 'variable'

**Severity:** ERROR

Every condition must specify a `variable` to inspect.

**Triggers on:**

```yaml
    conditions:
      - operator: contains
        value: /admin
```

**Fix:**

```yaml
      - variable: request_uri
        operator: contains
        value: /admin
```

### BN401 — Condition missing 'operator'

**Severity:** ERROR

Every condition must specify an `operator` for comparison.

**Triggers on:**

```yaml
    conditions:
      - variable: request_uri
        value: /admin
```

**Fix:**

```yaml
      - variable: request_uri
        operator: contains
        value: /admin
```

### BN402 — detect_sqli/detect_xss ignores 'value'

**Severity:** WARNING

The `detect_sqli` and `detect_xss` operators perform built-in detection and ignore the `value` field. Remove it to avoid confusion.

**Triggers on:**

```yaml
      - variable: request_body
        operator: detect_sqli
        value: "SELECT *"
```

**Fix:**

```yaml
      - variable: request_body
        operator: detect_sqli
```

### BN403 — Duplicate condition in chain

**Severity:** WARNING

Two conditions within the same rule are identical. Since conditions are AND-combined, a duplicate has no effect.

**Triggers on:**

```yaml
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
      - variable: request_uri
        operator: contains
        value: /admin
```

**Fix:** Remove the duplicate.

### BN404 — Chained conditions exceed 10

**Severity:** WARNING

A rule has more than 10 conditions. This may exceed API limits. Consider splitting into separate rules.

---
