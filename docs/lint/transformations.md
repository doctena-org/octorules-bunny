## Transformation Checks (BN125)

### BN122 — Redundant `lowercase` transformation

**Severity:** INFO

The `lowercase` transformation is redundant when used with the `str_eq` operator, which is already case-insensitive. Removing the transformation simplifies the rule without changing behavior.

**Triggers on:**

```yaml
    conditions:
      - variable: request_headers
        variable_value: User-Agent
        operator: str_eq
        value: "chrome"
    transformations:
      - lowercase
```

**Fix:** Remove the unnecessary transformation:

```yaml
    conditions:
      - variable: request_headers
        variable_value: User-Agent
        operator: str_eq
        value: "chrome"
```

### BN125 — Duplicate transformation

**Severity:** WARNING

The same transformation appears more than once. Duplicates have no effect and likely indicate a copy-paste error.

**Triggers on:**

```yaml
    transformations:
      - lowercase
      - lowercase
```

**Fix:** Remove the duplicate.

---
