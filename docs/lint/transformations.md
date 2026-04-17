## Transformation Checks (BN125)

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
