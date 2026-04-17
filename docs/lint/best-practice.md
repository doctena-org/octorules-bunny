## Best Practice (BN6xx)

### BN600 — Very short rule name

**Severity:** INFO

The rule name (`ref`) is shorter than 2 characters. Use a descriptive name.

**Triggers on:**

```yaml
  - ref: X
```

**Fix:**

```yaml
  - ref: Block admin access
```

### BN601 — Rule has no description

**Severity:** INFO

Adding a `description` helps explain the rule's purpose to other team members and in the Bunny dashboard.

**Triggers on:**

```yaml
  - ref: Block bots
    action: block
    conditions: [...]
```

**Fix:**

```yaml
  - ref: Block bots
    description: Challenge requests from known scraper user agents
    action: block
    conditions: [...]
```

### BN602 — Access list is disabled

**Severity:** INFO

An access list has `enabled: false`. If intentionally disabled, consider removing it. If temporarily disabled, this is a reminder that it's not enforcing.

**Triggers on:**

```yaml
  - ref: "1"
    type: country
    action: block
    enabled: false
    content: "CN"
```

**Fix:** Enable or remove:

```yaml
    enabled: true
```

---
