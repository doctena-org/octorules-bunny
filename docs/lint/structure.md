## Structure (BN0xx)

### BN001 — Rule missing 'ref'

**Severity:** ERROR

Every rule must have a `ref` field that uniquely identifies it within the phase. For custom WAF and rate limit rules, this becomes the `ruleName` in the Bunny API. For access lists, this is the API-assigned numeric ID (discovered via `octorules dump`).

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
  - action: block
    conditions:
    - variable: request_uri
      operator: contains
      value: /admin
```

**Fix:** Add a `ref` field:

```yaml
  - ref: Block admin
    action: block
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
```

### BN002 — Duplicate ref within phase

**Severity:** ERROR

Two or more rules in the same phase share the same `ref` value. Each ref must be unique within its phase.

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
  - ref: Block bots
    action: block
    conditions:
    - '...'
  - ref: Block bots
    action: challenge
    conditions:
    - '...'
```

**Fix:** Use unique refs:

```yaml
  - ref: Block bots strict
    action: block
    conditions: [...]
  - ref: Challenge bots
    action: challenge
    conditions: [...]
```

### BN003 — Rule missing required field

**Severity:** ERROR

A required field is missing. Required fields depend on phase type:
- Custom WAF rules: `action`, `conditions`
- Rate limit rules: `action`, `conditions`, `request_count`
- Access lists: `action`, `type`, `content`

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
  - ref: Incomplete rule
    conditions:
    - variable: request_uri
      operator: contains
      value: /admin
```

**Fix:** Add the missing `action` field:

```yaml
  - ref: Incomplete rule
    action: block
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
```

### BN004 — Unknown top-level rule field

**Severity:** WARNING

A field name is not recognized for the rule type. This usually indicates a typo. Valid fields for custom WAF rules: `ref`, `action`, `severity`, `description`, `conditions`, `transformations`. Rate limit rules add: `request_count`, `timeframe`, `block_time`, `counter_key_type`. Access lists use: `ref`, `type`, `action`, `enabled`, `content`, `description`.

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
  - ref: My rule
    action: block
    aciton: challenge
    conditions:
    - '...'
```

**Fix:** Correct the field name or remove it.

### BN005 — Rule field has wrong type

**Severity:** ERROR

A field exists but has the wrong type. For example, `severity` must be a string not an integer, `conditions` must be a list, `enabled` must be a boolean.

**Triggers on:**

```yaml
  - ref: My rule
    action: block
    severity: 2
    conditions: [...]
```

**Fix:** Use the correct type:

```yaml
    severity: error
```

### BN006 — Rule entry is not a dict

**Severity:** ERROR

Each entry in a rules list must be a YAML mapping (dict). A bare scalar or list
element (e.g. a string or integer) is always an authoring mistake.

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
  - not a dict
```

**Fix:** Replace the scalar with a proper rule mapping.

### BN007 — Phase value is not a list

**Severity:** ERROR

Each phase key must map to a YAML list (sequence). A scalar, mapping, or
null value is always an authoring mistake -- rules files expect a list of
rule entries under each phase.

**Triggers on:**

```yaml
bunny:
  waf_custom_rules: not a list
```

**Fix:** Use a proper list:

```yaml
bunny:
  waf_custom_rules:
  - ref: Block admin
    action: block
    conditions:
    - variable: request_uri
      operator: contains
      value: /admin
```

---

### BN009 — Duplicate ref across different phases

**Severity:** INFO

A rule's `ref` appears in two or more Bunny phases. The API scopes refs per-phase so this isn't a bug, but it makes audit logs and reports ambiguous ("which `api-throttle` changed?").

**Triggers on:**

```yaml
bunny:
  waf_custom_rules:
    - ref: api-throttle  # same ref
      action: block
      conditions: [...]

  waf_rate_limit_rules:
    - ref: api-throttle  # same ref
      action: block
      conditions: [...]
```

**Fix:** Use distinct refs per phase (e.g. `api-throttle-waf` and `api-throttle-rl`).

---

### BN010 — Invalid ref format

**Severity:** ERROR

Custom WAF and rate limit rule names must match `[a-zA-Z0-9 ]+` — alphanumeric characters and spaces only. No hyphens, underscores, or special characters. This is an API constraint enforced by Bunny.

**Triggers on:**

```yaml
  - ref: block-admin
```

**Fix:** Use spaces instead of hyphens:

```yaml
  - ref: Block admin
```

### BN011 — Description longer than 255 chars (octorules guidance)

**Severity:** WARNING

The 255-character threshold is octorules guidance — Bunny's spec declares no length constraint. Very long descriptions are unwieldy in dashboards and diffs.

**Triggers on:** A `description` field with more than 255 characters.

**Fix:** Shorten the description.

---
