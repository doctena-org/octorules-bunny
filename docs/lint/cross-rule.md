## Cross-Rule Analysis (BN5xx)

### BN500 — Duplicate conditions across rules

**Severity:** WARNING

Two or more rules in the same phase have identical condition sets. This may indicate a copy-paste error.

**Triggers on:**

```yaml
  - ref: Rule A
    action: block
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
  - ref: Rule B
    action: log
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
```

**Fix:** Remove the duplicate or differentiate the conditions.

### BN501 — Rule count exceeds plan tier limit

**Severity:** WARNING

The number of rules exceeds known plan tier limits:

| Tier | Custom WAF | Rate Limits | Access Lists |
|------|:----------:|:-----------:|:------------:|
| Basic | 0 | 2 | 1 |
| Advanced | 10 | 10 | 5 |
| Business | 25 | 25 | 10 |
| Enterprise | 50 | Unlimited | Unlimited |

The tier is auto-detected per-zone from the Shield API during zone resolution. When `plan` is set in the provider config, it serves as a fallback. When neither is available, BN501 warns for the lowest tier exceeded (e.g., if you have 3 rate-limit rules, it warns that the Basic tier limit of 2 is exceeded).

**Fix:** Upgrade the zone's Shield tier or reduce rule count. You can also set `plan` in the provider config as a fallback:

```yaml
providers:
  bunny:
    api_key: env/BUNNY_API_KEY
    plan: advanced
```

### BN502 — Conflicting access lists

**Severity:** WARNING

Two access lists of the same type category have overlapping entries with
different actions (e.g., one blocks and another allows the same value).
Supported type categories: `ip`/`cidr` (compared by network overlap),
`country`, `asn`, and `ja4` (compared by exact match). Conflict detection is
per-type-category -- an `ip` list and a `country` list with the same value
will not produce a false positive.

**Triggers on:**

```yaml
  - ref: "1"
    type: ip
    action: block
    content: "1.2.3.4"
  - ref: "2"
    type: ip
    action: allow
    content: "1.2.3.4"
```

```yaml
  - ref: "3"
    type: country
    action: block
    content: "CN"
  - ref: "4"
    type: country
    action: allow
    content: "CN"
```

**Fix:** Remove the overlap or consolidate into a single list.

### BN503 — Rule likely unreachable after catch-all terminating rule

**Severity:** WARNING

A rule is preceded by a rule that matches all traffic (single catch-all condition like `contains ""`) with a terminating action (`block`, `challenge`, `allow`, `bypass`). Subsequent rules in the same phase will never execute.

`log` actions do not terminate — they log and continue to the next rule.

**Triggers on:**

```yaml
bunny_waf_custom_rules:
  - ref: catch all
    action: block
    conditions:
      - variable: request_url
        operator: contains
        value: ""
  - ref: specific rule
    action: block
    conditions:
      - variable: request_url
        operator: contains
        value: "/admin"
```

**Fix:** Reorder rules so the catch-all appears last, or add conditions to narrow its scope.

### BN504 — Cross-list / cross-rule CIDR overlap

**Severity:** WARNING

Two CIDR entries (within the same access list or across different access lists in the same zone) overlap. This may indicate redundancy or a configuration error. Detection uses a sweep-line algorithm to identify overlapping networks, mirroring checks in other providers (AZ339 for Azure, GA305 for Google, WA167 for AWS).

**Triggers on:**

```yaml
bunny_waf_access_list_rules:
  - ref: "blocked-1"
    type: cidr
    action: block
    content: |
      192.0.2.0/24
      192.0.2.0/25  # overlaps with the /24 above
  - ref: "blocked-2"
    type: cidr
    action: block
    content: |
      203.0.113.0/24
      203.0.113.128/25  # overlaps with the /24 above
```

**Fix:** Remove the redundant / overlapping CIDR or clarify the intent:

```yaml
bunny_waf_access_list_rules:
  - ref: "blocked-1"
    type: cidr
    action: block
    content: |
      192.0.2.0/24
  - ref: "blocked-2"
    type: cidr
    action: block
    content: |
      203.0.113.0/24
```

---
