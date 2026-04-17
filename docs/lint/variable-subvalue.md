## Variable Sub-Value Validation (BN115-BN117)

### BN115 — Variable requires variable_value

**Severity:** WARNING

The `geo` variable requires a `variable_value` to specify what geographic field to match. Valid sub-values: `COUNTRY_CODE`, `LATITUDE`, `LONGITUDE`, `ASN`, `CITY`, `CONTINENT`.

**Triggers on:**

```yaml
      - variable: geo
        operator: str_eq
        value: US
```

**Fix:**

```yaml
      - variable: geo
        variable_value: COUNTRY_CODE
        operator: str_eq
        value: US
```

### BN116 — Invalid GEO sub-value

**Severity:** ERROR

The `variable_value` for `geo` must be one of: `COUNTRY_CODE`, `LATITUDE`, `LONGITUDE`, `ASN`, `CITY`, `CONTINENT`. Case-sensitive (uppercase).

**Triggers on:**

```yaml
        variable_value: country
```

**Fix:**

```yaml
        variable_value: COUNTRY_CODE
```

### BN117 — REQUEST_HEADERS/REQUEST_COOKIES requires variable_value

**Severity:** WARNING

The `request_headers` and `request_cookies` variables require a `variable_value` specifying which header or cookie name to inspect.

**Triggers on:**

```yaml
      - variable: request_headers
        operator: contains
        value: bot
```

**Fix:**

```yaml
      - variable: request_headers
        variable_value: User-Agent
        operator: contains
        value: bot
```

---

### BN119 — Regex starts with wildcard

**Severity:** INFO

A `rx` operator's regex pattern starts with `.*` or `.+`. Bunny's regex matching is unanchored by default, so the leading wildcard is redundant and forces the engine to backtrack, hurting performance.

**Triggers on:**

```yaml
conditions:
  - variable: request_uri
    operator: rx
    value: ".*admin"  # redundant .* prefix
```

**Fix:** Remove the leading wildcard — `admin` matches the same set of URIs, faster.

---
