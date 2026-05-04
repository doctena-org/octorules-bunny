## Variable Sub-Value Validation (BN115–BN124, BN521)

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

### BN123 — Percent-encoded literal value

**Severity:** WARNING

A condition uses a percent-encoded literal (e.g., `%2F` for `/`, `%20` for space) on a decoded URI variable (`request_uri`, `request_filename`, `request_basename`). These variables are already decoded, so the encoded literal will never match. Use the decoded form instead, or switch to `request_uri_raw` if matching the encoded form is intentional.

**Triggers on:**

```yaml
      - variable: request_uri
        operator: contains
        value: "%2Fadmin"  # will never match decoded /admin
```

**Fix:** Use the decoded value:

```yaml
        value: "/admin"
```

Or use `request_uri_raw` if matching the encoded form:

```yaml
      - variable: request_uri_raw
        operator: contains
        value: "%2Fadmin"
```

### BN124 — `contains_word` with whitespace

**Severity:** WARNING

The `contains_word` operator matches at word boundaries. A value containing whitespace (spaces, tabs, newlines) can never match because `contains_word` cannot span multiple words while respecting boundary semantics. Use `contains` for substring matching or re-examine the intent.

**Triggers on:**

```yaml
      - variable: request_uri
        operator: contains_word
        value: "admin panel"  # impossible to match as a word
```

**Fix:** Use `contains` for substring matching:

```yaml
        operator: contains
        value: "admin panel"
```

Or split into separate conditions:

```yaml
      - variable: request_uri
        operator: contains_word
        value: "admin"
      - variable: request_uri
        operator: contains_word
        value: "panel"
```

### BN521 — Path-prefix should start with slash

**Severity:** WARNING

A condition on `request_uri` or `request_filename` uses a literal-comparison operator (`begins_with`, `ends_with`, `contains`, `contains_word`, `str_match`, `str_eq`, `eq`) with a value that does not start with `/`. For path-matching intent, values should start with `/` to avoid accidental substring matches. This check does not fire on `rx` (regex bodies legitimately omit `/`) or `request_uri_raw` (may have different encoding semantics).

**Triggers on:**

```yaml
      - variable: request_uri
        operator: begins_with
        value: "admin"  # matches /administration, /unadmin, etc.
```

**Fix:** Add the leading slash:

```yaml
        value: "/admin"
```

Or use a more specific operator if the intent is substring matching.

---
