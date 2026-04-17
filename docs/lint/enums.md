## Enum Validation (BN1xx)

### BN100 — Invalid action value

**Severity:** ERROR

The action must be one of: `block`, `log`, `challenge`, `allow`, `bypass`.

**Triggers on:**

```yaml
  - ref: My rule
    action: deny
```

**Fix:**

```yaml
    action: block
```

### BN101 — Invalid operator value

**Severity:** ERROR

The operator must be one of: `begins_with`, `ends_with`, `contains`, `contains_word`, `str_match`, `eq`, `ge`, `gt`, `le`, `lt`, `within`, `rx`, `str_eq`, `detect_sqli`, `detect_xss`.

**Triggers on:**

```yaml
    conditions:
      - variable: request_uri
        operator: matches
        value: /admin
```

**Fix:**

```yaml
        operator: contains
```

### BN102 — Unknown variable value

**Severity:** WARNING

The variable name is not recognized. See the README for the full list of 26 valid variables.

**Triggers on:**

```yaml
    conditions:
      - variable: request_path
```

**Fix:**

```yaml
      - variable: request_uri
```

### BN103 — Unknown transformation value

**Severity:** WARNING

The transformation name is not recognized. Valid transformations include: `lowercase`, `url_decode`, `html_entity_decode`, `compress_whitespace`, `normalize_path`, `remove_nulls`, `cmdline`, and others (21 total).

**Triggers on:**

```yaml
    transformations:
      - base64
```

**Fix:**

```yaml
    transformations:
      - lowercase
```

### BN104 — Invalid severity value

**Severity:** ERROR

The severity must be one of: `info`, `warning`, `error`.

**Triggers on:**

```yaml
    severity: high
```

**Fix:**

```yaml
    severity: error
```

### BN105 — Invalid regex pattern

**Severity:** ERROR

When the `rx` operator is used, the `value` field must be a valid regular expression. This check compiles the pattern to detect syntax errors before sync.

**Triggers on:**

```yaml
    conditions:
      - variable: request_uri
        operator: rx
        value: "[unclosed"
```

**Fix:** Correct the regex:

```yaml
        value: "\\[unclosed\\]"
```

### BN106 — Operator requires 'value'

**Severity:** ERROR

Most operators require a `value` field. The exceptions are `detect_sqli` and `detect_xss`, which perform built-in detection. All other operators require a non-empty value.

**Triggers on:**

```yaml
    conditions:
      - variable: request_uri
        operator: contains
```

**Fix:**

```yaml
      - variable: request_uri
        operator: contains
        value: /admin
```

### BN107 — Numeric operator on non-numeric variable

**Severity:** WARNING

Numeric comparison operators (`eq`, `ge`, `gt`, `le`, `lt`) are used with a variable that is not typically numeric. Only `args_combined_size` and `response_status` are numeric.

**Triggers on:**

```yaml
      - variable: request_uri
        operator: lt
        value: "5"
```

**Fix:** Use a string operator or target a numeric variable:

```yaml
      - variable: response_status
        operator: lt
        value: "500"
```

### BN108 — Catch-all condition

**Severity:** WARNING

The condition matches all traffic. Common patterns: `contains ""`, `begins_with /`, `rx .*`. If intentional, consider using an access list instead.

**Triggers on:**

```yaml
      - variable: request_uri
        operator: contains
        value: ""
```

**Fix:** Use a more specific value:

```yaml
        value: /admin
```

### BN109 — variable_value on unsupported variable

**Severity:** WARNING

A `variable_value` is set on a variable that doesn't support sub-values. Only `args`, `args_get`, `args_post`, `geo`, `request_cookies`, `request_headers`, and `response_headers` accept sub-values.

**Triggers on:**

```yaml
      - variable: request_uri
        variable_value: path
```

**Fix:** Remove the sub-value:

```yaml
      - variable: request_uri
```

---
