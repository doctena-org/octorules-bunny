# Lint Rule Reference

`octorules lint` performs offline static analysis of your Bunny Shield WAF rules files. **55 rules** with the `BN` prefix cover structure, actions, operators, variables, transformations, conditions, rate limits, access lists, edge rules, cross-rule analysis, and best practices.

These rules are registered automatically when `octorules-bunny` is installed. They run alongside any core and other provider rules during `octorules lint`.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

```yaml
bunny_waf_custom_rules:
  # octorules:disable=BN010
  - ref: legacy-rule
    action: block
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
```

**Multiple rules:**

```yaml
  # octorules:disable=BN004,BN601
  - ref: Special rule
    action: block
    custom_field: something
    conditions:
      - variable: request_uri
        operator: contains
        value: /test
```

Suppressed findings are excluded from the report but counted in the summary line (e.g., `Total: 0 error(s), 0 warning(s), 0 info (1 suppressed)`).

### Severity levels

| Level | Meaning |
|-------|---------|
| **ERROR** | Invalid config that will fail at Bunny Shield API |
| **WARNING** | Likely mistake or suboptimal pattern |
| **INFO** | Style suggestion or best practice |

---

## Rule ID Quick Reference

| ID | Description | Severity |
|----|-------------|----------|
| [BN001](#bn001--rule-missing-ref) | Rule missing 'ref' | ERROR |
| [BN002](#bn002--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [BN003](#bn003--rule-missing-required-field) | Rule missing required field | ERROR |
| [BN004](#bn004--unknown-top-level-rule-field) | Unknown top-level rule field | WARNING |
| [BN005](#bn005--rule-field-has-wrong-type) | Rule field has wrong type | ERROR |
| [BN006](#bn006--rule-entry-is-not-a-dict) | Rule entry is not a dict | ERROR |
| [BN007](#bn007--phase-value-is-not-a-list) | Phase value is not a list | ERROR |
| [BN010](#bn010--invalid-ref-format) | Invalid ref format | ERROR |
| [BN011](#bn011--description-exceeds-255-characters) | Description exceeds 255 characters | WARNING |
| [BN100](#bn100--invalid-action-value) | Invalid action value | ERROR |
| [BN101](#bn101--invalid-operator-value) | Invalid operator value | ERROR |
| [BN102](#bn102--unknown-variable-value) | Unknown variable value | WARNING |
| [BN103](#bn103--unknown-transformation-value) | Unknown transformation value | WARNING |
| [BN104](#bn104--invalid-severity-value) | Invalid severity value | ERROR |
| [BN105](#bn105--invalid-regex-pattern) | Invalid regex pattern in rx operator | ERROR |
| [BN106](#bn106--operator-requires-value) | Operator requires 'value' but none provided | ERROR |
| [BN107](#bn107--numeric-operator-on-non-numeric-variable) | Numeric operator used with non-numeric variable | WARNING |
| [BN108](#bn108--catch-all-condition) | Catch-all condition (matches all traffic) | WARNING |
| [BN109](#bn109--variable_value-on-unsupported-variable) | variable_value on unsupported variable | WARNING |
| [BN115](#bn115--variable-requires-variable_value) | Variable requires variable_value but none provided | WARNING |
| [BN116](#bn116--invalid-geo-sub-value) | Invalid GEO sub-value | ERROR |
| [BN117](#bn117--request_headersrequest_cookies-requires-variable_value) | REQUEST_HEADERS/REQUEST_COOKIES requires variable_value | WARNING |
| [BN125](#bn125--duplicate-transformation) | Duplicate transformation in same rule | WARNING |
| [BN200](#bn200--request_count-must-be-a-positive-integer) | request_count must be a positive integer | ERROR |
| [BN201](#bn201--invalid-timeframe-value) | Invalid timeframe value | ERROR |
| [BN202](#bn202--invalid-block_time-value) | Invalid block_time value | ERROR |
| [BN203](#bn203--invalid-counter_key_type-value) | Invalid counter_key_type value | ERROR |
| [BN210](#bn210--very-short-block_time) | Very short block_time (30s) | WARNING |
| [BN300](#bn300--invalid-access-list-type) | Invalid access list type | ERROR |
| [BN301](#bn301--empty-access-list-content) | Empty access list content | ERROR |
| [BN302](#bn302--invalid-cidrip-notation) | Invalid CIDR/IP notation | WARNING |
| [BN303](#bn303--invalid-asn-format) | Invalid ASN format | WARNING |
| [BN304](#bn304--invalid-country-code) | Invalid country code | WARNING |
| [BN305](#bn305--privatereserved-ip-range) | Private/reserved IP range in access list | WARNING |
| [BN306](#bn306--cidr-has-host-bits-set) | CIDR has host bits set (auto-correctable) | WARNING |
| [BN307](#bn307--overlapping-cidrs) | Overlapping CIDRs within same access list | WARNING |
| [BN308](#bn308--invalid-ja4-fingerprint) | Invalid JA4 fingerprint format | WARNING |
| [BN309](#bn309--duplicate-ip-in-access-list) | Duplicate IP/CIDR in access list | WARNING |
| [BN400](#bn400--condition-missing-variable) | Condition missing 'variable' | ERROR |
| [BN401](#bn401--condition-missing-operator) | Condition missing 'operator' | ERROR |
| [BN402](#bn402--detect_sqlidetect_xss-ignores-value) | detect_sqli/detect_xss operators ignore 'value' field | WARNING |
| [BN403](#bn403--duplicate-condition-in-chain) | Duplicate condition in chained conditions | WARNING |
| [BN404](#bn404--chained-conditions-exceed-10) | Chained conditions exceed 10 | WARNING |
| [BN500](#bn500--duplicate-conditions-across-rules) | Duplicate conditions across rules in phase | WARNING |
| [BN501](#bn501--rule-count-exceeds-plan-tier-limit) | Rule count may exceed plan tier limit | WARNING |
| [BN502](#bn502--conflicting-access-lists) | Conflicting access lists (ip/cidr/country/asn/ja4 overlap with different actions) | WARNING |
| [BN600](#bn600--very-short-rule-name) | Very short rule name | INFO |
| [BN601](#bn601--rule-has-no-description) | Rule has no description | INFO |
| [BN602](#bn602--access-list-is-disabled) | Access list is disabled (enabled: false) | INFO |
| [BN700](#bn700--invalid-or-missing-edge-rule-action_type) | Invalid or missing edge rule action_type | ERROR |
| [BN701](#bn701--invalid-or-missing-edge-rule-trigger-type) | Invalid or missing edge rule trigger type | ERROR |
| [BN702](#bn702--edge-rule-has-no-triggers) | Edge rule has no triggers | ERROR |
| [BN703](#bn703--invalid-edge-rule-trigger_matching_type) | Invalid edge rule trigger_matching_type | ERROR |
| [BN704](#bn704--edge-rule-trigger-has-empty-pattern_matches) | Edge rule trigger has empty pattern_matches | WARNING |
| [BN705](#bn705--invalid-edge-rule-pattern_matching_type) | Invalid edge rule pattern_matching_type | ERROR |

---

## Structure (BN0xx)

### BN001 — Rule missing 'ref'

**Severity:** ERROR

Every rule must have a `ref` field that uniquely identifies it within the phase. For custom WAF and rate limit rules, this becomes the `ruleName` in the Bunny API. For access lists, this is the API-assigned numeric ID (discovered via `octorules dump`).

**Triggers on:**

```yaml
bunny_waf_custom_rules:
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
bunny_waf_custom_rules:
  - ref: Block bots
    action: block
    conditions: [...]
  - ref: Block bots
    action: challenge
    conditions: [...]
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
bunny_waf_custom_rules:
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
bunny_waf_custom_rules:
  - ref: My rule
    action: block
    aciton: challenge
    conditions: [...]
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
bunny_waf_custom_rules:
  - "not a dict"         # <-- string instead of mapping
```

**Fix:** Replace the scalar with a proper rule mapping.

### BN007 — Phase value is not a list

**Severity:** ERROR

Each phase key must map to a YAML list (sequence). A scalar, mapping, or
null value is always an authoring mistake -- rules files expect a list of
rule entries under each phase.

**Triggers on:**

```yaml
bunny_waf_custom_rules: "not a list"
```

**Fix:** Use a proper list:

```yaml
bunny_waf_custom_rules:
  - ref: Block admin
    action: block
    conditions:
      - variable: request_uri
        operator: contains
        value: /admin
```

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

### BN011 — Description exceeds 255 characters

**Severity:** WARNING

Rule descriptions longer than 255 characters may be truncated by the API.

**Triggers on:** A `description` field with more than 255 characters.

**Fix:** Shorten the description.

---

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

The `timeframe` must be one of: `1s`, `10s`, `1m`, `5m`, `15m`, `1h`. The free plan only supports up to `10s`. Also fires when the `timeframe` field is entirely missing from a rate limit rule.

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

## Access List (BN3xx)

### BN300 — Invalid access list type

**Severity:** ERROR

The `type` must be one of: `ip`, `cidr`, `asn`, `country`, `organization`, `ja4`.

**Triggers on:**

```yaml
bunny_waf_access_list_rules:
  - ref: "1"
    type: hostname
```

**Fix:**

```yaml
    type: ip
```

### BN301 — Empty access list content

**Severity:** ERROR

The `content` field must contain at least one entry. Each entry is on a separate line.

**Triggers on:**

```yaml
    content: ""
```

**Fix:**

```yaml
    content: |
      CN
      RU
```

### BN302 — Invalid CIDR/IP notation

**Severity:** WARNING

For `ip` and `cidr` type access lists, each entry must be a valid IP address or CIDR range.

**Triggers on:**

```yaml
    type: ip
    content: |
      not-an-ip
```

**Fix:**

```yaml
    content: |
      192.0.2.1
```

### BN303 — Invalid ASN format

**Severity:** WARNING

For `asn` type access lists, each entry must be numeric or AS-prefixed (e.g., `13335` or `AS13335`).

**Triggers on:**

```yaml
    type: asn
    content: |
      cloudflare
```

**Fix:**

```yaml
    content: |
      AS13335
```

### BN304 — Invalid country code

**Severity:** WARNING

For `country` type access lists, each entry must be exactly 2 uppercase letters (ISO 3166-1 alpha-2).

**Triggers on:**

```yaml
    content: |
      usa
```

**Fix:**

```yaml
    content: |
      US
```

### BN305 — Private/reserved IP range

**Severity:** WARNING

An IP or CIDR falls within a private/reserved range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1/128, fc00::/7). These are not routable on the public internet.

**Triggers on:**

```yaml
    type: ip
    content: |
      192.168.1.1
```

**Fix:**

```yaml
    content: |
      203.0.113.50
```

### BN306 — CIDR has host bits set

**Severity:** WARNING

A CIDR has host bits set (e.g., `10.0.0.1/24`). The API normalises to the network address, causing phantom diffs on the next plan.

**Triggers on:**

```yaml
    type: cidr
    content: |
      10.0.0.1/24
```

**Fix:**

```yaml
    content: |
      10.0.0.0/24
```

### BN307 — Overlapping CIDRs

**Severity:** WARNING

Two CIDRs in the same access list overlap. The broader range already covers the narrower one.

**Triggers on:**

```yaml
    type: cidr
    content: |
      10.0.0.0/8
      10.1.0.0/16
```

**Fix:** Remove the narrower range:

```yaml
    content: |
      10.0.0.0/8
```

### BN308 — Invalid JA4 fingerprint

**Severity:** WARNING

For `ja4` type access lists, each entry must be a valid JA4 TLS fingerprint — exactly 36 characters in the format `a_b_c`:

- Section A (10 chars): protocol (`t`/`q`/`d`) + TLS version + SNI + cipher count + extension count + ALPN
- Section B (12 chars): truncated SHA-256 of cipher suites (lowercase hex)
- Section C (12 chars): truncated SHA-256 of extensions (lowercase hex)

**Triggers on:**

```yaml
    type: ja4
    content: |
      not-a-fingerprint
```

**Fix:**

```yaml
    content: |
      t13d1516h2_8daaf6152771_e5627efa2ab1
```

### BN309 — Duplicate IP/CIDR in access list

**Severity:** WARNING

The same IP address or CIDR range appears more than once in a single `ip` or `cidr` type access list. Duplicates waste capacity and may indicate a copy-paste error. IPv6 addresses are normalised to lowercase before comparison so that `2001:DB8::1` and `2001:db8::1` are detected as duplicates.

**Triggers on:**

```yaml
    type: ip
    content: |
      1.2.3.4
      5.6.7.0/24
      1.2.3.4
```

```yaml
    type: cidr
    content: |
      2001:DB8::1/128
      2001:db8::1/128
```

**Fix:** Remove the duplicate entry:

```yaml
    type: ip
    content: |
      1.2.3.4
      5.6.7.0/24
```

---

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

| Plan | Custom WAF | Rate Limits |
|------|:----------:|:-----------:|
| Free | 0 | 2 |
| Advanced | 10 | 10 |

**Fix:** Upgrade your plan or reduce rule count.

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

---

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

## Edge Rules (BN7xx)

### BN700 — Invalid or missing edge rule action_type

**Severity:** ERROR

Every edge rule must have a valid `action_type`. Valid values: `block_request`, `bypass_aws_s3_authentication`, `bypass_perma_cache`, `disable_optimizer`, `disable_request_coalescing`, `disable_shield`, `disable_shield_access_lists`, `disable_shield_bot_detection`, `disable_shield_challenge`, `disable_shield_rate_limiting`, `disable_token_auth`, `disable_waf`, `enable_request_coalescing`, `enable_token_auth`, `force_compression`, `force_download`, `force_ssl`, `ignore_query_string`, `origin_magic_containers`, `origin_storage`, `origin_url`, `override_browser_cache_response_header`, `override_browser_cache_time`, `override_cache_time`, `override_cache_time_public`, `redirect`, `remove_browser_cache_response_header`, `retry_origin`, `run_edge_script`, `set_connection_limit`, `set_network_rate_limit`, `set_request_header`, `set_requests_per_second_limit`, `set_response_header`, `set_status_code`.

**Triggers on:**

```yaml
bunny_edge_rules:
  - ref: My edge rule
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

or:

```yaml
  - ref: My edge rule
    action_type: invalid_action
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

**Fix:** Add or correct the `action_type`:

```yaml
  - ref: My edge rule
    action_type: force_ssl
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

### BN701 — Invalid or missing edge rule trigger type

**Severity:** ERROR

Every trigger must have a valid `type`. Valid values: `cookie`, `country_code`, `country_state_code`, `origin_connection_error`, `origin_retry_attempt_count`, `random_chance`, `remote_ip`, `request_header`, `request_method`, `response_header`, `status_code`, `url`, `url_extension`, `url_query_string`.

**Triggers on:**

```yaml
    triggers:
      - pattern_matches:
          - "*.example.com"
```

or:

```yaml
    triggers:
      - type: hostname
        pattern_matches:
          - "*.example.com"
```

**Fix:**

```yaml
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

### BN702 — Edge rule has no triggers

**Severity:** ERROR

An edge rule must have at least one trigger. Without triggers the rule cannot match any request.

**Triggers on:**

```yaml
  - ref: My edge rule
    action_type: force_ssl
```

or:

```yaml
  - ref: My edge rule
    action_type: force_ssl
    triggers: []
```

**Fix:** Add at least one trigger:

```yaml
  - ref: My edge rule
    action_type: force_ssl
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

### BN703 — Invalid edge rule trigger_matching_type

**Severity:** ERROR

The top-level `trigger_matching_type` controls how multiple triggers are combined. Valid values: `any` (at least one trigger must match), `all` (all triggers must match), `none` (no trigger must match).

**Triggers on:**

```yaml
  - ref: My edge rule
    action_type: force_ssl
    trigger_matching_type: first
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

**Fix:**

```yaml
    trigger_matching_type: all
```

### BN704 — Edge rule trigger has empty pattern_matches

**Severity:** WARNING

A trigger's `pattern_matches` list is empty. Without patterns the trigger cannot match any request.

**Triggers on:**

```yaml
    triggers:
      - type: url
        pattern_matches: []
```

**Fix:** Add at least one pattern:

```yaml
    triggers:
      - type: url
        pattern_matches:
          - "*.example.com"
```

### BN705 — Invalid edge rule pattern_matching_type

**Severity:** ERROR

Each trigger can specify a `pattern_matching_type` controlling how the patterns in `pattern_matches` are evaluated. Valid values: `any` (match if any pattern matches), `all` (match if all patterns match), `none` (match if no pattern matches).

**Triggers on:**

```yaml
    triggers:
      - type: url
        pattern_matching_type: first
        pattern_matches:
          - "*.example.com"
```

**Fix:**

```yaml
        pattern_matching_type: any
```
