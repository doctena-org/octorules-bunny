# Lint Rule Reference

`octorules lint` performs offline static analysis of your Bunny Shield WAF rules files. **68 rules** with the `BN` prefix cover structure, actions, operators, variables, transformations, conditions, rate limits, access lists, edge rules, cross-rule analysis, and best practices.

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
| [BN001](structure.md#bn001--rule-missing-ref) | Rule missing 'ref' | ERROR |
| [BN002](structure.md#bn002--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [BN003](structure.md#bn003--rule-missing-required-field) | Rule missing required field | ERROR |
| [BN004](structure.md#bn004--unknown-top-level-rule-field) | Unknown top-level rule field | WARNING |
| [BN005](structure.md#bn005--rule-field-has-wrong-type) | Rule field has wrong type | ERROR |
| [BN006](structure.md#bn006--rule-entry-is-not-a-dict) | Rule entry is not a dict | ERROR |
| [BN007](structure.md#bn007--phase-value-is-not-a-list) | Phase value is not a list | ERROR |
| [BN009](structure.md#bn009--duplicate-ref-across-different-phases) | Duplicate ref across different phases | INFO |
| [BN010](structure.md#bn010--invalid-ref-format) | Invalid ref format | ERROR |
| [BN011](structure.md#bn011--description-exceeds-255-characters) | Description exceeds 255 characters | WARNING |
| [BN100](enums.md#bn100--invalid-action-value) | Invalid action value | ERROR |
| [BN101](enums.md#bn101--invalid-operator-value) | Invalid operator value | ERROR |
| [BN102](enums.md#bn102--unknown-variable-value) | Unknown variable value | WARNING |
| [BN103](enums.md#bn103--unknown-transformation-value) | Unknown transformation value | WARNING |
| [BN104](enums.md#bn104--invalid-severity-value) | Invalid severity value | ERROR |
| [BN105](enums.md#bn105--invalid-regex-pattern) | Invalid regex pattern in rx operator | ERROR |
| [BN106](enums.md#bn106--operator-requires-value) | Operator requires 'value' but none provided | ERROR |
| [BN107](enums.md#bn107--numeric-operator-on-non-numeric-variable) | Numeric operator used with non-numeric variable | WARNING |
| [BN108](enums.md#bn108--catch-all-condition) | Catch-all condition (matches all traffic) | WARNING |
| [BN109](enums.md#bn109--variable_value-on-unsupported-variable) | variable_value on unsupported variable | WARNING |
| [BN115](variable-subvalue.md#bn115--variable-requires-variable_value) | Variable requires variable_value but none provided | WARNING |
| [BN116](variable-subvalue.md#bn116--invalid-geo-sub-value) | Invalid GEO sub-value | ERROR |
| [BN117](variable-subvalue.md#bn117--request_headersrequest_cookies-requires-variable_value) | REQUEST_HEADERS/REQUEST_COOKIES requires variable_value | WARNING |
| [BN119](variable-subvalue.md#bn119--regex-starts-with-wildcard) | Regex starts with '.*' or '.+' (performance footgun) | INFO |
| [BN125](transformations.md#bn125--duplicate-transformation) | Duplicate transformation in same rule | WARNING |
| [BN200](rate-limit.md#bn200--request_count-must-be-a-positive-integer) | request_count must be a positive integer | ERROR |
| [BN201](rate-limit.md#bn201--invalid-timeframe-value) | Invalid timeframe value | ERROR |
| [BN202](rate-limit.md#bn202--invalid-block_time-value) | Invalid block_time value | ERROR |
| [BN203](rate-limit.md#bn203--invalid-counter_key_type-value) | Invalid counter_key_type value | ERROR |
| [BN210](rate-limit.md#bn210--very-short-block_time) | Very short block_time (30s) | WARNING |
| [BN300](access-list.md#bn300--invalid-access-list-type) | Invalid access list type | ERROR |
| [BN301](access-list.md#bn301--empty-access-list-content) | Empty access list content | ERROR |
| [BN302](access-list.md#bn302--invalid-cidrip-notation) | Invalid CIDR/IP notation | WARNING |
| [BN303](access-list.md#bn303--invalid-asn-format) | Invalid ASN format | WARNING |
| [BN304](access-list.md#bn304--invalid-country-code) | Invalid country code | WARNING |
| [BN305](access-list.md#bn305--privatereserved-ip-range) | Private/reserved IP range in access list | WARNING |
| [BN306](access-list.md#bn306--cidr-has-host-bits-set) | CIDR has host bits set (auto-correctable) | WARNING |
| [BN307](access-list.md#bn307--overlapping-cidrs) | Overlapping CIDRs within same access list | WARNING |
| [BN308](access-list.md#bn308--invalid-ja4-fingerprint) | Invalid JA4 fingerprint format | WARNING |
| [BN309](access-list.md#bn309--duplicate-entry-in-access-list) | Duplicate entry in access list | WARNING |
| [BN310](access-list.md#bn310--duplicate-organization-entry-in-access-list) | Duplicate organization entry in access list | WARNING |
| [BN400](condition.md#bn400--condition-missing-variable) | Condition missing 'variable' | ERROR |
| [BN401](condition.md#bn401--condition-missing-operator) | Condition missing 'operator' | ERROR |
| [BN402](condition.md#bn402--detect_sqlidetect_xss-ignores-value) | detect_sqli/detect_xss operators ignore 'value' field | WARNING |
| [BN403](condition.md#bn403--duplicate-condition-in-chain) | Duplicate condition in chained conditions | WARNING |
| [BN404](condition.md#bn404--chained-conditions-exceed-10) | Chained conditions exceed 10 | WARNING |
| [BN500](cross-rule.md#bn500--duplicate-conditions-across-rules) | Duplicate conditions across rules in phase | WARNING |
| [BN501](cross-rule.md#bn501--rule-count-exceeds-plan-tier-limit) | Rule count may exceed plan tier limit | WARNING |
| [BN502](cross-rule.md#bn502--conflicting-access-lists) | Conflicting access lists (ip/cidr/country/asn/ja4 overlap with different actions) | WARNING |
| [BN503](cross-rule.md#bn503--rule-likely-unreachable-after-catch-all-terminating-rule) | Rule likely unreachable after catch-all terminating rule | WARNING |
| [BN600](best-practice.md#bn600--very-short-rule-name) | Very short rule name | INFO |
| [BN601](best-practice.md#bn601--rule-has-no-description) | Rule has no description | INFO |
| [BN602](best-practice.md#bn602--access-list-is-disabled) | Access list is disabled (enabled: false) | INFO |
| [BN700](edge-rule.md#bn700--invalid-or-missing-edge-rule-action_type) | Invalid or missing edge rule action_type | ERROR |
| [BN701](edge-rule.md#bn701--invalid-or-missing-edge-rule-trigger-type) | Invalid or missing edge rule trigger type | ERROR |
| [BN702](edge-rule.md#bn702--edge-rule-has-no-triggers) | Edge rule has no triggers | ERROR |
| [BN703](edge-rule.md#bn703--invalid-edge-rule-trigger_matching_type) | Invalid edge rule trigger_matching_type | ERROR |
| [BN704](edge-rule.md#bn704--edge-rule-trigger-has-empty-pattern_matches) | Edge rule trigger has empty pattern_matches | WARNING |
| [BN705](edge-rule.md#bn705--invalid-edge-rule-pattern_matching_type) | Invalid edge rule pattern_matching_type | ERROR |
| [BN706](edge-rule.md#bn706--edge-rule-action-missing-required-parameter) | Edge rule action missing required parameter | ERROR |
| [BN707](edge-rule.md#bn707--edge-rule-trigger-has-empty-pattern) | Edge rule trigger has empty/whitespace pattern | ERROR |
| [BN708](edge-rule.md#bn708--invalid-country-code-in-country_code-trigger) | Invalid country code in country_code trigger | ERROR |
| [BN709](edge-rule.md#bn709--invalid-ipcidr-in-remote_ip-trigger) | Invalid IP/CIDR in remote_ip trigger | ERROR |
| [BN710](edge-rule.md#bn710--invalid-http-method-in-request_method-trigger) | Invalid HTTP method in request_method trigger | ERROR |
| [BN711](edge-rule.md#bn711--status-code-out-of-range-in-status_code-trigger) | Status code out of range (100-900) in status_code trigger | ERROR |
| [BN712](edge-rule.md#bn712--malformed-lua-pattern) | Malformed Lua pattern (pattern: prefix) | ERROR |
| [BN713](edge-rule.md#bn713--url-trigger-pattern-format) | URL trigger pattern must start with /, http, or * | WARNING |
| [BN715](edge-rule.md#bn715--redirect-status-code-range) | Redirect status code must be 300-399 | ERROR |

---

## Categories

| Category | BN Range | Rules | Details |
|----------|----------|-------|--------|
| Structure | BN001–BN011 | 10 | [structure.md](structure.md) |
| Enum validation | BN100–BN109 | 10 | [enums.md](enums.md) |
| Variable sub-value validation | BN115–BN119 | 4 | [variable-subvalue.md](variable-subvalue.md) |
| Transformation checks | BN125 | 1 | [transformations.md](transformations.md) |
| Rate limit | BN200–BN210 | 5 | [rate-limit.md](rate-limit.md) |
| Access list | BN300–BN310 | 11 | [access-list.md](access-list.md) |
| Condition validation | BN400–BN404 | 5 | [condition.md](condition.md) |
| Cross-rule analysis | BN500–BN503 | 4 | [cross-rule.md](cross-rule.md) |
| Best practice | BN600–BN602 | 3 | [best-practice.md](best-practice.md) |
| Edge rules | BN700–BN715 | 15 | [edge-rule.md](edge-rule.md) |
