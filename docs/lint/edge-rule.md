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

### BN706 — Edge rule action missing required parameter

**Severity:** ERROR

An edge rule's `action_type` requires one or both `action_parameter_1` / `action_parameter_2` fields, but they are empty or missing.

Actions requiring `action_parameter_1`: `redirect`, `set_response_header`, `set_request_header`, `set_status_code`, `override_cache_time`, `override_cache_time_public`, `override_browser_cache_time`, `set_network_rate_limit`, `set_connection_limit`, `set_requests_per_second_limit`, `remove_browser_cache_response_header`, `override_browser_cache_response_header`, `origin_url`, `run_edge_script`.

Actions also requiring `action_parameter_2`: `redirect`, `set_response_header`, `set_request_header`.

**Triggers on:**

```yaml
bunny_edge_rules:
  - ref: bad redirect
    action_type: redirect
    action_parameter_1: ""
    triggers:
      - type: url
        pattern_matches:
          - "*"
```

**Fix:** Provide the required parameter(s) for the action type.

### BN707 — Edge rule trigger has empty pattern

**Severity:** ERROR

A `pattern_matches` entry is empty or whitespace-only. The Bunny API rejects these with "Each condition is required to have at least one trigger".

**Triggers on:**

```yaml
bunny_edge_rules:
  - ref: bad
    triggers:
      - type: url
        pattern_matches:
          - "http://*"
          - ""           # empty string — invalid
```

**Fix:** Remove empty entries or replace with valid patterns.

### BN708 — Invalid country code in country_code trigger

**Severity:** ERROR

A `country_code` trigger pattern is not a valid ISO 3166-1 alpha-2 country code (two uppercase letters).

**Triggers on:**

```yaml
triggers:
  - type: country_code
    pattern_matches:
      - USA      # 3 letters
      - us       # lowercase
```

**Fix:** Use two uppercase letters: `US`, `GB`, `DE`, etc. (Lua `pattern:` patterns bypass this check.)

### BN709 — Invalid IP/CIDR in remote_ip trigger

**Severity:** ERROR

A `remote_ip` trigger pattern is not a valid IPv4/IPv6 address or CIDR block.

**Triggers on:**

```yaml
triggers:
  - type: remote_ip
    pattern_matches:
      - not-an-ip
      - 192.168.1.300
```

**Fix:** Use a valid IP (`192.168.1.1`, `2001:db8::1`) or CIDR (`10.0.0.0/8`, `fe80::/10`). Lua `pattern:` patterns bypass this check.

### BN710 — Invalid HTTP method in request_method trigger

**Severity:** ERROR

A `request_method` trigger pattern is not a standard HTTP method (uppercase).

Valid methods: `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`.

**Triggers on:**

```yaml
triggers:
  - type: request_method
    pattern_matches:
      - get      # lowercase
      - YEET     # not a method
```

**Fix:** Use uppercase standard HTTP methods.

### BN711 — Status code out of range in status_code trigger

**Severity:** ERROR

A `status_code` trigger pattern is not an integer between 100 and 900 (enforced by the Bunny API).

**Triggers on:**

```yaml
triggers:
  - type: status_code
    pattern_matches:
      - "99"           # below 100
      - "999"          # above 900
      - "forbidden"    # non-numeric
```

**Fix:** Use a numeric HTTP status code between 100 and 900.

### BN712 — Malformed Lua pattern

**Severity:** ERROR

A pattern prefixed with `pattern:` contains malformed [Lua pattern](https://docs.bunny.net/cdn/edge-rules/pattern-matching) syntax — unclosed character set (`[...`), trailing escape (`%`), or empty body after the prefix.

Lua patterns use a simplified syntax: `%a`/`%d`/`%w` for classes, `[abc]`/`[^abc]` for sets, `+`/`*`/`-` repeaters, `%` as the escape character. Alternation (`|`), lookaheads, and PCRE syntax are **not** supported.

**Triggers on:**

```yaml
triggers:
  - type: url
    pattern_matches:
      - "pattern:[bad"           # unclosed bracket
      - "pattern:foo%"           # trailing escape
      - "pattern:"               # empty pattern
```

**Fix:** Close character sets, escape the final character, or remove the `pattern:` prefix to use literal/glob matching.

### BN713 — URL trigger pattern format

**Severity:** WARNING

An edge rule `type: url` trigger has a `pattern_matches` entry that doesn't start with `/`, `http`, or `*`. Such patterns never match any URL — the engine compares against the full path.

**Triggers on:**

```yaml
triggers:
  - type: url
    pattern_matches:
      - "admin"       # should be "/admin" or "*admin*"
```

**Fix:** Prefix with `/` for paths, `http` for full URLs, or `*` for wildcards. Lua `pattern:` patterns bypass this check.

### BN715 — Redirect status code range

**Severity:** ERROR

An edge rule with `action_type: redirect` has `action_parameter_2` set to a value outside the HTTP redirect range (300-399). Non-3xx codes won't trigger a browser redirect.

Common valid codes: `301` (permanent), `302` (temporary), `303` (see other), `307` (temporary, preserve method), `308` (permanent, preserve method).

**Triggers on:**

```yaml
bunny_edge_rules:
  - ref: bad redirect
    action_type: redirect
    action_parameter_1: https://example.com/new
    action_parameter_2: "200"   # not a redirect code
```

**Fix:** Use a status code in 300-399.
