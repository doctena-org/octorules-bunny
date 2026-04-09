# octorules-bunny

Bunny.net Shield WAF provider for [octorules](https://github.com/doctena-org/octorules) — manages Bunny Shield custom WAF rules, rate limits, access lists, edge rules, managed rule overrides, pull zone security, and bot/DDoS configuration as YAML.

> **Alpha** — this provider has comprehensive offline test coverage (486 tests)
> but has not yet been tested against live Bunny Shield APIs. Use with caution
> and report any issues.

## Installation

```bash
pip install octorules-bunny
```

This installs octorules (core) and octorules-bunny. The provider is auto-discovered — no `class:` needed in config.

## Configuration

```yaml
# config.yaml
providers:
  bunny:
    api_key: env/BUNNY_API_KEY
  rules:
    directory: ./rules

zones:
  my-blog:
    sources:
      - rules
  api-backend:
    sources:
      - rules
```

Each zone name maps to a Bunny Pull Zone name. The provider resolves pull zone names to Shield Zone IDs at runtime. The `env/` prefix resolves values from environment variables at runtime. All keys under the provider section are forwarded to the provider constructor as keyword arguments (octodns-style passthrough).

### Authentication

Set `BUNNY_API_KEY` to your Bunny.net account API key (found at https://dash.bunny.net under Account Settings). The key is account-scoped — one key covers all pull zones.

### Provider settings

All settings below go under the provider section (e.g. `providers.bunny`).

| Key | Default | Description |
|-----|---------|-------------|
| `api_key` | `BUNNY_API_KEY` env var | Bunny.net API key |
| `timeout` | `30` | API timeout in seconds |
| `max_retries` | `2` | API retry count (retries on 429/5xx) |
| `max_workers` | `1` | Parallel workers for multi-zone operations |

Safety thresholds are configured under `safety:` (framework-owned, not forwarded to the provider):

| Key | Default | Description |
|-----|---------|-------------|
| `safety.delete_threshold` | `30.0` | Max % of rules that can be deleted |
| `safety.update_threshold` | `30.0` | Max % of rules that can be updated |
| `safety.min_existing` | `3` | Min rules before thresholds apply |

## Supported features

| Feature | Status |
|---------|--------|
| Phase rules (4 phases) | Supported |
| Edge rules (redirects, headers, force SSL, blocking) | Supported |
| Pull zone security (blocked IPs/countries/referrers, token auth, CORS) | Supported |
| Managed WAF rule overrides | Supported |
| Shield config (bot/DDoS) | Supported |
| Zone discovery (`list_zones`) | Supported |
| Audit IP extraction (`octorules audit`) | Supported |
| Custom rulesets | Not supported (Bunny API limitation) |
| Lists | Not supported (use access list phase instead) |

## Zone File Example

```yaml
# rules/my-cdn.yaml
---
bunny_waf_custom_rules:
  - ref: Block SQLi
    action: block
    severity: error
    description: Detect SQL injection in request body
    conditions:
      - variable: request_body
        operator: detect_sqli
    transformations:
      - lowercase
      - url_decode

  - ref: Block bad bots
    action: challenge
    severity: warning
    description: Challenge requests from known bot user agents
    conditions:
      - variable: request_headers
        variable_value: User-Agent
        operator: rx
        value: "(curl|wget|python-requests)"
    transformations:
      - lowercase

  - ref: Block admin from CN
    action: block
    severity: error
    description: Block access to admin panel from China
    conditions:
      - variable: request_uri
        operator: begins_with
        value: /admin
      - variable: geo
        variable_value: COUNTRY_CODE
        operator: str_eq
        value: CN

bunny_waf_rate_limit_rules:
  - ref: API rate limit
    action: block
    description: Rate limit API endpoints
    request_count: 100
    timeframe: 1m
    block_time: 5m
    counter_key_type: ip
    conditions:
      - variable: request_uri
        operator: begins_with
        value: /api/

bunny_waf_access_list_rules:
  - ref: "42"
    type: country
    action: block
    enabled: true
    content: |
      CN
      RU

  - ref: "43"
    type: ip
    action: allow
    enabled: true
    content: |
      203.0.113.0/24

bunny_waf_managed_rules:
  disabled:
    - "941100"
    - "942100"
  log_only:
    - "930100"

bunny_shield_config:
  bot_detection:
    execution_mode: block
    request_integrity_sensitivity: medium
    ip_sensitivity: medium
    fingerprint_sensitivity: high
    complex_fingerprinting: true
  ddos:
    shield_sensitivity: medium
    execution_mode: block
    challenge_window: 300
```

## Phases

| Phase | YAML key | Description |
|-------|----------|-------------|
| Custom WAF | `bunny_waf_custom_rules` | Custom WAF rules with conditions, operators, and actions |
| Rate Limit | `bunny_waf_rate_limit_rules` | Rate limiting rules with thresholds and block times |
| Access List | `bunny_waf_access_list_rules` | IP/CIDR/ASN/Country/Org/JA4 block/allow lists |
| Edge Rules | `bunny_edge_rules` | CDN-level edge rules (redirects, header manipulation, force SSL, blocking) |

## Non-Phase Sections

| YAML key | Description |
|----------|-------------|
| `bunny_waf_managed_rules` | Disable or log-only individual managed WAF rules |
| `bunny_shield_config` | Bot detection and DDoS protection configuration |
| `bunny_pullzone_security` | Pull zone security: blocked IPs/countries/referrers, token auth, CORS |

## Actions

| Action | API Value | Description |
|--------|:---------:|-------------|
| `block` | 1 | Block the request |
| `log` | 2 | Log only (no enforcement) |
| `challenge` | 3 | JavaScript proof-of-work challenge |
| `allow` | 4 | Explicitly allow the request |
| `bypass` | 5 | Bypass all further WAF processing |

## Operators

| Operator | API Value | Description |
|----------|:---------:|-------------|
| `begins_with` | 0 | String prefix match |
| `ends_with` | 1 | String suffix match |
| `contains` | 2 | Substring match |
| `contains_word` | 3 | Word-level match |
| `str_match` | 4 | Case-sensitive exact match |
| `eq` | 5 | Integer equality |
| `ge` | 6 | Greater or equal |
| `gt` | 7 | Greater than |
| `le` | 8 | Less or equal |
| `lt` | 9 | Less than |
| `within` | 12 | Substring containment |
| `rx` | 14 | Regular expression |
| `str_eq` | 15 | Case-insensitive exact match |
| `detect_sqli` | 17 | SQL injection detection (no value needed) |
| `detect_xss` | 18 | XSS detection (no value needed) |

## Variables

| Variable | API Value | Sub-value? | Description |
|----------|:---------:|:----------:|-------------|
| `request_uri` | 0 | No | Request URI |
| `request_uri_raw` | 1 | No | Raw request URI |
| `args` | 2 | Optional | All arguments |
| `args_combined_size` | 3 | No | Total argument size |
| `args_get` | 4 | Optional | GET parameters |
| `args_post` | 6 | Optional | POST parameters |
| `geo` | 9 | **Required** | Geographic data (COUNTRY_CODE, ASN, CITY, CONTINENT, LATITUDE, LONGITUDE) |
| `remote_addr` | 10 | No | Client IP address |
| `query_string` | 11 | No | Query string |
| `request_body` | 13 | No | Request body |
| `request_cookies` | 15 | **Required** | Cookie (specify cookie name as variable_value) |
| `request_headers` | 18 | **Required** | Header (specify header name as variable_value) |
| `request_method` | 20 | No | HTTP method |
| `response_status` | 24 | No | Response status code |
| `fingerprint` | 25 | No | Client fingerprint |

See `octorules_bunny/_enums.py` for the complete list of 26 variables.

## Rule Name Constraints

Custom WAF and rate limit rule names (`ref`) must match `[a-zA-Z0-9 ]+` (alphanumeric characters and spaces only). No hyphens, underscores, or special characters. This is an API constraint enforced by Bunny.

Access list `ref` values are API-assigned numeric IDs. Use `octorules dump` to discover IDs after initial creation in the Bunny dashboard.

## Sync Behavior

Bunny Shield does not support atomic bulk rule replacement. The provider uses a diff-and-reconcile strategy:

1. **Patch** existing rules (ref exists in both old and new)
2. **Add** new rules (ref only in desired YAML)
3. **Remove** stale rules (ref only in current API state)

This order ensures the zone never has *fewer* rules than intended during sync.

## Plan Limits

| Plan | Custom WAF Rules | Rate Limits | Access Lists |
|------|:----------------:|:-----------:|:------------:|
| Free | 0 | 2 | Managed only |
| Advanced ($9.50/mo) | 10 | 10 | Custom + managed |
| Enterprise | Unlimited | Unlimited | Full |

## Linting

55 lint rules with the `BN` prefix validate your rules offline before sync. See [docs/lint.md](docs/lint.md) for the full reference.

```bash
octorules lint
```

## Known limitations

- **Non-atomic sync**: Bunny Shield has no bulk-replace API. `octorules sync` uses diff-and-reconcile (patch existing, add new, remove stale) — three separate API calls per changed rule. A failure mid-sync leaves the zone in an intermediate state; re-running sync will converge.
- **Rule name constraints**: Bunny requires alphanumeric characters and spaces only — hyphens, underscores, and special characters are rejected by the API.
- **No custom rulesets or lists**: Bunny Shield has no equivalent of AWS Rule Groups or Cloudflare Lists. Use the access list phase for IP/CIDR/ASN/country blocking.
- **Access list entries are individual**: Each access list entry is a separate API object; there is no batch create/delete. Large changeset syncs make many API calls.
- **Plan tier limits**: Free plans cannot create custom WAF rules and are limited to 2 rate-limit rules. The linter warns about these limits (BN501).

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest tests/ -v
```

Pre-commit hook:

```bash
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

## License

Apache-2.0
