# octorules-bunny

Bunny.net Shield WAF provider for [octorules](https://github.com/doctena-org/octorules) — manages Bunny Shield custom WAF rules, rate limits, access lists, edge rules, managed rule overrides, pull zone security, and bot/DDoS configuration as YAML.

## Installation

```bash
pip install octorules-bunny
```

This installs octorules (core) and octorules-bunny. The provider is auto-discovered — no `class:` needed in config.

## Configuration

```yaml
# octorules.yaml
providers:
  bunny:
    api_key: env/BUNNY_API_KEY
  rules:
    directory: ./rules

zones:
  my-cdn:
    sources:
      - rules
    targets:
      - bunny
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
| `plan` | *(auto-detected)* | Bunny Shield WAF tier (`basic`, `advanced`, `business`, or `enterprise`). Auto-detected per-zone from the API during zone resolution. Set this as a fallback if the API does not return a plan type. |

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
| Upload scanning (CSAM/AV) | Supported |
| WAF settings (learning mode, body limits, whitelabel, header logging) | Supported |
| Custom rulesets | Not supported (Bunny API limitation) |
| Lists | Not supported (use access list phase instead) |
| Curated threat lists (VPN, Tor, datacenters, AbuseIPDB, etc.) | Supported |

## Zone File Example

```yaml
# rules/my-cdn.yaml
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
    severity: warning
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
  - ref: blocked-countries
    type: country
    action: block
    enabled: true
    content: |
      CN
      RU

bunny_edge_rules:
  - ref: Force HTTPS
    enabled: true
    description: Force HTTPS
    action_type: force_ssl
    action_parameter_1: ""
    action_parameter_2: ""
    trigger_matching_type: all
    triggers:
      - type: url
        pattern_matching_type: any
        pattern_matches:
          - "http://*"

bunny_waf_managed_rules:
  disabled:
    - "941100"
  log_only:
    - "930100"

bunny_shield_config:
  bot_detection:
    execution_mode: log
    request_integrity_sensitivity: medium
    ip_sensitivity: medium
    fingerprint_sensitivity: high
    complex_fingerprinting: false
  ddos:
    shield_sensitivity: medium
    execution_mode: log
    challenge_window: 300
  waf:
    enabled: true
    execution_mode: block
    learning_mode: false
    request_body_limit_action: 1
    response_body_limit_action: 2
    whitelabel_response_pages: true
    realtime_threat_intelligence_enabled: false
    request_header_logging_enabled: true
    request_ignored_headers:
      - Authorization
      - Cookie
  upload_scanning:
    enabled: true
    csam_scanning_mode: 1
    antivirus_scanning_mode: 1

bunny_curated_threat_lists:
  VPN Providers:
    enabled: true
    action: block
  TOR Exit Nodes:
    enabled: true
    action: challenge
  AbuseIPDB:
    enabled: true
    action: log

bunny_pullzone_security:
  blocked_ips:
    - "198.51.100.99"
  blocked_countries: []
  block_post_requests: false
  logging_ip_anonymization_type: 1  # 0=none, 1=one octet, 2=two octets
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
| `bunny_curated_threat_lists` | Enable/disable Bunny's curated threat intelligence lists (VPN, Tor, AbuseIPDB, FireHOL, etc.) |

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
| `args_get_names` | 5 | No | GET parameter names |
| `args_post` | 6 | Optional | POST parameters |
| `args_post_names` | 7 | No | POST parameter names |
| `files_names` | 8 | No | Uploaded file names |
| `geo` | 9 | **Required** | Geographic data (COUNTRY_CODE, ASN, CITY, CONTINENT, LATITUDE, LONGITUDE) |
| `remote_addr` | 10 | No | Client IP address |
| `query_string` | 11 | No | Query string |
| `request_basename` | 12 | No | Request URI basename |
| `request_body` | 13 | No | Request body |
| `request_cookies_names` | 14 | No | Cookie names |
| `request_cookies` | 15 | **Required** | Cookie (specify cookie name as variable_value) |
| `request_filename` | 16 | No | Request filename |
| `request_headers_names` | 17 | No | Header names |
| `request_headers` | 18 | **Required** | Header (specify header name as variable_value) |
| `request_line` | 19 | No | Full request line |
| `request_method` | 20 | No | HTTP method |
| `request_protocol` | 21 | No | Request protocol |
| `response_body` | 22 | No | Response body |
| `response_headers` | 23 | Optional | Response header (specify header name as variable_value) |
| `response_status` | 24 | No | Response status code |
| `fingerprint` | 25 | No | Client fingerprint |

## Rule Name Constraints

Custom WAF and rate limit rule names (`ref`) must match `[a-zA-Z0-9 ]+` (alphanumeric characters and spaces only). No hyphens, underscores, or special characters. This is an API constraint enforced by Bunny.

Access list `ref` values map to the list name in the Bunny API. Use descriptive names (e.g. `blocked-countries`, `allowed-ips`). Names can contain any characters — the alphanumeric constraint only applies to WAF/rate-limit rules.

## Sync Behavior

Bunny Shield does not support atomic bulk rule replacement. The provider uses a diff-and-reconcile strategy:

1. **Patch** existing rules (ref exists in both old and new)
2. **Add** new rules (ref only in desired YAML)
3. **Remove** stale rules (ref only in current API state)

This order ensures the zone never has *fewer* rules than intended during sync.

## Plan Limits

Bunny Shield WAF tier is **per-zone** (not account-wide). Set via the Bunny dashboard when enabling Shield on a pull zone. The tier is auto-detected from the API during zone resolution.

| Tier | planType | Custom WAF Rules | Rate Limits | Custom Access Lists |
|------|:--------:|:----------------:|:-----------:|:-------------------:|
| Basic | 0 | 0 | 2 | 1 (1k entries) |
| Advanced ($9.50/mo) | 1 | 10 | 10 | 5 (5k entries) |
| Business ($49/mo) | 2 | 25 | 25 | 10 (7.5k entries) |
| Enterprise | 3 | 50 | Unlimited | Unlimited |

## Linting

77 lint rules with the `BN` prefix validate your rules offline before sync. See [docs/lint/README.md](docs/lint/README.md) for the full reference.

```bash
octorules lint
```

## Known limitations

- **Non-atomic sync**: Bunny Shield has no bulk-replace API. `octorules sync` uses diff-and-reconcile (patch existing, add new, remove stale) — three separate API calls per changed rule. A failure mid-sync leaves the zone in an intermediate state; re-running sync will converge.
- **Rule name constraints**: Bunny requires alphanumeric characters and spaces only — hyphens, underscores, and special characters are rejected by the API.
- **No custom rulesets or lists**: Bunny Shield has no equivalent of AWS Rule Groups or Cloudflare Lists. Use the access list phase for IP/CIDR/ASN/country blocking.
- **Access list entries are individual**: Each access list entry is a separate API object; there is no batch create/delete. Large changeset syncs make many API calls.
- **Plan tier limits**: Basic tier cannot create custom WAF rules and is limited to 2 rate-limit rules. The linter warns about these limits (BN501). Tier is auto-detected from the API; set `plan:` in the provider config as a fallback.

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

octorules-bunny is licensed under the [Apache License 2.0](LICENSE).
