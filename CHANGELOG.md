# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-04-07

### Added
- Debug logging across provider operations — resolve, get/put phase rules,
  extension hooks, and list/ruleset operations are now visible with `--debug`.

## [0.1.2] - 2026-04-07

### Added
- `Retry-After` header support on 429 responses — the client now respects the
  server's requested delay (capped at 120 seconds).
- Duplicate ref detection in `put_phase_rules` — raises `ConfigError` when
  edge rules have identical descriptions, preventing silent data loss.

### Changed
- Pull zone list is cached for the lifetime of the provider instance, avoiding
  redundant API calls during multi-zone resolution.

### Fixed
- BN309 now normalises IPv6 addresses to lowercase before duplicate comparison,
  matching the documented behaviour (`2001:DB8::1` and `2001:db8::1` are
  detected as duplicates).

## [0.1.1] - 2026-04-06

### Fixed
- Edge rule action type enum mapping corrected — 35 action types now match
  the Bunny API (previously only 15 were mapped, many to wrong integer
  values). New action types include `disable_waf`, `retry_origin`,
  `run_edge_script`, `origin_storage`, `origin_magic_containers`, and
  20 others.
- Edge rule trigger type enum mapping corrected — 14 trigger types now match
  the Bunny API (previously `url_query_string`, `cookie`, `url_extension`
  and others were mapped to wrong integer values). New trigger types:
  `country_state_code`, `origin_retry_attempt_count`,
  `origin_connection_error`. Removed: `content_type` (not a valid API
  trigger type).
- `trigger_matching_type` enum values swapped (`any` = 0, `all` = 1) to
  match API, and `none` (= 2) added.
- Removed invalid `"critical"` severity level from severity enum — valid
  values are now `info`, `warning`, `error` only.

## [0.1.0] - 2026-04-05

### Added
- Bunny Shield WAF provider for octorules
- Custom WAF rules phase (`bunny_waf_custom_rules`): full CRUD with
  diff-and-reconcile sync
- Rate limit rules phase (`bunny_waf_rate_limit_rules`): requestCount,
  timeframe, blockTime, counterKeyType with required-field validation
- Access list rules phase (`bunny_waf_access_list_rules`): IP, CIDR, ASN,
  Country, Organization, JA4 list types with conflict detection across types
- Edge rules phase (`bunny_edge_rules`): manage CDN-level edge rules
  (redirects, header manipulation, force SSL, blocking)
- Managed WAF rule overrides (`bunny_waf_managed_rules`): disable or set
  log-only on individual managed rules
- Shield config extension (`bunny_shield_config`): bot detection and DDoS
  protection knobs with partial-update support
- Pull zone security extension (`bunny_pullzone_security`): blocked
  IPs/countries/referrers, token auth, CORS, logging anonymization
- Thin httpx client with auto-pagination, retry on 429/5xx, connection pool
  scaling, and error classification
- 52 lint rules (BN001–BN705) covering all 4 phases, cross-rule analysis,
  and best practices
- Audit extension for IP/CIDR extraction from access lists and WAF rules
- Parallel phase fetching via `fetch_parallel`
- `get_zone_metadata()` accessor and human-readable `_fmt_scope()` log labels
- Entry point `octorules.providers: bunny` for auto-discovery
