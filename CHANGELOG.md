# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.2] - 2026-04-13

### Added
- BN310: Duplicate organization entry in access list (WARNING).
- BN503: Rule likely unreachable after catch-all terminating rule (WARNING).
- BN706: Edge rule action missing required parameter (ERROR).

### Changed
- BN100, BN203: Valid options moved to `suggestion` field.
- Reserved IP list expanded from 7 to 28 networks (adds CGNAT, link-local,
  documentation, benchmark, multicast, IPv6 ranges).
- Explicit `RULE_IDS` per validator module for dead-rule detection.

## [0.2.1] - 2026-04-13

### Changed
- BN309 now detects duplicate entries in both `ip` and `cidr` type access lists
  (previously only `ip`). CIDR entries are normalised to their network address
  before comparison, so `10.0.0.1/24` and `10.0.0.0/24` are detected as
  duplicates.

## [0.2.0] - 2026-04-10

### Added
- `plan` provider kwarg — allows specifying the Bunny account tier (`free` or `advanced`) for plan-aware lint checks. The tier feeds into `zone_plans` and the core zone plans cache for automatic plan tier detection during lint.

### Changed
- BN501 now checks only the configured tier's limit when `plan` is set to a known tier, instead of always warning for the lowest tier exceeded.
- Linter and extension registration is now thread-safe (`threading.Lock`).

### Removed
- Unused `format_plan` and `count_changes` methods from `ShieldConfigFormatter` and `PullZoneSecurityFormatter`.

## [0.1.5] - 2026-04-09

### Fixed
- README test count updated (471 → 486).

### Changed
- Extension registration guards now use `threading.Lock` for correctness.
- Pre-commit hook now runs `yamllint` on workflow files.

## [0.1.4] - 2026-04-08

### Added
- BN006 lint rule: "Rule entry is not a dict" (ERROR)
- BN007 lint rule: "Phase value is not a list" (ERROR)

### Changed
- 20 missing docstrings added to provider (100% coverage)
- `payload` parameter renamed to `settings` on 2 methods (consistency)
- README heading capitalization normalized to sentence case

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
- 53 lint rules (BN001–BN705) covering all 4 phases, cross-rule analysis,
  and best practices
- Audit extension for IP/CIDR extraction from access lists and WAF rules
- Parallel phase fetching via `fetch_parallel`
- `get_zone_metadata()` accessor and human-readable `_fmt_scope()` log labels
- Entry point `octorules.providers: bunny` for auto-discovery
