# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.2] - 2026-04-18

### Added
- **BN311** (access_list, WARNING): catch-all CIDR (``0.0.0.0/0`` or
  ``::/0``) in an access list. Parallels GA306 (Google), AZ322 (Azure),
  and WA163 (AWS) — fills the last remaining gap in the catch-all
  rule family across providers.

### Changed
- BN307 (overlap) now skips catch-all entries so they aren't
  double-flagged against every other CIDR in the list. Catch-alls
  are handled exclusively by BN311. Behavior narrowing — configs
  with ``0.0.0.0/0`` + other entries stop seeing BN307 warnings for
  those combinations.
- BN307 algorithm rewritten from O(n²) pairwise comparison to
  O(n log n) sweep-line. Large access lists (1,000+ entries) now
  lint in well under a second; the previous brute-force pass was
  quadratic and scaled poorly.
- Minimum ``octorules`` dependency: ``>=0.26.0`` (was ``>=0.24.0``).

## [0.3.1] - 2026-04-17

### Added
- New lint rules (count increased from 58 to 68):
  - **BN009** (INFO): duplicate ref across different phases (confusing
    for audits even though the API scopes refs per-phase)
  - **BN119** (INFO): regex starts with `.*` or `.+` — redundant with
    unanchored matching and hurts performance
  - **BN707** (ERROR): empty/whitespace pattern string in `pattern_matches`
  - **BN708** (ERROR): invalid country code in `country_code` trigger
  - **BN709** (ERROR): invalid IP/CIDR in `remote_ip` trigger
  - **BN710** (ERROR): invalid HTTP method in `request_method` trigger
  - **BN711** (ERROR): status code outside 100-900 in `status_code` trigger
  - **BN712** (ERROR): malformed Lua pattern (unclosed bracket, trailing
    escape, empty body) when `pattern:` prefix is used
  - **BN713** (WARNING): edge rule URL trigger pattern must start with
    `/`, `http`, or `*` (patterns without these prefixes never match)
  - **BN715** (ERROR): edge rule `redirect` action status code
    (`action_parameter_2`) must be 300-399

### Changed
- `list_zones()` now uses the shared pull-zones cache populated by
  `resolve_zone_id()` — back-to-back calls no longer re-query the API.
- `resolve_zone_id()` error messages now include hints: a list of
  available pull zones when the name isn't found (helps catch typos),
  and the conflicting IDs when multiple pull zones share a name.
- Access list sync batches the ``list_access_lists`` lookup that
  resolves ``configurationId`` for newly-created lists: was
  ``1 + N`` lookups, now ``2`` regardless of new-list count.  Creating
  10 new access lists drops from 11 to 2 ``list_access_lists`` calls
  (~1.8s saved at typical API latency).
- New client method ``list_access_lists_full()`` returns the raw
  response dict.  ``get_managed_access_lists()`` now uses it instead
  of reaching into ``self._client._request`` (private-method access
  removed).

## [0.3.0] - 2026-04-16

### Added
- `bunny_curated_threat_lists` non-phase section: enable/disable and
  configure actions for Bunny's curated threat intelligence lists (VPN
  Providers, TOR Exit Nodes, Common Datacenters, AbuseIPDB, FireHOL,
  etc.).  Supports plan, sync, dump, lint validation, and formatting.
- `bunny_shield_config.waf` section: manage all WAF settings including
  `enabled` (master switch), `execution_mode` (log/block),
  `learning_mode`, body inspection limits, `whitelabel_response_pages`,
  `realtime_threat_intelligence_enabled`, `profile_id`,
  `engine_config`, and request header logging.
- `bot_detection.fingerprint_aggression` field for browser fingerprint
  aggression level.
- `bunny_pullzone_security.logging_ip_anonymization_type` replaces the
  non-functional `logging_ip_anonymization` bool with the actual
  `LogAnonymizationType` int (0=none, 1=one octet, 2=two octets).
- `bunny_shield_config.upload_scanning` section: manage CSAM and
  antivirus upload scanning settings.
- BN501 now checks access list count against plan tier limits (Basic=1,
  Advanced=5, Business=10).
- Plan tier auto-detection from the Shield API `planType` field during
  zone resolution. The `plan` provider kwarg serves as a fallback.
- Business and Enterprise tiers added to `_PLAN_LIMITS` and
  `_PLAN_TYPE_MAP` (planType 0=Basic, 1=Advanced, 2=Business,
  3=Enterprise).

### Changed
- Enum maps refactored from 14 dict pairs + free functions to `EnumMap` class
  with `resolve()`/`unresolve()` methods, simplifying imports across all
  modules.
- Shield config and pull zone security extensions unified via shared
  `_config_base.py` module (`ConfigChange`, `ConfigPlan`, `ConfigFormatter`),
  eliminating ~200 lines of duplicate dataclass/formatter/diff code.
- Linter cross-phase checks refactored to use `_iter_phases()` helper.
- `BN_RULE_METAS` changed from `globals()` introspection to explicit tuple.
- Pagination format detection extracted to `_extract_page()` helper.
- Condition duplicate detection uses tuple keys instead of `json.dumps()`.
- Private/reserved IP range lookup partitioned by IP version (`_PRIVATE_V4`/
  `_PRIVATE_V6`), halving average scan length per address.
- Access list detail fetches run in parallel when `max_workers > 1`.

### Fixed
- Shield zone PATCH now uses the correct `{"shieldZoneId": N, "shieldZone": {...}}`
  envelope required by the Bunny API (previously sent flat fields, silently
  ignored).
- Bot detection normalization/denormalization updated for the nested API
  format (`requestIntegrity.sensitivity`, `ipAddress.sensitivity`,
  `browserFingerprint.sensitivity`/`complexEnabled`).
- Pull zone security list fields (`blocked_ips`, `blocked_countries`,
  `blocked_referrers`, `allowed_referrers`, `cors_extensions`) correctly
  typed as lists, matching the actual Bunny API format.
- Pull zone field name corrected: `LoggingIPAnonymizationEnabled` (was
  `LoggingIPAnonymization`).
- Rate limit rules now include `severity` in normalization and `severityType`
  in denormalization, fixing idempotency drift on re-plan.
- `ruleDescription` is now always sent for custom WAF and rate limit rules
  (even when empty), fixing 400 errors from the API.
- Access list content trailing newline stripped via `prepare_rule` hook,
  preventing perpetual drift from YAML block scalars.
- `_config_id` registered as an API field so it is excluded from diffs.
- Access list detail fetch catches specific exceptions instead of bare
  `except Exception`, and logs warnings on failure.
- Access list create logs a warning when the config update step fails after
  the list was created (partial state).
- Non-integer `Retry-After` headers now log a debug message instead of being
  silently ignored.

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
