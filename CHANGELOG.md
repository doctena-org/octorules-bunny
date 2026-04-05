# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
