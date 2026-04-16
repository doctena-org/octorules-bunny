"""Bunny.net Shield WAF provider for octorules.

Maps octorules concepts to Bunny Shield:
  - Zones -> Pull Zones (resolve_zone_id resolves name -> shield zone ID)
  - Phases -> Rule types within a shield zone (custom WAF / rate limit / access list)
  - Custom rulesets / Lists -> Not supported
"""

import logging
import os
import threading

import httpx
from octorules.config import ConfigError
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderError
from octorules.provider.utils import fetch_parallel, make_error_wrapper

from octorules_bunny._client import (
    BunnyAPIError,
    BunnyAuthError,
    BunnyShieldClient,
)
from octorules_bunny._enums import (
    ACCESS_LIST_ACTION,
    ACCESS_LIST_TYPE,
    ACTION,
    BLOCKTIME,
    COUNTER_KEY,
    EDGE_ACTION,
    EDGE_PATTERN_MATCH,
    EDGE_TRIGGER,
    EDGE_TRIGGER_MATCH,
    OPERATOR,
    SEVERITY,
    TIMEFRAME,
    TRANSFORMATION,
    VARIABLE,
)
from octorules_bunny._phases import BUNNY_PHASE_IDS

log = logging.getLogger(__name__)

_wrap_provider_errors = make_error_wrapper(
    auth_errors=(BunnyAuthError,),
    connection_errors=(httpx.ConnectError, httpx.ConnectTimeout, ConnectionError),
    generic_errors=(httpx.HTTPStatusError, BunnyAPIError),
)


def _shield_zone_id(scope: Scope) -> int:
    """Extract the shield zone ID from scope, raising ConfigError on bad values."""
    try:
        return int(scope.zone_id)
    except (ValueError, TypeError) as e:
        raise ConfigError(f"Invalid shield zone ID {scope.zone_id!r}: must be numeric") from e


def _unwrap_data(response: dict | list) -> dict | list:
    """Unwrap the ``{"data": ...}`` envelope used by Bunny Shield API responses."""
    if isinstance(response, dict) and "data" in response:
        return response["data"]
    return response


# ---------------------------------------------------------------------------
# Rule normalization (API format <-> octorules YAML format)
# ---------------------------------------------------------------------------
def _normalize_condition(cond: dict) -> dict:
    """Normalize a single rule condition from API to YAML format."""
    result: dict = {}
    vt = cond.get("variableTypes", {})
    if isinstance(vt, dict) and vt:
        var_key = next(iter(vt))
        if str(var_key).isdigit():
            # API returned numeric key — look up in int->str mapping.
            result["variable"] = VARIABLE.resolve(int(var_key))
        else:
            # API returned string key (e.g. "REQUEST_URI") — lowercase it
            # to match octorules YAML convention.
            result["variable"] = str(var_key).lower()
        sub = vt[var_key]
        if sub is not None and sub != "":
            result["variable_value"] = str(sub)
    result["operator"] = OPERATOR.resolve(cond.get("operatorType", ""))
    value = cond.get("value", "")
    if value is not None and value != "":
        result["value"] = value
    return result


def _denormalize_condition(cond: dict) -> dict:
    """Denormalize a single condition from YAML to API format."""
    if not cond:
        return {}
    var_str = cond.get("variable", "")
    # API expects UPPERCASE variable keys (e.g. "REQUEST_URI").
    var_key = var_str.upper()
    sub = cond.get("variable_value", "")
    result: dict = {
        "variableTypes": {var_key: sub},
        "operatorType": OPERATOR.unresolve(cond.get("operator", "")),
    }
    value = cond.get("value", "")
    if value is not None and value != "":
        result["value"] = value
    return result


def _normalize_custom_rule(rule: dict) -> dict:
    """Convert an API custom WAF rule to octorules YAML format."""
    api_id = rule.get("id")
    config = rule.get("ruleConfiguration", {})

    conditions: list[dict] = []
    # Primary condition
    primary = _normalize_condition(config)
    if primary:
        conditions.append(primary)
    # Chained conditions (AND)
    for chain in config.get("chainedRuleConditions") or []:
        chained = _normalize_condition(chain)
        if chained:
            conditions.append(chained)

    transformations = [TRANSFORMATION.resolve(t) for t in config.get("transformationTypes", [])]

    result: dict = {
        "ref": rule.get("ruleName", ""),
        "action": ACTION.resolve(config.get("actionType", "")),
        "severity": SEVERITY.resolve(config.get("severityType", "")),
        "conditions": conditions,
        "_api_id": api_id,
    }
    desc = rule.get("ruleDescription", "")
    if desc:
        result["description"] = desc
    if transformations:
        result["transformations"] = transformations
    return result


def _denormalize_custom_rule(rule: dict, shield_zone_id: int) -> dict:
    """Convert a YAML custom WAF rule to API format."""
    conditions = rule.get("conditions", [])
    primary = conditions[0] if conditions else {}
    chained = [_denormalize_condition(c) for c in conditions[1:]]

    transformations = [TRANSFORMATION.unresolve(t) for t in rule.get("transformations", [])]

    primary_api = _denormalize_condition(primary) if primary else {}

    config: dict = {
        "actionType": ACTION.unresolve(rule.get("action", "")),
        "severityType": SEVERITY.unresolve(rule.get("severity", "info")),
        **primary_api,
        "transformationTypes": transformations,
    }
    if chained:
        config["chainedRuleConditions"] = chained

    result: dict = {
        "shieldZoneId": shield_zone_id,
        "ruleName": rule.get("ref", ""),
        "ruleDescription": rule.get("description", ""),
        "ruleConfiguration": config,
    }
    return result


def _normalize_rate_limit(rule: dict) -> dict:
    """Convert an API rate limit rule to octorules YAML format."""
    api_id = rule.get("id")
    config = rule.get("ruleConfiguration", {})

    conditions: list[dict] = []
    primary = _normalize_condition(config)
    if primary:
        conditions.append(primary)
    for chain in config.get("chainedRuleConditions") or []:
        chained = _normalize_condition(chain)
        if chained:
            conditions.append(chained)

    transformations = [TRANSFORMATION.resolve(t) for t in config.get("transformationTypes", [])]

    # Rate limit fields may be inside ruleConfiguration or at the top level
    # depending on the API version/endpoint.
    def _get(key: str, default=None):
        return config.get(key, rule.get(key, default))

    result: dict = {
        "ref": rule.get("ruleName", ""),
        "action": ACTION.resolve(config.get("actionType", "")),
        "severity": SEVERITY.resolve(config.get("severityType", 0)),
        "request_count": _get("requestCount", 0),
        "timeframe": TIMEFRAME.resolve(_get("timeframe", "")),
        "block_time": BLOCKTIME.resolve(_get("blockTime", "")),
        "counter_key_type": COUNTER_KEY.resolve(_get("counterKeyType", "")),
        "conditions": conditions,
        "_api_id": api_id,
    }
    desc = rule.get("ruleDescription", "")
    if desc:
        result["description"] = desc
    if transformations:
        result["transformations"] = transformations
    return result


def _denormalize_rate_limit(rule: dict, shield_zone_id: int) -> dict:
    """Convert a YAML rate limit rule to API format."""
    conditions = rule.get("conditions", [])
    primary = conditions[0] if conditions else {}
    chained = [_denormalize_condition(c) for c in conditions[1:]]

    transformations = [TRANSFORMATION.unresolve(t) for t in rule.get("transformations", [])]

    primary_api = _denormalize_condition(primary) if primary else {}

    config: dict = {
        "actionType": ACTION.unresolve(rule.get("action", "")),
        "severityType": SEVERITY.unresolve(rule.get("severity", "info")),
        **primary_api,
        "transformationTypes": transformations,
        "requestCount": rule.get("request_count", 0),
        "timeframe": TIMEFRAME.unresolve(rule.get("timeframe", "")),
        "blockTime": BLOCKTIME.unresolve(rule.get("block_time", "")),
        "counterKeyType": COUNTER_KEY.unresolve(rule.get("counter_key_type", "")),
    }
    if chained:
        config["chainedRuleConditions"] = chained

    result: dict = {
        "shieldZoneId": shield_zone_id,
        "ruleName": rule.get("ref", ""),
        "ruleDescription": rule.get("description", ""),
        "ruleConfiguration": config,
    }
    return result


def _normalize_access_list(rule: dict) -> dict:
    """Convert an API access list to octorules YAML format.

    Handles both ``AccessListDetails`` (from the list endpoint, has
    ``listId``/``name``/``isEnabled``) and ``CustomAccessList`` (from
    the get/create endpoints, has ``id``/``name``/``content``).
    """
    # List endpoint uses listId; get/create endpoint uses id.
    api_id = rule.get("listId", rule.get("id"))
    result: dict = {
        "ref": rule.get("name", str(api_id or "")),
        "type": ACCESS_LIST_TYPE.resolve(rule.get("type", "")),
        "action": ACCESS_LIST_ACTION.resolve(rule.get("action", "")),
        "enabled": bool(rule.get("isEnabled", rule.get("enabled", True))),
        "content": (rule.get("content") or "").rstrip("\n"),
        "_api_id": api_id,
        "_config_id": rule.get("configurationId"),
    }
    return result


def _denormalize_access_list_create(rule: dict) -> dict:
    """Build the create payload for a new custom access list.

    Per the Bunny Shield API spec, the create endpoint accepts ``name``,
    ``type``, and ``content``.  Action and enabled state are configured
    separately via the configuration endpoint.
    """
    return {
        "name": rule.get("ref", ""),
        "type": ACCESS_LIST_TYPE.unresolve(rule.get("type", "")),
        "content": (rule.get("content") or "").rstrip("\n"),
    }


def _denormalize_access_list_update(rule: dict) -> dict:
    """Build the update payload for an existing custom access list."""
    return {
        "name": rule.get("ref", ""),
        "content": (rule.get("content") or "").rstrip("\n"),
    }


def _denormalize_access_list_config(rule: dict) -> dict:
    """Build the configuration payload (action + enabled)."""
    return {
        "isEnabled": rule.get("enabled", True),
        "action": ACCESS_LIST_ACTION.unresolve(rule.get("action", "")),
    }


# ---------------------------------------------------------------------------
# Edge Rule normalization (CDN-level rules on pull zone)
# ---------------------------------------------------------------------------
def _normalize_edge_trigger(trigger: dict) -> dict:
    """Normalize a single edge rule trigger from API to YAML format."""
    result: dict = {
        "type": EDGE_TRIGGER.resolve(trigger.get("Type", "")),
        "pattern_matching_type": EDGE_PATTERN_MATCH.resolve(trigger.get("PatternMatchingType", "")),
        "pattern_matches": trigger.get("PatternMatches", []),
    }
    p1 = trigger.get("Parameter1", "")
    if p1 is not None and p1 != "":
        result["parameter_1"] = p1
    return result


def _denormalize_edge_trigger(trigger: dict) -> dict:
    """Denormalize a single edge rule trigger from YAML to API format."""
    result: dict = {
        "Type": EDGE_TRIGGER.unresolve(trigger.get("type", "")),
        "PatternMatchingType": EDGE_PATTERN_MATCH.unresolve(
            trigger.get("pattern_matching_type", "")
        ),
        "PatternMatches": trigger.get("pattern_matches", []),
    }
    p1 = trigger.get("parameter_1", "")
    if p1 is not None and p1 != "":
        result["Parameter1"] = p1
    return result


def _normalize_edge_rule(rule: dict) -> dict:
    """Convert an API edge rule to octorules YAML format."""
    triggers = [_normalize_edge_trigger(t) for t in rule.get("Triggers", [])]
    result: dict = {
        "ref": rule.get("Description", ""),
        "_api_id": rule.get("Guid", ""),
        "enabled": bool(rule.get("Enabled", True)),
        "description": rule.get("Description", ""),
        "action_type": EDGE_ACTION.resolve(rule.get("ActionType", "")),
        "action_parameter_1": rule.get("ActionParameter1", ""),
        "action_parameter_2": rule.get("ActionParameter2", ""),
        "trigger_matching_type": EDGE_TRIGGER_MATCH.resolve(rule.get("TriggerMatchingType", "")),
        "triggers": triggers,
    }
    return result


def _denormalize_edge_rule(rule: dict) -> dict:
    """Convert a YAML edge rule to API format."""
    triggers = [_denormalize_edge_trigger(t) for t in rule.get("triggers", [])]
    result: dict = {
        "ActionType": EDGE_ACTION.unresolve(rule.get("action_type", "")),
        "ActionParameter1": rule.get("action_parameter_1", ""),
        "ActionParameter2": rule.get("action_parameter_2", ""),
        "TriggerMatchingType": EDGE_TRIGGER_MATCH.unresolve(
            rule.get("trigger_matching_type", "all")
        ),
        "Triggers": triggers,
        "Description": rule.get("description", rule.get("ref", "")),
        "Enabled": rule.get("enabled", True),
    }
    # Include Guid when updating an existing rule
    api_id = rule.get("_api_id", "")
    if api_id:
        result["Guid"] = api_id
    return result


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
class BunnyShieldProvider:
    """Bunny.net Shield WAF provider for octorules.

    Maps octorules concepts to Bunny Shield:
      - Zones -> Pull Zones (resolve_zone_id looks up by name)
      - Phases -> Rule types (custom WAF / rate limit / access list)
      - Custom rulesets, Lists -> Not supported

    Authentication uses the Bunny API key (``api_key`` parameter or
    ``BUNNY_API_KEY`` environment variable).
    """

    SUPPORTS = frozenset({"zone_discovery"})

    def __init__(
        self,
        *,
        timeout: float | None = None,
        max_workers: int = 1,
        max_retries: int = 2,
        client: object = None,
        api_key: str | None = None,
        plan: str | None = None,
        **_extra: object,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            api_key = api_key or os.environ.get("BUNNY_API_KEY", "")
            if not api_key:
                raise ConfigError(
                    "Bunny API key not specified"
                    " (set 'api_key' in provider config or BUNNY_API_KEY env var)"
                )
            client_kwargs: dict = {
                "timeout": timeout if timeout is not None else 30.0,
                "max_retries": max_retries,
            }
            if max_workers > 1:
                client_kwargs["max_connections"] = 10 * max_workers
            self._client = BunnyShieldClient(api_key, **client_kwargs)
        self._max_workers = max_workers
        self._plan = plan.lower() if plan else None
        self._lock = threading.Lock()
        # shield_zone_id (str) -> {pull_zone_id, name}
        self._zone_meta: dict[str, dict] = {}
        self._zone_plans: dict[str, str] = {}
        self._pull_zones_cache: list[dict] | None = None

    # -- Helpers --

    def get_zone_metadata(self, zone_id: str) -> dict | None:
        """Return cached metadata for a resolved zone, or None if not resolved.

        The returned dict contains ``pull_zone_id`` (int) and ``name`` (str).
        """
        return self._zone_meta.get(zone_id)

    def _fmt_scope(self, scope: Scope) -> str:
        """Human-readable scope label with shield zone ID for log messages."""
        name = scope.label
        if not name:
            meta = self._zone_meta.get(scope.zone_id)
            if meta:
                name = meta["name"]
        if name:
            return f"{name} (shield_zone_id={scope.zone_id})"
        return f"shield_zone_id={scope.zone_id}"

    # -- Resource management --

    def close(self) -> None:
        """Close the underlying HTTP client, releasing connections."""
        if hasattr(self._client, "close"):
            self._client.close()

    def __enter__(self) -> "BunnyShieldProvider":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- Properties --

    @property
    def max_workers(self) -> int:
        """Maximum number of concurrent workers for parallel operations."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        """Return None; Bunny Shield has no account-level scope."""
        return None

    @property
    def account_name(self) -> str | None:
        """Return None; Bunny Shield has no account-level scope."""
        return None

    @property
    def zone_plans(self) -> dict[str, str]:
        """Zone tiers detected from the Shield API (``planType``).

        Bunny Shield WAF tier is per-zone.  The tier is auto-detected
        from the ``planType`` field returned by the Shield Zone API
        during ``resolve_zone_id``.  The ``plan`` provider kwarg serves
        as a fallback when the API does not return a known plan type.
        """
        return dict(self._zone_plans)

    # -- Zone resolution --

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a pull zone name to its Shield Zone ID.

        Steps:
        1. List pull zones, find by name.
        2. Get the Shield Zone for that pull zone.
        """
        if self._pull_zones_cache is None:
            with self._lock:
                if self._pull_zones_cache is None:
                    self._pull_zones_cache = self._client.list_pull_zones()
        pull_zones = self._pull_zones_cache
        matches = [pz for pz in pull_zones if pz.get("Name") == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No pull zone found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple pull zones found for {zone_name!r}")

        pz = matches[0]
        pull_zone_id = pz["Id"]
        shield_raw = self._client.get_shield_zone_by_pullzone(pull_zone_id)
        # Shield API wraps responses in {"data": {...}} — unwrap if present.
        shield = _unwrap_data(shield_raw)
        shield_zone_id = str(shield.get("shieldZoneId", shield.get("id", "")))
        if not shield_zone_id:
            raise ConfigError(
                f"Shield Zone not found for pull zone {zone_name!r}"
                " (is Bunny Shield enabled for this zone?)"
            )

        # Auto-detect zone tier from API response.
        _PLAN_TYPE_MAP = {0: "basic", 1: "advanced", 2: "business", 3: "enterprise"}
        api_tier = _PLAN_TYPE_MAP.get(shield.get("planType"))

        with self._lock:
            self._zone_meta[shield_zone_id] = {
                "pull_zone_id": pull_zone_id,
                "name": zone_name,
            }
            # API-detected tier takes precedence; fall back to provider kwarg.
            if api_tier:
                self._zone_plans[zone_name] = api_tier
            elif self._plan:
                self._zone_plans[zone_name] = self._plan
        log.debug(
            "Resolved %s -> shield_zone_id=%s (pull_zone_id=%d)",
            zone_name,
            shield_zone_id,
            pull_zone_id,
        )
        return shield_zone_id

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all pull zone names."""
        pull_zones = self._client.list_pull_zones()
        log.debug("list_zones: %d pull zones", len(pull_zones))
        return [pz["Name"] for pz in pull_zones if "Name" in pz]

    # -- Phase rules --

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Fetch rules for a single phase from the Shield Zone."""
        if provider_id not in BUNNY_PHASE_IDS:
            return []
        if provider_id == "bunny_edge_rule":
            pz_id = self._pull_zone_id(scope)
            pz = self._client.get_pull_zone(pz_id)
            raw = pz.get("EdgeRules", [])
            result = [_normalize_edge_rule(r) for r in raw]
            log.debug(
                "get_phase_rules %s/%s: %d rules", self._fmt_scope(scope), provider_id, len(result)
            )
            return result
        sz = _shield_zone_id(scope)
        if provider_id == "bunny_waf_custom":
            raw = self._client.list_custom_waf_rules(sz)
            result = [_normalize_custom_rule(r) for r in raw]
            log.debug(
                "get_phase_rules %s/%s: %d rules", self._fmt_scope(scope), provider_id, len(result)
            )
            return result
        if provider_id == "bunny_waf_rate_limit":
            raw = self._client.list_rate_limits(sz)
            result = [_normalize_rate_limit(r) for r in raw]
            log.debug(
                "get_phase_rules %s/%s: %d rules", self._fmt_scope(scope), provider_id, len(result)
            )
            return result
        if provider_id == "bunny_waf_access_list":
            summaries = self._client.list_access_lists(sz)
            # The list endpoint returns metadata but not content — fetch
            # each list individually to get the full content.
            fetchable = [s for s in summaries if s.get("listId", s.get("id")) is not None]
            result = self._fetch_access_list_details(sz, fetchable)
            log.debug(
                "get_phase_rules %s/%s: %d rules", self._fmt_scope(scope), provider_id, len(result)
            )
            return result
        return []

    def _fetch_access_list_details(self, sz: int, summaries: list[dict]) -> list[dict]:
        """Fetch full content for each access list summary.

        When ``max_workers > 1``, detail fetches run concurrently via a
        thread pool.  Individual failures fall back to summary-only data
        so the overall fetch never fails partially.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _fetch_one(summary: dict) -> dict:
            list_id = summary.get("listId", summary.get("id"))
            try:
                detail = self._client.get_access_list(sz, list_id)
                full = _unwrap_data(detail)
                merged = {**summary, **full}
                return _normalize_access_list(merged)
            except (BunnyAPIError, BunnyAuthError, httpx.HTTPStatusError) as exc:
                log.warning("Failed to fetch access list %s detail: %s", list_id, exc)
                return _normalize_access_list(summary)

        if self._max_workers <= 1 or len(summaries) <= 1:
            return [_fetch_one(s) for s in summaries]

        # Parallel path: maintain insertion order via index mapping.
        result: list[dict | None] = [None] * len(summaries)
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_idx = {executor.submit(_fetch_one, s): i for i, s in enumerate(summaries)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                result[idx] = future.result()
        return [r for r in result if r is not None]

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Replace rules of a specific phase using diff-and-reconcile.

        No atomic replace is available. This method:
        1. Patches rules whose ref exists in both old and new.
        2. Adds rules with new refs.
        3. Removes rules whose ref is only in old.

        This order guarantees the zone never has fewer rules than intended.
        """
        # Edge rules live on the pull zone, not the shield zone.
        sz = (
            self._pull_zone_id(scope)
            if provider_id == "bunny_edge_rule"
            else _shield_zone_id(scope)
        )
        current = self.get_phase_rules(scope, provider_id)

        # Guard against duplicate refs (e.g. edge rules with identical Descriptions)
        # which would silently drop rules in the dict comprehensions below.
        for label, rule_list in (("current", current), ("desired", rules)):
            seen_refs: dict[str, int] = {}
            for r in rule_list:
                ref = r.get("ref", "")
                seen_refs[ref] = seen_refs.get(ref, 0) + 1
            dupes = sorted(ref for ref, count in seen_refs.items() if count > 1)
            if dupes:
                raise ConfigError(f"Duplicate refs in {label} rules for {provider_id}: {dupes}")

        old_by_ref = {r["ref"]: r for r in current}
        new_by_ref = {r["ref"]: r for r in rules}

        patched: list[str] = []
        added: list[str] = []
        removed: list[str] = []

        try:
            # 1. Patch existing
            for ref, new_rule in new_by_ref.items():
                if ref in old_by_ref:
                    api_id = old_by_ref[ref].get("_api_id")
                    if api_id is not None:
                        payload = self._denormalize(new_rule, provider_id, sz)
                        # Carry _config_id from old rule (needed for access list config updates)
                        if "_config_id" in old_by_ref[ref]:
                            payload["_config_id"] = old_by_ref[ref]["_config_id"]
                        self._update_rule(provider_id, sz, api_id, payload)
                        patched.append(ref)

            # 2. Add new
            for ref, new_rule in new_by_ref.items():
                if ref not in old_by_ref:
                    payload = self._denormalize(new_rule, provider_id, sz)
                    self._create_rule(provider_id, sz, payload)
                    added.append(ref)

            # 3. Remove stale
            for ref in old_by_ref:
                if ref not in new_by_ref:
                    api_id = old_by_ref[ref].get("_api_id")
                    if api_id is not None:
                        self._delete_rule(provider_id, sz, api_id)
                        removed.append(ref)
        except Exception:
            log.error(
                "put_phase_rules %s/%s PARTIAL FAILURE: "
                "patched=%s added=%s removed=%s (of %d total rules)",
                self._fmt_scope(scope),
                provider_id,
                patched,
                added,
                removed,
                len(rules),
            )
            raise

        if patched or added or removed:
            log.debug(
                "put_phase_rules %s/%s: patched=%s added=%s removed=%s",
                self._fmt_scope(scope),
                provider_id,
                patched,
                added,
                removed,
            )

        return len(rules)

    @_wrap_provider_errors
    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for all Bunny phases from a Shield Zone."""
        phases_to_fetch = provider_ids if provider_ids is not None else list(BUNNY_PHASE_IDS)
        phases_to_fetch = [p for p in phases_to_fetch if p in BUNNY_PHASE_IDS]

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        sl = self._fmt_scope(scope)
        log.debug("Fetching %d phase(s) for %s", len(phases_to_fetch), sl)

        def _result_fn(phase: str, rules: list[dict]) -> tuple[str, list[dict]] | None:
            return (phase, rules) if rules else None

        rules, failed = fetch_parallel(
            phases_to_fetch,
            submit_fn=lambda ex, p: ex.submit(self.get_phase_rules, scope, p),
            key_fn=lambda p: p,
            result_fn=_result_fn,
            label="phase",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return PhaseRulesResult(rules, failed_phases=failed)

    # -- Denormalize / CRUD dispatch ----------------------------------------

    def _denormalize(self, rule: dict, provider_id: str, shield_zone_id: int) -> dict:
        if provider_id == "bunny_waf_custom":
            return _denormalize_custom_rule(rule, shield_zone_id)
        if provider_id == "bunny_waf_rate_limit":
            return _denormalize_rate_limit(rule, shield_zone_id)
        if provider_id == "bunny_waf_access_list":
            # Access list denormalize is handled specially in _create_rule/_update_rule
            # because the API uses separate endpoints for content and config.
            return rule  # pass through — create/update handles denormalization
        if provider_id == "bunny_edge_rule":
            return _denormalize_edge_rule(rule)
        raise ProviderError(f"Unknown provider_id: {provider_id!r}")

    def _create_rule(self, provider_id: str, sz: int, payload: dict) -> None:
        if provider_id == "bunny_waf_custom":
            self._client.create_custom_waf_rule(payload)
        elif provider_id == "bunny_waf_rate_limit":
            self._client.create_rate_limit(payload)
        elif provider_id == "bunny_waf_access_list":
            # Two-step: create the list, then configure action/enabled.
            create_payload = _denormalize_access_list_create(payload)
            resp = _unwrap_data(self._client.create_access_list(sz, create_payload))
            list_id = resp.get("id")
            if list_id:
                # Fetch the list details to get the configurationId.
                summaries = self._client.list_access_lists(sz)
                config_id = None
                for s in summaries:
                    if s.get("listId") == list_id:
                        config_id = s.get("configurationId")
                        break
                if config_id:
                    try:
                        config_payload = _denormalize_access_list_config(payload)
                        self._client.update_access_list_config(sz, config_id, config_payload)
                    except (BunnyAPIError, BunnyAuthError) as exc:
                        log.warning(
                            "Access list %s created but config update failed "
                            "(partial state — action/enabled may be wrong): %s",
                            list_id,
                            exc,
                        )
                        raise
        elif provider_id == "bunny_edge_rule":
            self._client.create_or_update_edge_rule(sz, payload)
        else:
            raise ProviderError(f"Cannot create rule: unknown provider_id {provider_id!r}")

    def _update_rule(self, provider_id: str, sz: int, api_id: int | str, payload: dict) -> None:
        if provider_id == "bunny_waf_custom":
            self._client.update_custom_waf_rule(api_id, payload)
        elif provider_id == "bunny_waf_rate_limit":
            self._client.update_rate_limit(api_id, payload)
        elif provider_id == "bunny_waf_access_list":
            # Update content, then update config if needed.
            update_payload = _denormalize_access_list_update(payload)
            self._client.update_access_list(sz, api_id, update_payload)
            # Update action/enabled via the configuration endpoint.
            config_id = payload.get("_config_id")
            if config_id:
                config_payload = _denormalize_access_list_config(payload)
                self._client.update_access_list_config(sz, config_id, config_payload)
        elif provider_id == "bunny_edge_rule":
            self._client.create_or_update_edge_rule(sz, payload)
        else:
            raise ProviderError(f"Cannot update rule: unknown provider_id {provider_id!r}")

    def _delete_rule(self, provider_id: str, sz: int, api_id: int | str) -> None:
        if provider_id == "bunny_waf_custom":
            self._client.delete_custom_waf_rule(api_id)
        elif provider_id == "bunny_waf_rate_limit":
            self._client.delete_rate_limit(api_id)
        elif provider_id == "bunny_waf_access_list":
            self._client.delete_access_list(sz, api_id)
        elif provider_id == "bunny_edge_rule":
            self._client.delete_edge_rule(sz, api_id)
        else:
            raise ProviderError(f"Cannot delete rule: unknown provider_id {provider_id!r}")

    # -- Pull zone helpers (used by extension hooks) -------------------------

    def _pull_zone_id(self, scope: Scope) -> int:
        """Look up the pull zone ID for a scope from cached zone metadata.

        Raises ``ConfigError`` if the zone was not resolved first (no
        cached metadata).
        """
        meta = self._zone_meta.get(scope.zone_id)
        if meta is None:
            raise ConfigError(
                f"No pull zone metadata for shield_zone_id={scope.zone_id!r}"
                " — was resolve_zone_id called?"
            )
        return meta["pull_zone_id"]

    @_wrap_provider_errors
    def get_pullzone_security(self, scope: Scope) -> dict:
        """Fetch pull zone and extract security-relevant fields."""
        from octorules_bunny._pullzone_security import normalize_pullzone_security

        pz = self._client.get_pull_zone(self._pull_zone_id(scope))
        log.debug("GET pullzone_security %s", self._fmt_scope(scope))
        return normalize_pullzone_security(pz)

    @_wrap_provider_errors
    def update_pullzone_security(self, scope: Scope, settings: dict) -> None:
        """Update pull zone security settings."""
        from octorules_bunny._pullzone_security import denormalize_pullzone_security

        payload = denormalize_pullzone_security(settings)
        self._client.update_pull_zone(self._pull_zone_id(scope), payload)
        log.debug("PUT pullzone_security %s", self._fmt_scope(scope))

    # -- Curated threat lists (managed access lists) -----------------------

    @_wrap_provider_errors
    def get_managed_access_lists(self, scope: Scope) -> list[dict]:
        """Fetch the managed (curated) access lists for a shield zone."""
        sz = _shield_zone_id(scope)
        # list_access_lists returns customLists only — we need the raw
        # response to get managedLists from the full endpoint.
        raw = self._client._request("GET", f"/shield/shield-zone/{sz}/access-lists")
        if isinstance(raw, dict):
            return raw.get("managedLists", [])
        return []

    @_wrap_provider_errors
    def update_curated_list_config(self, scope: Scope, config_id: int, payload: dict) -> dict:
        """Update a curated threat list's action and enabled state."""
        sz = _shield_zone_id(scope)
        log.debug("PUT curated_list config_id=%d %s", config_id, self._fmt_scope(scope))
        return self._client.update_access_list_config(sz, config_id, payload)

    # -- Shield config methods (used by extension hooks) --------------------

    @_wrap_provider_errors
    def get_shield_zone_config(self, scope: Scope) -> dict:
        """Fetch the Shield Zone configuration."""
        log.debug("GET shield_zone_config %s", self._fmt_scope(scope))
        return _unwrap_data(self._client.get_shield_zone(_shield_zone_id(scope)))

    @_wrap_provider_errors
    def get_bot_detection_config(self, scope: Scope) -> dict:
        """Fetch bot detection configuration."""
        log.debug("GET bot_detection %s", self._fmt_scope(scope))
        return _unwrap_data(self._client.get_bot_detection(_shield_zone_id(scope)))

    @_wrap_provider_errors
    def update_bot_detection_config(self, scope: Scope, settings: dict) -> dict:
        """Update bot detection configuration."""
        log.debug("PUT bot_detection %s", self._fmt_scope(scope))
        return self._client.update_bot_detection(_shield_zone_id(scope), settings)

    @_wrap_provider_errors
    def get_upload_scanning_config(self, scope: Scope) -> dict:
        """Fetch upload scanning configuration."""
        log.debug("GET upload_scanning %s", self._fmt_scope(scope))
        return _unwrap_data(self._client.get_upload_scanning(_shield_zone_id(scope)))

    @_wrap_provider_errors
    def update_upload_scanning_config(self, scope: Scope, settings: dict) -> dict:
        """Update upload scanning configuration."""
        log.debug("PUT upload_scanning %s", self._fmt_scope(scope))
        return self._client.update_upload_scanning(_shield_zone_id(scope), settings)

    @_wrap_provider_errors
    def update_shield_zone_config(self, scope: Scope, settings: dict) -> dict:
        """Update Shield Zone configuration (DDoS, managed rules, etc.).

        The Bunny Shield API expects ``{"shieldZoneId": N, "shieldZone": {fields}}``
        for PATCH — fields are nested under the ``shieldZone`` key.
        """
        payload = {
            "shieldZoneId": _shield_zone_id(scope),
            "shieldZone": settings,
        }
        log.debug("PUT shield_zone_config %s", self._fmt_scope(scope))
        return self._client.update_shield_zone(payload)

    # -- Custom rulesets (not supported) ------------------------------------

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """Bunny Shield has no custom rulesets concept."""
        return []

    @_wrap_provider_errors
    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        """Bunny Shield has no custom rulesets concept."""
        return []

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Bunny Shield has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        """Bunny Shield has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        """Bunny Shield has no custom rulesets concept."""
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Bunny Shield has no custom rulesets concept."""
        return {}

    # -- Lists (not supported) ----------------------------------------------

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        """Bunny Shield does not support lists; use the access list phase instead."""
        return []

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Bunny Shield does not support lists; use the access list phase instead."""
        raise ConfigError("Lists are not supported by Bunny Shield (use access list phase)")

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Bunny Shield does not support lists."""
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Bunny Shield does not support lists."""
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]:
        """Bunny Shield does not support lists."""
        return []

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Bunny Shield does not support lists."""
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """Return 'completed'; Bunny Shield operations are synchronous."""
        return "completed"

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Bunny Shield does not support lists."""
        return {}
