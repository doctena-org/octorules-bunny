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
    ACCESS_LIST_TYPE_TO_STR,
    ACTION_TO_STR,
    BLOCKTIME_TO_STR,
    COUNTER_KEY_TO_STR,
    EDGE_ACTION_TO_STR,
    EDGE_PATTERN_MATCH_TO_STR,
    EDGE_TRIGGER_MATCH_TO_STR,
    EDGE_TRIGGER_TO_STR,
    OPERATOR_TO_STR,
    SEVERITY_TO_STR,
    STR_TO_ACCESS_LIST_TYPE,
    STR_TO_ACTION,
    STR_TO_BLOCKTIME,
    STR_TO_COUNTER_KEY,
    STR_TO_EDGE_ACTION,
    STR_TO_EDGE_PATTERN_MATCH,
    STR_TO_EDGE_TRIGGER,
    STR_TO_EDGE_TRIGGER_MATCH,
    STR_TO_OPERATOR,
    STR_TO_SEVERITY,
    STR_TO_TIMEFRAME,
    STR_TO_TRANSFORMATION,
    STR_TO_VARIABLE,
    TIMEFRAME_TO_STR,
    TRANSFORMATION_TO_STR,
    VARIABLE_TO_STR,
    _resolve,
    _unresolve,
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


# ---------------------------------------------------------------------------
# Rule normalization (API format <-> octorules YAML format)
# ---------------------------------------------------------------------------
def _normalize_condition(cond: dict) -> dict:
    """Normalize a single rule condition from API to YAML format."""
    result: dict = {}
    vt = cond.get("variableTypes", {})
    if isinstance(vt, dict) and vt:
        var_key = next(iter(vt))
        var_int = int(var_key) if str(var_key).isdigit() else var_key
        result["variable"] = _resolve(VARIABLE_TO_STR, var_int)
        sub = vt[var_key]
        if sub is not None and sub != "":
            result["variable_value"] = str(sub)
    result["operator"] = _resolve(OPERATOR_TO_STR, cond.get("operatorType", ""))
    value = cond.get("value", "")
    if value is not None and value != "":
        result["value"] = value
    return result


def _denormalize_condition(cond: dict) -> dict:
    """Denormalize a single condition from YAML to API format."""
    if not cond:
        return {}
    var_str = cond.get("variable", "")
    var_int = _unresolve(STR_TO_VARIABLE, var_str)
    sub = cond.get("variable_value", "")
    result: dict = {
        "variableTypes": {str(var_int): sub},
        "operatorType": _unresolve(STR_TO_OPERATOR, cond.get("operator", "")),
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
    for chain in config.get("chainedRuleConditions", []):
        chained = _normalize_condition(chain)
        if chained:
            conditions.append(chained)

    transformations = [
        _resolve(TRANSFORMATION_TO_STR, t) for t in config.get("transformationTypes", [])
    ]

    result: dict = {
        "ref": rule.get("ruleName", ""),
        "action": _resolve(ACTION_TO_STR, config.get("actionType", "")),
        "severity": _resolve(SEVERITY_TO_STR, config.get("severityType", "")),
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

    transformations = [
        _unresolve(STR_TO_TRANSFORMATION, t) for t in rule.get("transformations", [])
    ]

    primary_api = _denormalize_condition(primary) if primary else {}

    config: dict = {
        "actionType": _unresolve(STR_TO_ACTION, rule.get("action", "")),
        "severityType": _unresolve(STR_TO_SEVERITY, rule.get("severity", "info")),
        **primary_api,
        "transformationTypes": transformations,
    }
    if chained:
        config["chainedRuleConditions"] = chained

    result: dict = {
        "shieldZoneId": shield_zone_id,
        "ruleName": rule.get("ref", ""),
        "ruleConfiguration": config,
    }
    desc = rule.get("description", "")
    if desc:
        result["ruleDescription"] = desc
    return result


def _normalize_rate_limit(rule: dict) -> dict:
    """Convert an API rate limit rule to octorules YAML format."""
    api_id = rule.get("id")
    config = rule.get("ruleConfiguration", {})

    conditions: list[dict] = []
    primary = _normalize_condition(config)
    if primary:
        conditions.append(primary)
    for chain in config.get("chainedRuleConditions", []):
        chained = _normalize_condition(chain)
        if chained:
            conditions.append(chained)

    transformations = [
        _resolve(TRANSFORMATION_TO_STR, t) for t in config.get("transformationTypes", [])
    ]

    result: dict = {
        "ref": rule.get("ruleName", ""),
        "action": _resolve(ACTION_TO_STR, config.get("actionType", "")),
        "request_count": rule.get("requestCount", 0),
        "timeframe": _resolve(TIMEFRAME_TO_STR, rule.get("timeframe", "")),
        "block_time": _resolve(BLOCKTIME_TO_STR, rule.get("blockTime", "")),
        "counter_key_type": _resolve(COUNTER_KEY_TO_STR, rule.get("counterKeyType", "")),
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

    transformations = [
        _unresolve(STR_TO_TRANSFORMATION, t) for t in rule.get("transformations", [])
    ]

    primary_api = _denormalize_condition(primary) if primary else {}

    config: dict = {
        "actionType": _unresolve(STR_TO_ACTION, rule.get("action", "")),
        **primary_api,
        "transformationTypes": transformations,
    }
    if chained:
        config["chainedRuleConditions"] = chained

    result: dict = {
        "shieldZoneId": shield_zone_id,
        "ruleName": rule.get("ref", ""),
        "ruleConfiguration": config,
        "requestCount": rule.get("request_count", 0),
        "timeframe": _unresolve(STR_TO_TIMEFRAME, rule.get("timeframe", "")),
        "blockTime": _unresolve(STR_TO_BLOCKTIME, rule.get("block_time", "")),
        "counterKeyType": _unresolve(STR_TO_COUNTER_KEY, rule.get("counter_key_type", "")),
    }
    desc = rule.get("description", "")
    if desc:
        result["ruleDescription"] = desc
    return result


def _normalize_access_list(rule: dict) -> dict:
    """Convert an API access list to octorules YAML format."""
    return {
        "ref": str(rule.get("id", "")),
        "type": _resolve(ACCESS_LIST_TYPE_TO_STR, rule.get("accessListType", "")),
        "action": _resolve(ACTION_TO_STR, rule.get("actionType", "")),
        "enabled": bool(rule.get("enabled", True)),
        "content": rule.get("content", ""),
        "_api_id": rule.get("id"),
    }


def _denormalize_access_list(rule: dict, shield_zone_id: int) -> dict:
    """Convert a YAML access list to API format."""
    result: dict = {
        "shieldZoneId": shield_zone_id,
        "accessListType": _unresolve(STR_TO_ACCESS_LIST_TYPE, rule.get("type", "")),
        "actionType": _unresolve(STR_TO_ACTION, rule.get("action", "")),
        "enabled": rule.get("enabled", True),
        "content": rule.get("content", ""),
    }
    return result


# ---------------------------------------------------------------------------
# Edge Rule normalization (CDN-level rules on pull zone)
# ---------------------------------------------------------------------------
def _normalize_edge_trigger(trigger: dict) -> dict:
    """Normalize a single edge rule trigger from API to YAML format."""
    result: dict = {
        "type": _resolve(EDGE_TRIGGER_TO_STR, trigger.get("Type", "")),
        "pattern_matching_type": _resolve(
            EDGE_PATTERN_MATCH_TO_STR, trigger.get("PatternMatchingType", "")
        ),
        "pattern_matches": trigger.get("PatternMatches", []),
    }
    p1 = trigger.get("Parameter1", "")
    if p1 is not None and p1 != "":
        result["parameter_1"] = p1
    return result


def _denormalize_edge_trigger(trigger: dict) -> dict:
    """Denormalize a single edge rule trigger from YAML to API format."""
    result: dict = {
        "Type": _unresolve(STR_TO_EDGE_TRIGGER, trigger.get("type", "")),
        "PatternMatchingType": _unresolve(
            STR_TO_EDGE_PATTERN_MATCH, trigger.get("pattern_matching_type", "")
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
        "action_type": _resolve(EDGE_ACTION_TO_STR, rule.get("ActionType", "")),
        "action_parameter_1": rule.get("ActionParameter1", ""),
        "action_parameter_2": rule.get("ActionParameter2", ""),
        "trigger_matching_type": _resolve(
            EDGE_TRIGGER_MATCH_TO_STR, rule.get("TriggerMatchingType", "")
        ),
        "triggers": triggers,
    }
    return result


def _denormalize_edge_rule(rule: dict) -> dict:
    """Convert a YAML edge rule to API format."""
    triggers = [_denormalize_edge_trigger(t) for t in rule.get("triggers", [])]
    result: dict = {
        "ActionType": _unresolve(STR_TO_EDGE_ACTION, rule.get("action_type", "")),
        "ActionParameter1": rule.get("action_parameter_1", ""),
        "ActionParameter2": rule.get("action_parameter_2", ""),
        "TriggerMatchingType": _unresolve(
            STR_TO_EDGE_TRIGGER_MATCH, rule.get("trigger_matching_type", "all")
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
        self._lock = threading.Lock()
        # shield_zone_id (str) -> {pull_zone_id, name}
        self._zone_meta: dict[str, dict] = {}
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
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        return None

    @property
    def account_name(self) -> str | None:
        return None

    @property
    def zone_plans(self) -> dict[str, str]:
        return {}

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
        shield = self._client.get_shield_zone_by_pullzone(pull_zone_id)
        shield_zone_id = str(shield.get("shieldZoneId", shield.get("id", "")))
        if not shield_zone_id:
            raise ConfigError(
                f"Shield Zone not found for pull zone {zone_name!r}"
                " (is Bunny Shield enabled for this zone?)"
            )

        with self._lock:
            self._zone_meta[shield_zone_id] = {
                "pull_zone_id": pull_zone_id,
                "name": zone_name,
            }
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
            raw = self._client.list_access_lists(sz)
            result = [_normalize_access_list(r) for r in raw]
            log.debug(
                "get_phase_rules %s/%s: %d rules", self._fmt_scope(scope), provider_id, len(result)
            )
            return result
        return []

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
            return _denormalize_access_list(rule, shield_zone_id)
        if provider_id == "bunny_edge_rule":
            return _denormalize_edge_rule(rule)
        raise ProviderError(f"Unknown provider_id: {provider_id!r}")

    def _create_rule(self, provider_id: str, sz: int, payload: dict) -> None:
        if provider_id == "bunny_waf_custom":
            self._client.create_custom_waf_rule(payload)
        elif provider_id == "bunny_waf_rate_limit":
            self._client.create_rate_limit(payload)
        elif provider_id == "bunny_waf_access_list":
            self._client.create_access_list(sz, payload)
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
            self._client.update_access_list(sz, api_id, payload)
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

    # -- Shield config methods (used by extension hooks) --------------------

    @_wrap_provider_errors
    def get_shield_zone_config(self, scope: Scope) -> dict:
        """Fetch the Shield Zone configuration."""
        log.debug("GET shield_zone_config %s", self._fmt_scope(scope))
        return self._client.get_shield_zone(_shield_zone_id(scope))

    @_wrap_provider_errors
    def get_bot_detection_config(self, scope: Scope) -> dict:
        """Fetch bot detection configuration."""
        log.debug("GET bot_detection %s", self._fmt_scope(scope))
        return self._client.get_bot_detection(_shield_zone_id(scope))

    @_wrap_provider_errors
    def update_bot_detection_config(self, scope: Scope, payload: dict) -> dict:
        """Update bot detection configuration."""
        log.debug("PUT bot_detection %s", self._fmt_scope(scope))
        return self._client.update_bot_detection(_shield_zone_id(scope), payload)

    @_wrap_provider_errors
    def update_shield_zone_config(self, scope: Scope, payload: dict) -> dict:
        """Update Shield Zone configuration (DDoS, managed rules, etc.)."""
        payload["shieldZoneId"] = _shield_zone_id(scope)
        log.debug("PUT shield_zone_config %s", self._fmt_scope(scope))
        return self._client.update_shield_zone(payload)

    # -- Custom rulesets (not supported) ------------------------------------

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        return []

    @_wrap_provider_errors
    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        return []

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        raise ConfigError("Custom rulesets are not supported by Bunny Shield")

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        return {}

    # -- Lists (not supported) ----------------------------------------------

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        return []

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        raise ConfigError("Lists are not supported by Bunny Shield (use access list phase)")

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]:
        return []

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        raise ConfigError("Lists are not supported by Bunny Shield")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        return "completed"

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        return {}
