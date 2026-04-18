"""Curated threat lists (Bunny-managed access lists).

Manages the enable/disable state and action for Bunny's curated threat
intelligence lists (VPN Providers, TOR Exit Nodes, Common Datacenters,
AbuseIPDB, FireHOL, etc.).

These are Bunny-maintained lists that cannot be created or deleted — only
their ``isEnabled`` and ``action`` can be toggled via the access list
configurations endpoint.

YAML section: ``bunny_curated_threat_lists``

Example::

    bunny_curated_threat_lists:
      VPN Providers:
        enabled: true
        action: block
      TOR Exit Nodes:
        enabled: true
        action: challenge
      AbuseIPDB:
        enabled: false
"""

import logging

from octorules.registration import idempotent_registration

from octorules_bunny._config_base import ConfigChange, ConfigFormatter, ConfigPlan
from octorules_bunny._enums import ACCESS_LIST_ACTION

log = logging.getLogger(__name__)

_VALID_ACTIONS = frozenset(ACCESS_LIST_ACTION)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_curated_lists(managed_lists: list[dict]) -> dict:
    """Normalize the ``managedLists`` array from the access lists API.

    Returns a dict keyed by list name::

        {"VPN Providers": {"enabled": False, "action": "log", "_config_id": 100}, ...}
    """
    result: dict = {}
    for ml in managed_lists:
        name = ml.get("name", "")
        if not name:
            continue
        result[name] = {
            "enabled": bool(ml.get("isEnabled", False)),
            "action": ACCESS_LIST_ACTION.resolve(ml.get("action", 4)),
            "_config_id": ml.get("configurationId"),
        }
    return result


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
def diff_curated_lists(current: dict, desired: dict) -> ConfigPlan:
    """Diff current vs desired curated threat list config.

    Only lists present in *desired* are compared.  Lists not mentioned
    in the YAML are left untouched.
    """
    changes: list[ConfigChange] = []
    for name, des in desired.items():
        cur = current.get(name)
        if cur is None:
            # List doesn't exist on the API side (unknown name) — skip
            continue
        cur_enabled = cur.get("enabled")
        cur_action = cur.get("action")
        des_enabled = des.get("enabled")
        des_action = des.get("action")
        if cur_enabled != des_enabled or cur_action != des_action:
            changes.append(
                ConfigChange(
                    section="curated_threat_lists",
                    field=name,
                    current=cur,
                    desired=des,
                )
            )
    return ConfigPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_curated_lists(all_desired, scope, provider):
    """Prefetch: fetch current managed access lists."""
    desired = all_desired.get("bunny_curated_threat_lists")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        managed = provider.get_managed_access_lists(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch curated threat lists for %s", scope.label)
        managed = []

    return (managed, desired)


def _finalize_curated_lists(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diffs and add to zone plan."""
    if ctx is None:
        return

    managed, desired = ctx
    current = normalize_curated_lists(managed)
    plan = diff_curated_lists(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("bunny_curated_threat_lists", []).append(plan)


def _apply_curated_lists(zp, plans, scope, provider):
    """Apply curated threat list config changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ConfigPlan) or not plan.has_changes:
            continue

        for change in plan.changes:
            if not change.has_changes:
                continue
            name = change.field
            cur = change.current
            des = change.desired
            config_id = cur.get("_config_id") if isinstance(cur, dict) else None
            if config_id is None:
                log.warning("No config_id for curated list %r — skipping", name)
                continue
            payload = {
                "isEnabled": des.get("enabled", False),
                "action": ACCESS_LIST_ACTION.unresolve(des.get("action", "log")),
            }
            provider.update_curated_list_config(scope, config_id, payload)
            synced.append(f"bunny_curated_threat_lists:{name}")

    return synced, None


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
def _validate_curated_lists(desired, zone_name, errors, lines):
    """Validate bunny_curated_threat_lists offline."""
    config = desired.get("bunny_curated_threat_lists")
    if not isinstance(config, dict):
        return

    pfx = f"  {zone_name}/bunny_curated_threat_lists"
    for name, entry in config.items():
        if not isinstance(entry, dict):
            errors.append(f"{pfx}: {name!r} must be a mapping, got {type(entry).__name__}")
            continue
        en = entry.get("enabled")
        if en is not None and not isinstance(en, bool):
            errors.append(f"{pfx}: {name}.enabled must be a bool, got {type(en).__name__}")
        action = entry.get("action", "")
        if action and action not in _VALID_ACTIONS:
            errors.append(
                f"{pfx}: {name}.action {action!r} is invalid (valid: {sorted(_VALID_ACTIONS)})"
            )


# ---------------------------------------------------------------------------
# Dump
# ---------------------------------------------------------------------------
def _dump_curated_lists(scope, provider, out_dir):
    """Export current curated threat list config to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        managed = provider.get_managed_access_lists(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if not managed:
        return None

    normalized = normalize_curated_lists(managed)
    # Strip internal _config_id for dump output
    result = {}
    for name, entry in normalized.items():
        result[name] = {k: v for k, v in entry.items() if not k.startswith("_")}

    return {"bunny_curated_threat_lists": result} if result else None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@idempotent_registration
def register_curated_lists() -> None:
    """Register curated threat list hooks with the core extension system."""
    from octorules.extensions import (
        register_apply_extension,
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_curated_lists, _finalize_curated_lists)
    register_apply_extension("bunny_curated_threat_lists", _apply_curated_lists)
    register_format_extension(
        "bunny_curated_threat_lists", ConfigFormatter("bunny_curated_threat_lists")
    )
    register_validate_extension(_validate_curated_lists)
    register_dump_extension(_dump_curated_lists)
