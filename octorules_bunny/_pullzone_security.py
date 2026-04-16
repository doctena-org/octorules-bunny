"""Pull zone security settings managed as code.

Manages CDN-level security fields on the pull zone object:
IP blocking, country blocking, hotlink protection (referrer
allow/block), token authentication, CORS headers, and privacy
settings (IP anonymization).

Uses the same extension hook pattern as ``_shield_config.py``:
plan_zone_hook (prefetch + finalize), apply_extension,
format_extension, validate_extension, and dump_extension.
"""

import logging
import threading

from octorules_bunny._config_base import ConfigChange, ConfigFormatter, ConfigPlan

log = logging.getLogger(__name__)

# Re-export for backward compatibility (tests, other modules that import these).
PullZoneSecurityChange = ConfigChange
PullZoneSecurityPlan = ConfigPlan
PullZoneSecurityFormatter = ConfigFormatter

# ---------------------------------------------------------------------------
# Field mapping: YAML key -> API key
# ---------------------------------------------------------------------------
_FIELD_MAP: dict[str, str] = {
    "blocked_ips": "BlockedIps",
    "blocked_countries": "BlockedCountries",
    "blocked_referrers": "BlockedReferrers",
    "allowed_referrers": "AllowedReferrers",
    "block_post_requests": "BlockPostRequests",
    "block_root_path_access": "BlockRootPathAccess",
    "enable_token_authentication": "EnableTokenAuthentication",
    "token_auth_include_ip": "ZoneSecurityIncludeHashRemoteIP",
    "block_none_referrer": "BlockNoneReferrer",
    "cors_enabled": "EnableAccessControlOriginHeader",
    "cors_extensions": "AccessControlOriginHeaderExtensions",
    "logging_ip_anonymization_type": "LogAnonymizationType",
}

# Reverse mapping: API key -> YAML key
_API_TO_YAML: dict[str, str] = {v: k for k, v in _FIELD_MAP.items()}

# Expected types for validation
_BOOL_FIELDS: frozenset[str] = frozenset(
    {
        "block_post_requests",
        "block_root_path_access",
        "enable_token_authentication",
        "token_auth_include_ip",
        "block_none_referrer",
        "cors_enabled",
    }
)

_INT_FIELDS: frozenset[str] = frozenset(
    {
        "logging_ip_anonymization_type",
    }
)

_LIST_FIELDS: frozenset[str] = frozenset(
    {
        "blocked_ips",
        "blocked_countries",
        "blocked_referrers",
        "allowed_referrers",
        "cors_extensions",
    }
)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_pullzone_security(pz: dict) -> dict:
    """Extract security-relevant fields from pull zone object.

    The Bunny API returns list fields (``BlockedIps``, ``BlockedCountries``,
    etc.) as JSON arrays, not strings.
    """
    return {
        "blocked_ips": pz.get("BlockedIps", []),
        "blocked_countries": pz.get("BlockedCountries", []),
        "blocked_referrers": pz.get("BlockedReferrers", []),
        "allowed_referrers": pz.get("AllowedReferrers", []),
        "block_post_requests": pz.get("BlockPostRequests", False),
        "block_root_path_access": pz.get("BlockRootPathAccess", False),
        "enable_token_authentication": pz.get("EnableTokenAuthentication", False),
        "token_auth_include_ip": pz.get("ZoneSecurityIncludeHashRemoteIP", False),
        "block_none_referrer": pz.get("BlockNoneReferrer", False),
        "cors_enabled": pz.get("EnableAccessControlOriginHeader", False),
        "cors_extensions": pz.get("AccessControlOriginHeaderExtensions", []),
        "logging_ip_anonymization_type": pz.get("LogAnonymizationType", 0),
    }


def denormalize_pullzone_security(config: dict) -> dict:
    """Convert YAML pullzone security section to API payload.

    Only includes keys that are present in *config* so that partial
    updates don't reset unspecified fields to defaults.
    """
    return {
        api_key: config[yaml_key] for yaml_key, api_key in _FIELD_MAP.items() if yaml_key in config
    }


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_pullzone_security(current: dict, desired: dict) -> ConfigPlan:
    """Diff current vs desired pull zone security config. Returns a plan."""
    changes: list[ConfigChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(
                ConfigChange(section="pullzone_security", field=key, current=cur, desired=des)
            )
    return ConfigPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_pullzone_security(all_desired, scope, provider):
    """Prefetch: fetch current pull zone security config."""
    desired = all_desired.get("bunny_pullzone_security")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_pullzone_security(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch pull zone security config for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_pullzone_security(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diffs and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_pullzone_security(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("bunny_pullzone_security", []).append(plan)


def _apply_pullzone_security(zp, plans, scope, provider):
    """Apply pull zone security config changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, ConfigPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_pullzone_security(scope, desired_values)
            synced.append("bunny_pullzone_security")
            break  # Single API call covers all fields

    return synced, None


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
def _validate_pullzone_security(desired, zone_name, errors, lines):
    """Validate bunny_pullzone_security offline."""
    config = desired.get("bunny_pullzone_security")
    if not isinstance(config, dict):
        return

    for key in config:
        if key not in _FIELD_MAP:
            errors.append(f"  {zone_name}/bunny_pullzone_security: unknown field {key!r}")

    for key in _BOOL_FIELDS:
        val = config.get(key)
        if val is not None and not isinstance(val, bool):
            errors.append(
                f"  {zone_name}/bunny_pullzone_security:"
                f" {key} must be a bool, got {type(val).__name__}"
            )

    for key in _LIST_FIELDS:
        val = config.get(key)
        if val is not None and not isinstance(val, list):
            errors.append(
                f"  {zone_name}/bunny_pullzone_security:"
                f" {key} must be a list, got {type(val).__name__}"
            )

    for key in _INT_FIELDS:
        val = config.get(key)
        if val is not None and (not isinstance(val, int) or isinstance(val, bool)):
            errors.append(
                f"  {zone_name}/bunny_pullzone_security:"
                f" {key} must be an int, got {type(val).__name__}"
            )


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
def _dump_pullzone_security(scope, provider, out_dir):
    """Export current pull zone security config to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        config = provider.get_pullzone_security(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if config:
        return {"bunny_pullzone_security": config}
    return None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
_registered = False
_register_lock = threading.Lock()


def register_pullzone_security() -> None:
    """Register all pull zone security hooks with the core extension system."""
    global _registered
    with _register_lock:
        if _registered:
            return
        _registered = True

    from octorules.extensions import (
        register_apply_extension,
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_pullzone_security, _finalize_pullzone_security)
    register_apply_extension("bunny_pullzone_security", _apply_pullzone_security)
    register_format_extension("bunny_pullzone_security", ConfigFormatter("bunny_pullzone_security"))
    register_validate_extension(_validate_pullzone_security)
    register_dump_extension(_dump_pullzone_security)
