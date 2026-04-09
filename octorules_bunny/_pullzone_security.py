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
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

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
    "logging_ip_anonymization": "LoggingIPAnonymization",
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
        "logging_ip_anonymization",
    }
)

_STR_FIELDS: frozenset[str] = frozenset(
    {
        "blocked_ips",
        "blocked_countries",
        "blocked_referrers",
        "allowed_referrers",
        "cors_extensions",
    }
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class PullZoneSecurityChange:
    """A single field change in pull zone security config."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class PullZoneSecurityPlan:
    """Plan for all pull zone security changes."""

    changes: list[PullZoneSecurityChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_pullzone_security(pz: dict) -> dict:
    """Extract security-relevant fields from pull zone object."""
    return {
        "blocked_ips": pz.get("BlockedIps", ""),
        "blocked_countries": pz.get("BlockedCountries", ""),
        "blocked_referrers": pz.get("BlockedReferrers", ""),
        "allowed_referrers": pz.get("AllowedReferrers", ""),
        "block_post_requests": pz.get("BlockPostRequests", False),
        "block_root_path_access": pz.get("BlockRootPathAccess", False),
        "enable_token_authentication": pz.get("EnableTokenAuthentication", False),
        "token_auth_include_ip": pz.get("ZoneSecurityIncludeHashRemoteIP", False),
        "block_none_referrer": pz.get("BlockNoneReferrer", False),
        "cors_enabled": pz.get("EnableAccessControlOriginHeader", False),
        "cors_extensions": pz.get("AccessControlOriginHeaderExtensions", ""),
        "logging_ip_anonymization": pz.get("LoggingIPAnonymization", False),
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
def _diff_dict(current: dict, desired: dict) -> list[PullZoneSecurityChange]:
    """Compare two flat dicts and return field-level changes."""
    changes: list[PullZoneSecurityChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(PullZoneSecurityChange(field=key, current=cur, desired=des))
    return changes


def diff_pullzone_security(current: dict, desired: dict) -> PullZoneSecurityPlan:
    """Diff current vs desired pull zone security config. Returns a plan."""
    changes = _diff_dict(current, desired)
    return PullZoneSecurityPlan(changes=changes)


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
        if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_pullzone_security(scope, desired_values)
            synced.append("bunny_pullzone_security")
            break  # Single API call covers all fields

    return synced, None


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class PullZoneSecurityFormatter:
    """Formats pull zone security config diffs for plan output."""

    def format_plan(self, plans: list, zone_name: str) -> list[str]:
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                lines.append(
                    f"  {zone_name}/pullzone_security.{change.field}:"
                    f" {change.current!r} -> {change.desired!r}"
                )
        return lines

    def count_changes(self, plans: list) -> int:
        count = 0
        for plan in plans:
            if isinstance(plan, PullZoneSecurityPlan):
                count += sum(1 for c in plan.changes if c.has_changes)
        return count

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"pullzone_security.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "field": change.field,
                        "current": change.current,
                        "desired": change.desired,
                    }
                )
            if changes:
                result.append({"changes": changes})
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"pullzone_security.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"pullzone_security.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, PullZoneSecurityPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "pullzone_security",
                    "provider_id": "bunny_pullzone_security",
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift


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

    for key in _STR_FIELDS:
        val = config.get(key)
        if val is not None and not isinstance(val, str):
            errors.append(
                f"  {zone_name}/bunny_pullzone_security:"
                f" {key} must be a string, got {type(val).__name__}"
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
    register_format_extension("bunny_pullzone_security", PullZoneSecurityFormatter())
    register_validate_extension(_validate_pullzone_security)
    register_dump_extension(_dump_pullzone_security)
