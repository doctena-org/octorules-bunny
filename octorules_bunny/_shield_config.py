"""Bot detection, DDoS config, and managed WAF rule overrides.

These are non-phase YAML sections handled via extension hooks:
- ``bunny_shield_config`` — bot detection and DDoS knobs
- ``bunny_waf_managed_rules`` — disable or log-only managed rules

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension — same pattern as Cloudflare's Page
Shield in ``octorules_cloudflare/page_shield.py``.
"""

import logging
import threading
from dataclasses import dataclass, field

from octorules_bunny._enums import (
    EXECUTION_MODE_TO_STR,
    SENSITIVITY_TO_STR,
    STR_TO_EXECUTION_MODE,
    STR_TO_SENSITIVITY,
    _resolve,
    _unresolve,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for config diffs
# ---------------------------------------------------------------------------
@dataclass
class ShieldConfigChange:
    """A single field change in a config section."""

    section: str  # "bot_detection", "ddos", or "managed_rules"
    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class ShieldConfigPlan:
    """Plan for all config changes in a zone."""

    changes: list[ShieldConfigChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)


# ---------------------------------------------------------------------------
# Shield config normalization
# ---------------------------------------------------------------------------
def normalize_shield_config(shield_zone: dict, bot_config: dict) -> dict:
    """Build the normalized ``bunny_shield_config`` dict from API data."""
    result: dict = {}

    if bot_config:
        result["bot_detection"] = {
            "execution_mode": _resolve(EXECUTION_MODE_TO_STR, bot_config.get("executionMode", 0)),
            "request_integrity_sensitivity": _resolve(
                SENSITIVITY_TO_STR, bot_config.get("requestIntegritySensitivity", 0)
            ),
            "ip_sensitivity": _resolve(SENSITIVITY_TO_STR, bot_config.get("ipSensitivity", 0)),
            "fingerprint_sensitivity": _resolve(
                SENSITIVITY_TO_STR, bot_config.get("fingerprintSensitivity", 0)
            ),
            "complex_fingerprinting": bool(bot_config.get("complexFingerprinting", False)),
        }

    if any(
        k in shield_zone
        for k in ("dDoSShieldSensitivity", "dDoSExecutionMode", "dDoSChallengeWindow")
    ):
        result["ddos"] = {
            "shield_sensitivity": _resolve(
                SENSITIVITY_TO_STR, shield_zone.get("dDoSShieldSensitivity", 0)
            ),
            "execution_mode": _resolve(
                EXECUTION_MODE_TO_STR, shield_zone.get("dDoSExecutionMode", 0)
            ),
            "challenge_window": shield_zone.get("dDoSChallengeWindow", 0),
        }

    return result


def denormalize_bot_config(config: dict) -> dict:
    """Convert YAML bot_detection section to API PATCH payload.

    Only includes keys that are present in *config* so that partial
    updates don't reset unspecified fields to defaults.
    """
    _MAP = {
        "execution_mode": ("executionMode", lambda v: _unresolve(STR_TO_EXECUTION_MODE, v)),
        "request_integrity_sensitivity": (
            "requestIntegritySensitivity",
            lambda v: _unresolve(STR_TO_SENSITIVITY, v),
        ),
        "ip_sensitivity": ("ipSensitivity", lambda v: _unresolve(STR_TO_SENSITIVITY, v)),
        "fingerprint_sensitivity": (
            "fingerprintSensitivity",
            lambda v: _unresolve(STR_TO_SENSITIVITY, v),
        ),
        "complex_fingerprinting": ("complexFingerprinting", lambda v: v),
    }
    result: dict = {}
    for yaml_key, (api_key, transform) in _MAP.items():
        if yaml_key in config:
            result[api_key] = transform(config[yaml_key])
    return result


def denormalize_ddos_config(config: dict) -> dict:
    """Convert YAML ddos section to Shield Zone PATCH payload fields.

    Only includes keys that are present in *config* so that partial
    updates don't reset unspecified fields to defaults.
    """
    _MAP = {
        "shield_sensitivity": (
            "dDoSShieldSensitivity",
            lambda v: _unresolve(STR_TO_SENSITIVITY, v),
        ),
        "execution_mode": ("dDoSExecutionMode", lambda v: _unresolve(STR_TO_EXECUTION_MODE, v)),
        "challenge_window": ("dDoSChallengeWindow", lambda v: v),
    }
    result: dict = {}
    for yaml_key, (api_key, transform) in _MAP.items():
        if yaml_key in config:
            result[api_key] = transform(config[yaml_key])
    return result


# ---------------------------------------------------------------------------
# Managed WAF rule overrides normalization
# ---------------------------------------------------------------------------
def normalize_managed_rules(shield_zone: dict) -> dict:
    """Build the normalized ``bunny_waf_managed_rules`` dict from API data."""
    disabled = shield_zone.get("wafDisabledRules", [])
    log_only = shield_zone.get("wafLogOnlyRules", [])

    result: dict = {}
    if disabled:
        result["disabled"] = sorted(str(r) for r in disabled)
    if log_only:
        result["log_only"] = sorted(str(r) for r in log_only)
    return result


def denormalize_managed_rules(config: dict) -> dict:
    """Convert YAML managed rules to Shield Zone PATCH payload fields."""
    result: dict = {}
    disabled = config.get("disabled")
    if disabled is not None:
        result["wafDisabledRules"] = [str(r) for r in disabled]
    log_only = config.get("log_only")
    if log_only is not None:
        result["wafLogOnlyRules"] = [str(r) for r in log_only]
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def _diff_dict(section: str, current: dict, desired: dict) -> list[ShieldConfigChange]:
    """Compare two flat dicts and return field-level changes."""
    changes: list[ShieldConfigChange] = []
    all_keys = sorted(desired.keys())
    for key in all_keys:
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(ShieldConfigChange(section=section, field=key, current=cur, desired=des))
    return changes


def diff_shield_config(current: dict, desired: dict) -> ShieldConfigPlan:
    """Diff current vs desired shield config. Returns a plan."""
    changes: list[ShieldConfigChange] = []
    for section in ("bot_detection", "ddos"):
        cur_section = current.get(section, {})
        des_section = desired.get(section, {})
        if cur_section or des_section:
            changes.extend(_diff_dict(section, cur_section, des_section))
    return ShieldConfigPlan(changes=changes)


def diff_managed_rules(current: dict, desired: dict) -> ShieldConfigPlan:
    """Diff current vs desired managed rule overrides."""
    changes: list[ShieldConfigChange] = []
    for key in ("disabled", "log_only"):
        cur = sorted(current.get(key, []))
        des = sorted(desired.get(key, []))
        if cur != des:
            changes.append(
                ShieldConfigChange(section="managed_rules", field=key, current=cur, desired=des)
            )
    return ShieldConfigPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_shield_config(all_desired, scope, provider):
    """Prefetch: fetch current shield zone + bot detection config."""
    desired_config = all_desired.get("bunny_shield_config")
    desired_managed = all_desired.get("bunny_waf_managed_rules")
    if desired_config is None and desired_managed is None:
        return None

    # Fetch current state via provider methods (error-wrapped)
    shield_zone = {}
    bot_config = {}
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        shield_zone = provider.get_shield_zone_config(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch shield zone config for %s", scope.label)
    if desired_config and desired_config.get("bot_detection"):
        try:
            bot_config = provider.get_bot_detection_config(scope)
        except ProviderAuthError:
            raise
        except ProviderError:
            log.warning("Failed to fetch bot detection config for %s", scope.label)

    return (shield_zone, bot_config, desired_config, desired_managed)


def _finalize_shield_config(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diffs and add to zone plan."""
    if ctx is None:
        return

    shield_zone, bot_config, desired_config, desired_managed = ctx

    # Shield config (bot + DDoS)
    if desired_config is not None:
        current_config = normalize_shield_config(shield_zone, bot_config)
        plan = diff_shield_config(current_config, desired_config)
        if plan.has_changes:
            zp.extension_plans.setdefault("bunny_shield_config", []).append(plan)

    # Managed rule overrides
    if desired_managed is not None:
        current_managed = normalize_managed_rules(shield_zone)
        plan = diff_managed_rules(current_managed, desired_managed)
        if plan.has_changes:
            zp.extension_plans.setdefault("bunny_waf_managed_rules", []).append(plan)


def _apply_shield_config(zp, plans, scope, provider):
    """Apply shield config and managed rule changes.

    Uses provider methods (not ``provider._client``) so that error
    wrapping (``@_wrap_provider_errors``) applies — auth errors will
    propagate as ``ProviderAuthError``, not raw ``BunnyAuthError``.
    """
    synced: list[str] = []
    # Collect desired values by section to avoid redundant API calls
    sections_done: set[str] = set()

    for plan in plans:
        if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
            continue

        for change in plan.changes:
            if not change.has_changes or change.section in sections_done:
                continue

            if change.section == "bot_detection":
                bot_desired = {
                    c.field: c.desired for c in plan.changes if c.section == "bot_detection"
                }
                if bot_desired:
                    payload = denormalize_bot_config(bot_desired)
                    provider.update_bot_detection_config(scope, payload)
                    synced.append("bunny_shield_config:bot_detection")
                sections_done.add("bot_detection")

            elif change.section == "ddos":
                ddos_desired = {c.field: c.desired for c in plan.changes if c.section == "ddos"}
                if ddos_desired:
                    payload = denormalize_ddos_config(ddos_desired)
                    provider.update_shield_zone_config(scope, payload)
                    synced.append("bunny_shield_config:ddos")
                sections_done.add("ddos")

            elif change.section == "managed_rules":
                managed_desired = {
                    c.field: c.desired for c in plan.changes if c.section == "managed_rules"
                }
                if managed_desired:
                    payload = denormalize_managed_rules(managed_desired)
                    provider.update_shield_zone_config(scope, payload)
                    synced.append("bunny_waf_managed_rules")
                sections_done.add("managed_rules")

    return synced, None


def _apply_managed_rules(zp, plans, scope, provider):
    """Apply managed rule override changes."""
    return _apply_shield_config(zp, plans, scope, provider)


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class ShieldConfigFormatter:
    """Formats shield config and managed rule diffs for plan output."""

    def format_plan(self, plans: list, zone_name: str) -> list[str]:
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                lines.append(
                    f"  {zone_name}/{change.section}.{change.field}:"
                    f" {change.current!r} -> {change.desired!r}"
                )
        return lines

    def count_changes(self, plans: list) -> int:
        count = 0
        for plan in plans:
            if isinstance(plan, ShieldConfigPlan):
                count += sum(1 for c in plan.changes if c.has_changes)
        return count

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"{change.section}.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "section": change.section,
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
        # pending_diffs is unused: shield config changes are field-level
        # (current -> desired) rather than rule-level diffs that accumulate
        # into the pending_diffs structure.
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"{change.section}.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"{change.section}.{change.field}")
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
            if not isinstance(plan, ShieldConfigPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "shield_config",
                    "provider_id": "bunny_shield_config",
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
_VALID_EXECUTION_MODES = frozenset(STR_TO_EXECUTION_MODE)
_VALID_SENSITIVITIES = frozenset(STR_TO_SENSITIVITY)


def _validate_shield_config(desired, zone_name, errors, lines):
    """Validate bunny_shield_config and bunny_waf_managed_rules offline."""
    config = desired.get("bunny_shield_config")
    if isinstance(config, dict):
        bot = config.get("bot_detection", {})
        if isinstance(bot, dict):
            em = bot.get("execution_mode", "")
            if em and em not in _VALID_EXECUTION_MODES:
                errors.append(
                    f"  {zone_name}/bunny_shield_config: invalid"
                    f" bot_detection.execution_mode {em!r}"
                )
            for key in (
                "request_integrity_sensitivity",
                "ip_sensitivity",
                "fingerprint_sensitivity",
            ):
                val = bot.get(key, "")
                if val and val not in _VALID_SENSITIVITIES:
                    errors.append(
                        f"  {zone_name}/bunny_shield_config: invalid bot_detection.{key} {val!r}"
                    )

        ddos = config.get("ddos", {})
        if isinstance(ddos, dict):
            em = ddos.get("execution_mode", "")
            if em and em not in _VALID_EXECUTION_MODES:
                errors.append(
                    f"  {zone_name}/bunny_shield_config: invalid ddos.execution_mode {em!r}"
                )
            ss = ddos.get("shield_sensitivity", "")
            if ss and ss not in _VALID_SENSITIVITIES:
                errors.append(
                    f"  {zone_name}/bunny_shield_config: invalid ddos.shield_sensitivity {ss!r}"
                )
            cw = ddos.get("challenge_window")
            if cw is not None and (not isinstance(cw, int) or isinstance(cw, bool) or cw < 0):
                errors.append(
                    f"  {zone_name}/bunny_shield_config: invalid"
                    f" ddos.challenge_window {cw!r} (must be non-negative int)"
                )

    managed = desired.get("bunny_waf_managed_rules")
    if isinstance(managed, dict):
        for key in ("disabled", "log_only"):
            val = managed.get(key)
            if val is not None and not isinstance(val, list):
                errors.append(
                    f"  {zone_name}/bunny_waf_managed_rules: {key}"
                    f" must be a list, got {type(val).__name__}"
                )


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
def _dump_shield_config(scope, provider, out_dir):
    """Export current shield config and managed rules to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    result: dict = {}
    try:
        shield_zone = provider.get_shield_zone_config(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None
    try:
        bot_config = provider.get_bot_detection_config(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        bot_config = {}

    config = normalize_shield_config(shield_zone, bot_config)
    if config:
        result["bunny_shield_config"] = config

    managed = normalize_managed_rules(shield_zone)
    if managed:
        result["bunny_waf_managed_rules"] = managed

    return result if result else None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
_registered = False
_register_lock = threading.Lock()


def register_shield_config() -> None:
    """Register all shield config hooks with the core extension system."""
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

    register_plan_zone_hook(_prefetch_shield_config, _finalize_shield_config)
    register_apply_extension("bunny_shield_config", _apply_shield_config)
    register_apply_extension("bunny_waf_managed_rules", _apply_managed_rules)
    register_format_extension("bunny_shield_config", ShieldConfigFormatter())
    register_format_extension("bunny_waf_managed_rules", ShieldConfigFormatter())
    register_validate_extension(_validate_shield_config)
    register_dump_extension(_dump_shield_config)
