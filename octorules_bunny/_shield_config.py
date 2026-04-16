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

from octorules_bunny._config_base import ConfigChange, ConfigFormatter, ConfigPlan, diff_flat_dicts
from octorules_bunny._enums import (
    EXECUTION_MODE,
    SENSITIVITY,
)

log = logging.getLogger(__name__)

# Re-export for backward compatibility (tests, other modules that import these).
ShieldConfigChange = ConfigChange
ShieldConfigPlan = ConfigPlan
ShieldConfigFormatter = ConfigFormatter


# ---------------------------------------------------------------------------
# Shield config normalization
# ---------------------------------------------------------------------------
def normalize_shield_config(
    shield_zone: dict, bot_config: dict, *, upload_config: dict | None = None
) -> dict:
    """Build the normalized ``bunny_shield_config`` dict from API data."""
    result: dict = {}

    if bot_config:
        # The bot detection API uses nested objects:
        #   requestIntegrity.sensitivity, ipAddress.sensitivity,
        #   browserFingerprint.sensitivity, browserFingerprint.complexEnabled
        ri = bot_config.get("requestIntegrity", {})
        ip = bot_config.get("ipAddress", {})
        bf = bot_config.get("browserFingerprint", {})
        result["bot_detection"] = {
            "execution_mode": EXECUTION_MODE.resolve(bot_config.get("executionMode", 0)),
            "request_integrity_sensitivity": SENSITIVITY.resolve(
                ri.get("sensitivity", 0) if isinstance(ri, dict) else 0
            ),
            "ip_sensitivity": SENSITIVITY.resolve(
                ip.get("sensitivity", 0) if isinstance(ip, dict) else 0
            ),
            "fingerprint_sensitivity": SENSITIVITY.resolve(
                bf.get("sensitivity", 0) if isinstance(bf, dict) else 0
            ),
            "complex_fingerprinting": bool(
                bf.get("complexEnabled", False) if isinstance(bf, dict) else False
            ),
            "fingerprint_aggression": (bf.get("aggression", 1) if isinstance(bf, dict) else 1),
        }

    if any(
        k in shield_zone
        for k in ("dDoSShieldSensitivity", "dDoSExecutionMode", "dDoSChallengeWindow")
    ):
        result["ddos"] = {
            "shield_sensitivity": SENSITIVITY.resolve(shield_zone.get("dDoSShieldSensitivity", 0)),
            "execution_mode": EXECUTION_MODE.resolve(shield_zone.get("dDoSExecutionMode", 0)),
            "challenge_window": shield_zone.get("dDoSChallengeWindow", 0),
        }

    # WAF settings — global switches, learning mode, body limits, engine config
    # WAFExecutionMode: 0=Log, 1=Block (different from the general EXECUTION_MODE)
    _WAF_EXEC = {0: "log", 1: "block"}
    result["waf"] = {
        "enabled": bool(shield_zone.get("wafEnabled", False)),
        "execution_mode": _WAF_EXEC.get(shield_zone.get("wafExecutionMode", 0), "log"),
        "learning_mode": bool(shield_zone.get("learningMode", False)),
        "learning_mode_until": shield_zone.get("learningModeUntil", ""),
        "request_body_limit_action": shield_zone.get("wafRequestBodyLimitAction", 0),
        "response_body_limit_action": shield_zone.get("wafResponseBodyLimitAction", 0),
        "whitelabel_response_pages": bool(shield_zone.get("whitelabelResponsePages", False)),
        "request_header_logging_enabled": bool(
            shield_zone.get("wafRequestHeaderLoggingEnabled", False)
        ),
        "request_ignored_headers": shield_zone.get("wafRequestIgnoredHeaders", []),
        "realtime_threat_intelligence_enabled": bool(
            shield_zone.get("wafRealtimeThreatIntelligenceEnabled", False)
        ),
        "profile_id": shield_zone.get("wafProfileId"),
        "engine_config": shield_zone.get("wafEngineConfig") or [],
    }

    # Upload scanning (separate API endpoint)
    if upload_config:
        result["upload_scanning"] = {
            "enabled": bool(upload_config.get("isEnabled", False)),
            "csam_scanning_mode": upload_config.get("csamScanningMode", 0),
            "antivirus_scanning_mode": upload_config.get("antivirusScanningMode", 0),
        }

    return result


def denormalize_bot_config(config: dict) -> dict:
    """Convert YAML bot_detection section to API PATCH payload.

    The bot detection API uses nested objects::

        {
            "executionMode": 1,
            "requestIntegrity": {"sensitivity": 1},
            "ipAddress": {"sensitivity": 1},
            "browserFingerprint": {"sensitivity": 2, "complexEnabled": true}
        }

    Only includes keys that are present in *config* so that partial
    updates don't reset unspecified fields to defaults.
    """
    result: dict = {}
    if "execution_mode" in config:
        result["executionMode"] = EXECUTION_MODE.unresolve(config["execution_mode"])
    if "request_integrity_sensitivity" in config:
        result["requestIntegrity"] = {
            "sensitivity": SENSITIVITY.unresolve(config["request_integrity_sensitivity"])
        }
    if "ip_sensitivity" in config:
        result["ipAddress"] = {"sensitivity": SENSITIVITY.unresolve(config["ip_sensitivity"])}
    _BF_KEYS = ("fingerprint_sensitivity", "complex_fingerprinting", "fingerprint_aggression")
    if any(k in config for k in _BF_KEYS):
        bf: dict = {}
        if "fingerprint_sensitivity" in config:
            bf["sensitivity"] = SENSITIVITY.unresolve(config["fingerprint_sensitivity"])
        if "complex_fingerprinting" in config:
            bf["complexEnabled"] = config["complex_fingerprinting"]
        if "fingerprint_aggression" in config:
            bf["aggression"] = config["fingerprint_aggression"]
        result["browserFingerprint"] = bf
    return result


def denormalize_ddos_config(config: dict) -> dict:
    """Convert YAML ddos section to Shield Zone PATCH payload fields.

    Only includes keys that are present in *config* so that partial
    updates don't reset unspecified fields to defaults.
    """
    _MAP = {
        "shield_sensitivity": (
            "dDoSShieldSensitivity",
            lambda v: SENSITIVITY.unresolve(v),
        ),
        "execution_mode": ("dDoSExecutionMode", lambda v: EXECUTION_MODE.unresolve(v)),
        "challenge_window": ("dDoSChallengeWindow", lambda v: v),
    }
    result: dict = {}
    for yaml_key, (api_key, transform) in _MAP.items():
        if yaml_key in config:
            result[api_key] = transform(config[yaml_key])
    return result


def denormalize_waf_settings(config: dict) -> dict:
    """Convert YAML waf section to Shield Zone PATCH payload fields.

    ``learning_mode_until`` is read-only (set by the API when learning
    mode is enabled) and is excluded from the denormalized output.
    """
    # WAFExecutionMode: "log"->0, "block"->1
    _WAF_EXEC_REV = {"log": 0, "block": 1}
    _MAP = {
        "enabled": ("wafEnabled", lambda v: v),
        "execution_mode": ("wafExecutionMode", lambda v: _WAF_EXEC_REV.get(v, 0)),
        "learning_mode": ("learningMode", lambda v: v),
        "request_body_limit_action": ("wafRequestBodyLimitAction", lambda v: v),
        "response_body_limit_action": ("wafResponseBodyLimitAction", lambda v: v),
        "whitelabel_response_pages": ("whitelabelResponsePages", lambda v: v),
        "request_header_logging_enabled": ("wafRequestHeaderLoggingEnabled", lambda v: v),
        "request_ignored_headers": ("wafRequestIgnoredHeaders", lambda v: v),
        "realtime_threat_intelligence_enabled": (
            "wafRealtimeThreatIntelligenceEnabled",
            lambda v: v,
        ),
        "profile_id": ("wafProfileId", lambda v: v),
        "engine_config": ("wafEngineConfig", lambda v: v),
    }
    result: dict = {}
    for yaml_key, (api_key, transform) in _MAP.items():
        if yaml_key in config:
            result[api_key] = transform(config[yaml_key])
    return result


def denormalize_upload_scanning(config: dict) -> dict:
    """Convert YAML upload_scanning section to API PATCH payload."""
    _MAP = {
        "enabled": ("isEnabled", lambda v: v),
        "csam_scanning_mode": ("csamScanningMode", lambda v: v),
        "antivirus_scanning_mode": ("antivirusScanningMode", lambda v: v),
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
def diff_shield_config(current: dict, desired: dict) -> ConfigPlan:
    """Diff current vs desired shield config. Returns a plan."""
    changes: list[ConfigChange] = []
    for section in ("bot_detection", "ddos", "waf", "upload_scanning"):
        cur_section = current.get(section, {})
        des_section = desired.get(section, {})
        if cur_section or des_section:
            changes.extend(diff_flat_dicts(section, cur_section, des_section))
    return ConfigPlan(changes=changes)


def diff_managed_rules(current: dict, desired: dict) -> ConfigPlan:
    """Diff current vs desired managed rule overrides."""
    changes: list[ConfigChange] = []
    for key in ("disabled", "log_only"):
        cur = sorted(current.get(key, []))
        des = sorted(desired.get(key, []))
        if cur != des:
            changes.append(
                ConfigChange(section="managed_rules", field=key, current=cur, desired=des)
            )
    return ConfigPlan(changes=changes)


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

    upload_config = {}
    if desired_config and desired_config.get("upload_scanning"):
        try:
            upload_config = provider.get_upload_scanning_config(scope)
        except ProviderAuthError:
            raise
        except ProviderError:
            log.warning("Failed to fetch upload scanning config for %s", scope.label)

    return (shield_zone, bot_config, upload_config, desired_config, desired_managed)


def _finalize_shield_config(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diffs and add to zone plan."""
    if ctx is None:
        return

    shield_zone, bot_config, upload_config, desired_config, desired_managed = ctx

    # Shield config (bot + DDoS + waf + upload_scanning)
    if desired_config is not None:
        current_config = normalize_shield_config(
            shield_zone, bot_config, upload_config=upload_config
        )
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
        if not isinstance(plan, ConfigPlan) or not plan.has_changes:
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

            elif change.section == "waf":
                waf_desired = {c.field: c.desired for c in plan.changes if c.section == "waf"}
                if waf_desired:
                    payload = denormalize_waf_settings(waf_desired)
                    provider.update_shield_zone_config(scope, payload)
                    synced.append("bunny_shield_config:waf")
                sections_done.add("waf")

            elif change.section == "upload_scanning":
                us_desired = {
                    c.field: c.desired for c in plan.changes if c.section == "upload_scanning"
                }
                if us_desired:
                    payload = denormalize_upload_scanning(us_desired)
                    provider.update_upload_scanning_config(scope, payload)
                    synced.append("bunny_shield_config:upload_scanning")
                sections_done.add("upload_scanning")

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
# Validate extension
# ---------------------------------------------------------------------------
_VALID_EXECUTION_MODES = frozenset(EXECUTION_MODE)
_VALID_SENSITIVITIES = frozenset(SENSITIVITY)


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
            fa = bot.get("fingerprint_aggression")
            if fa is not None and (not isinstance(fa, int) or isinstance(fa, bool)):
                errors.append(
                    f"  {zone_name}/bunny_shield_config: invalid"
                    f" bot_detection.fingerprint_aggression {fa!r} (must be int)"
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

        waf = config.get("waf", {})
        if isinstance(waf, dict):
            _pfx = f"  {zone_name}/bunny_shield_config: invalid waf"
            for key in (
                "enabled",
                "learning_mode",
                "whitelabel_response_pages",
                "request_header_logging_enabled",
                "realtime_threat_intelligence_enabled",
            ):
                val = waf.get(key)
                if val is not None and not isinstance(val, bool):
                    errors.append(f"{_pfx}.{key} {val!r} (must be bool)")
            waf_em = waf.get("execution_mode", "")
            if waf_em and waf_em not in ("log", "block"):
                errors.append(f"{_pfx}.execution_mode {waf_em!r} (must be 'log' or 'block')")
            for key in ("request_body_limit_action", "response_body_limit_action"):
                val = waf.get(key)
                if val is not None and (not isinstance(val, int) or isinstance(val, bool)):
                    errors.append(f"{_pfx}.{key} {val!r} (must be int)")
            pid = waf.get("profile_id")
            if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool)):
                errors.append(f"{_pfx}.profile_id {pid!r} (must be int or null)")
            ec = waf.get("engine_config")
            if ec is not None and not isinstance(ec, list):
                errors.append(f"{_pfx}.engine_config {ec!r} (must be list)")
            igh = waf.get("request_ignored_headers")
            if igh is not None and not isinstance(igh, list):
                errors.append(f"{_pfx}.request_ignored_headers {igh!r} (must be list)")

        us = config.get("upload_scanning", {})
        if isinstance(us, dict):
            _pfx = f"  {zone_name}/bunny_shield_config: invalid upload_scanning"
            en = us.get("enabled")
            if en is not None and not isinstance(en, bool):
                errors.append(f"{_pfx}.enabled {en!r} (must be bool)")
            for key in ("csam_scanning_mode", "antivirus_scanning_mode"):
                val = us.get(key)
                if val is not None and (not isinstance(val, int) or isinstance(val, bool)):
                    errors.append(f"{_pfx}.{key} {val!r} (must be int)")

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
    try:
        upload_config = provider.get_upload_scanning_config(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        upload_config = {}

    config = normalize_shield_config(shield_zone, bot_config, upload_config=upload_config or None)
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
    register_format_extension("bunny_shield_config", ConfigFormatter("bunny_shield_config"))
    register_format_extension("bunny_waf_managed_rules", ConfigFormatter("bunny_waf_managed_rules"))
    register_validate_extension(_validate_shield_config)
    register_dump_extension(_dump_shield_config)
