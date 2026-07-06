"""Bunny.net Shield WAF provider for octorules."""

from octorules.phases import (
    register_api_fields,
    register_namespace,
    register_non_phase_key,
    register_phases,
)

from octorules_bunny._phases import BUNNY_PHASE_IDS, BUNNY_PHASE_NAMES, BUNNY_PHASES
from octorules_bunny.provider import BunnyShieldProvider
from octorules_bunny.validate import validate_rules

register_phases(BUNNY_PHASES)
register_api_fields("rule", {"_api_id", "_config_id", "shieldZoneId", "Guid"})
register_non_phase_key("bunny_waf_managed_rules")
register_non_phase_key("bunny_shield_config")
register_non_phase_key("bunny_pullzone_security")
register_non_phase_key("bunny_curated_threat_lists")

# Register nested zone-file format: bunny: { waf_custom_rules: [...] }
register_namespace(
    "bunny",
    {
        "waf_custom_rules": "bunny_waf_custom_rules",
        "waf_rate_limit_rules": "bunny_waf_rate_limit_rules",
        "waf_access_list_rules": "bunny_waf_access_list_rules",
        "edge_rules": "bunny_edge_rules",
        "waf_managed_rules": "bunny_waf_managed_rules",
        "shield_config": "bunny_shield_config",
        "pullzone_security": "bunny_pullzone_security",
        "curated_threat_lists": "bunny_curated_threat_lists",
    },
)

from octorules_bunny.linter import register_bunny_linter  # noqa: E402

register_bunny_linter()

from octorules_bunny.audit import register_bunny_audit  # noqa: E402

register_bunny_audit()

from octorules_bunny._shield_config import register_shield_config  # noqa: E402

register_shield_config()

from octorules_bunny._pullzone_security import register_pullzone_security  # noqa: E402

register_pullzone_security()

from octorules_bunny._curated_lists import register_curated_lists  # noqa: E402

register_curated_lists()

__all__ = [
    "BUNNY_PHASE_IDS",
    "BUNNY_PHASE_NAMES",
    "BunnyShieldProvider",
    "validate_rules",
]
