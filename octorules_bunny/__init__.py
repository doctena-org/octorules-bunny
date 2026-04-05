"""Bunny.net Shield WAF provider for octorules."""

from octorules.phases import register_api_fields, register_non_phase_key, register_phases

from octorules_bunny._phases import BUNNY_PHASE_IDS, BUNNY_PHASE_NAMES, BUNNY_PHASES
from octorules_bunny.provider import BunnyShieldProvider
from octorules_bunny.validate import validate_rules

register_phases(BUNNY_PHASES)
register_api_fields("rule", {"_api_id", "shieldZoneId", "Guid"})
register_non_phase_key("bunny_waf_managed_rules")
register_non_phase_key("bunny_shield_config")
register_non_phase_key("bunny_pullzone_security")

from octorules_bunny.linter import register_bunny_linter  # noqa: E402

register_bunny_linter()

from octorules_bunny.audit import register_bunny_audit  # noqa: E402

register_bunny_audit()

from octorules_bunny._shield_config import register_shield_config  # noqa: E402

register_shield_config()

from octorules_bunny._pullzone_security import register_pullzone_security  # noqa: E402

register_pullzone_security()

__all__ = [
    "BUNNY_PHASE_IDS",
    "BUNNY_PHASE_NAMES",
    "BunnyShieldProvider",
    "validate_rules",
]
