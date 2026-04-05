"""Bunny Shield WAF phase definitions (shared between __init__ and provider)."""

from octorules.phases import Phase

BUNNY_PHASES = [
    Phase(
        "bunny_waf_custom_rules",
        "bunny_waf_custom",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "bunny_waf_rate_limit_rules",
        "bunny_waf_rate_limit",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "bunny_waf_access_list_rules",
        "bunny_waf_access_list",
        None,
        zone_level=True,
        account_level=False,
    ),
    Phase(
        "bunny_edge_rules",
        "bunny_edge_rule",
        None,
        zone_level=True,
        account_level=False,
    ),
]

BUNNY_PHASE_NAMES: frozenset[str] = frozenset(p.friendly_name for p in BUNNY_PHASES)
BUNNY_PHASE_IDS: frozenset[str] = frozenset(p.provider_id for p in BUNNY_PHASES)
