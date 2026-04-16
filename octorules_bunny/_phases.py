"""Bunny Shield WAF phase definitions (shared between __init__ and provider)."""

from octorules.phases import Phase

from octorules_bunny._enums import SEVERITY


def _bn_prepare_rule(rule: dict, phase: Phase) -> dict:
    """Bunny-specific rule preparation.

    Called by the core planner's ``prepare_desired_rules()`` via the
    ``Phase.prepare_rule`` hook.  Normalizes the desired YAML to the
    same canonical form produced by ``_normalize_custom_rule``:

    - ``severity``: int → string (e.g. ``0`` → ``"info"``).
    """
    rule = rule.copy()
    sev = rule.get("severity")
    if isinstance(sev, int):
        resolved = SEVERITY.resolve(sev)
        if resolved != str(sev):
            rule["severity"] = resolved
    return rule


def _bn_prepare_access_list(rule: dict, phase: Phase) -> dict:
    """Strip trailing newlines from content to match API normalization."""
    rule = rule.copy()
    content = rule.get("content")
    if isinstance(content, str):
        rule["content"] = content.rstrip("\n")
    return rule


BUNNY_PHASES = [
    Phase(
        "bunny_waf_custom_rules",
        "bunny_waf_custom",
        None,
        zone_level=True,
        account_level=False,
        prepare_rule=_bn_prepare_rule,
    ),
    Phase(
        "bunny_waf_rate_limit_rules",
        "bunny_waf_rate_limit",
        None,
        zone_level=True,
        account_level=False,
        prepare_rule=_bn_prepare_rule,
    ),
    Phase(
        "bunny_waf_access_list_rules",
        "bunny_waf_access_list",
        None,
        zone_level=True,
        account_level=False,
        prepare_rule=_bn_prepare_access_list,
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
