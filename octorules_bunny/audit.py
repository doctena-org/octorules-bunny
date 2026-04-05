"""Bunny Shield audit extension — extracts IP ranges from access lists and WAF rules."""

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_bunny._phases import BUNNY_PHASE_NAMES


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP ranges from Bunny Shield rules in *phase_name*."""
    if phase_name not in BUNNY_PHASE_NAMES:
        return []
    if phase_name not in PHASE_BY_NAME:
        return []

    rules = rules_data.get(phase_name)
    if not isinstance(rules, list):
        return []

    results: list[RuleIPInfo] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))

        # Access lists: extract from content field (IP and CIDR types only)
        if phase_name == "bunny_waf_access_list_rules":
            list_type = rule.get("type", "")
            if list_type in ("ip", "cidr"):
                content = rule.get("content", "")
                if isinstance(content, str):
                    ip_ranges = [line.strip() for line in content.splitlines() if line.strip()]
                    if ip_ranges:
                        results.append(
                            RuleIPInfo(
                                zone_name="",
                                phase_name=phase_name,
                                ref=ref,
                                action=action,
                                ip_ranges=ip_ranges,
                            )
                        )

        # Custom WAF / Rate limit: extract from conditions targeting REMOTE_ADDR
        elif phase_name in (
            "bunny_waf_custom_rules",
            "bunny_waf_rate_limit_rules",
        ):
            for cond in rule.get("conditions", []):
                if not isinstance(cond, dict):
                    continue
                var = cond.get("variable", "")
                if var == "remote_addr":
                    value = cond.get("value", "")
                    if value:
                        results.append(
                            RuleIPInfo(
                                zone_name="",
                                phase_name=phase_name,
                                ref=ref,
                                action=action,
                                ip_ranges=[value],
                            )
                        )

    return results


def register_bunny_audit() -> None:
    """Register the Bunny Shield audit IP extractor."""
    register_audit_extension("bunny_shield", _extract_ips)
