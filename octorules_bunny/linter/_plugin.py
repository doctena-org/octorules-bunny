"""Bunny Shield WAF lint plugin — orchestrates all Bunny-specific linter checks."""

import json
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME

from octorules_bunny._phases import BUNNY_PHASE_NAMES
from octorules_bunny.linter._rules import BN_RULE_METAS
from octorules_bunny.validate import validate_rules

BN_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in BN_RULE_METAS)

# Plan tier limits (custom WAF rules, rate limits).
_PLAN_LIMITS: dict[str, dict[str, int]] = {
    "free": {"bunny_waf_custom_rules": 0, "bunny_waf_rate_limit_rules": 2},
    "advanced": {"bunny_waf_custom_rules": 10, "bunny_waf_rate_limit_rules": 10},
}


def _check_duplicate_conditions(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """BN500: Detect duplicate conditions across rules in the same phase."""
    for phase_name, rules in rules_data.items():
        if phase_name not in BUNNY_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue
        # Skip access lists and edge rules — they don't have WAF-style conditions
        if phase_name.endswith("access_list_rules") or phase_name.endswith("edge_rules"):
            continue

        seen: dict[str, list[str]] = {}
        for rule in rules:
            conditions = rule.get("conditions", [])
            if not conditions:
                continue
            ref = str(rule.get("ref", ""))
            key = json.dumps(conditions, sort_keys=True)
            seen.setdefault(key, []).append(ref)

        for _, refs in seen.items():
            if len(refs) > 1:
                ctx.add(
                    LintResult(
                        rule_id="BN500",
                        severity=Severity.WARNING,
                        message=f"Duplicate conditions in rules: {', '.join(refs)}",
                        phase=phase_name,
                    )
                )


def _check_plan_tier_limits(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """BN501: Warn if rule count exceeds known plan tier limits.

    When ``ctx.plan_tier`` matches a known tier (e.g. "free", "advanced"),
    only check against that tier's limit.  When it is unknown or the
    default ("enterprise"), fall back to warning for the lowest tier
    exceeded — the previous behaviour.
    """
    tier = ctx.plan_tier.lower()

    for phase_name, rules in rules_data.items():
        if phase_name not in BUNNY_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        count = len(rules)

        if tier in _PLAN_LIMITS:
            # Known tier — check only that tier's limit.
            limit = _PLAN_LIMITS[tier].get(phase_name)
            if limit is not None and count > limit:
                ctx.add(
                    LintResult(
                        rule_id="BN501",
                        severity=Severity.WARNING,
                        message=(
                            f"{phase_name} has {count} rules, exceeding the"
                            f" {tier} plan limit of {limit}"
                        ),
                        phase=phase_name,
                    )
                )
        else:
            # Unknown/enterprise tier — warn for the lowest tier exceeded.
            for t, limits in _PLAN_LIMITS.items():
                limit = limits.get(phase_name)
                if limit is not None and count > limit:
                    ctx.add(
                        LintResult(
                            rule_id="BN501",
                            severity=Severity.WARNING,
                            message=(
                                f"{phase_name} has {count} rules, exceeding the"
                                f" {t} plan limit of {limit}"
                            ),
                            phase=phase_name,
                        )
                    )
                    break  # Only warn for the lowest tier exceeded


def _check_conflicting_access_lists(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """BN502: Detect access lists with overlapping entries and different actions."""
    phase_name = "bunny_waf_access_list_rules"
    if phase_name not in BUNNY_PHASE_NAMES:
        return
    if phase_name not in PHASE_BY_NAME:
        return
    if ctx.phase_filter and phase_name not in ctx.phase_filter:
        return
    rules = rules_data.get(phase_name)
    if not isinstance(rules, list) or len(rules) < 2:
        return

    # Group entries by (type_category, action) for overlap detection.
    # IP and CIDR share a category (an IP can overlap with a CIDR);
    # country, asn, and ja4 each get their own category so entries are
    # only compared within the same type.
    _TYPE_CATEGORY = {"ip": "ip_cidr", "cidr": "ip_cidr"}
    group_entries: dict[tuple[str, str], set[str]] = {}
    group_refs: dict[tuple[str, str], list[str]] = {}
    for rule in rules:
        list_type = rule.get("type", "")
        if list_type not in ("ip", "cidr", "country", "asn", "ja4"):
            continue
        type_cat = _TYPE_CATEGORY.get(list_type, list_type)
        action = rule.get("action", "")
        ref = str(rule.get("ref", ""))
        content = rule.get("content", "")
        if not isinstance(content, str):
            continue
        entries = {line.strip() for line in content.splitlines() if line.strip()}
        key = (type_cat, action)
        group_entries.setdefault(key, set()).update(entries)
        group_refs.setdefault(key, []).append(ref)

    # Check for overlapping entries across different actions within the
    # same type category.
    keys = list(group_entries.keys())
    for i, k1 in enumerate(keys):
        for k2 in keys[i + 1 :]:
            if k1[0] != k2[0]:  # different type category — skip
                continue
            overlap = group_entries[k1] & group_entries[k2]
            if overlap:
                samples = sorted(overlap)[:3]
                a1, a2 = k1[1], k2[1]
                ctx.add(
                    LintResult(
                        rule_id="BN502",
                        severity=Severity.WARNING,
                        message=(
                            f"Conflicting access lists: {a1} ({', '.join(group_refs[k1])})"
                            f" vs {a2} ({', '.join(group_refs[k2])})"
                            f" overlap on {samples}"
                        ),
                        phase=phase_name,
                    )
                )


def bunny_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Bunny Shield WAF lint checks on a zone rules file."""
    for phase_name, rules in rules_data.items():
        if phase_name not in BUNNY_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            ctx.add(
                LintResult(
                    rule_id="BN007",
                    severity=Severity.ERROR,
                    message=f"Phase '{phase_name}' value is not a list",
                    phase=phase_name,
                )
            )
            continue

        results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)

    # Cross-phase checks
    _check_duplicate_conditions(rules_data, ctx)
    _check_plan_tier_limits(rules_data, ctx)
    _check_conflicting_access_lists(rules_data, ctx)
