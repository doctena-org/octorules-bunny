"""Bunny Shield WAF lint plugin — orchestrates all Bunny-specific linter checks."""

from collections.abc import Iterator
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME

from octorules_bunny._phases import BUNNY_PHASE_NAMES
from octorules_bunny.validate import RULE_IDS as _validate_ids
from octorules_bunny.validate import _condition_key, validate_rules

# Rule IDs emitted by cross-phase checks in this module.
_PLUGIN_RULE_IDS: frozenset[str] = frozenset(
    {
        "BN007",
        "BN500",
        "BN501",
        "BN502",
        "BN503",
    }
)

BN_RULE_IDS: frozenset[str] = _validate_ids | _PLUGIN_RULE_IDS

# Plan tier limits (custom WAF rules, rate limits).
# Plan tier names and limits from the Bunny Shield dashboard (planType 0-3).
# Source: Shield WAF → Overview in the Bunny dashboard.
# Enterprise has no documented caps — omitted so the linter won't warn.
_PLAN_LIMITS: dict[str, dict[str, int]] = {
    "basic": {
        "bunny_waf_custom_rules": 0,
        "bunny_waf_rate_limit_rules": 2,
        "bunny_waf_access_list_rules": 1,
    },
    "advanced": {
        "bunny_waf_custom_rules": 10,
        "bunny_waf_rate_limit_rules": 10,
        "bunny_waf_access_list_rules": 5,
    },
    "business": {
        "bunny_waf_custom_rules": 25,
        "bunny_waf_rate_limit_rules": 25,
        "bunny_waf_access_list_rules": 10,
    },
}


# ---------------------------------------------------------------------------
# Phase iteration helper
# ---------------------------------------------------------------------------
def _iter_phases(
    rules_data: dict[str, Any],
    ctx: LintContext,
    *,
    skip_suffixes: tuple[str, ...] = (),
) -> Iterator[tuple[str, list]]:
    """Yield ``(phase_name, rules)`` for Bunny phases matching *ctx*.

    Filters out non-Bunny phases, unregistered phases, phases excluded by
    ``ctx.phase_filter``, non-list values, and phases ending with any of
    *skip_suffixes*.
    """
    for phase_name, rules in rules_data.items():
        if phase_name not in BUNNY_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue
        if skip_suffixes and any(phase_name.endswith(s) for s in skip_suffixes):
            continue
        yield phase_name, rules


# ---------------------------------------------------------------------------
# Cross-phase checks
# ---------------------------------------------------------------------------
_WAF_SKIP = ("access_list_rules", "edge_rules")


def _check_duplicate_conditions(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """BN500: Detect duplicate conditions across rules in the same phase."""
    for phase_name, rules in _iter_phases(rules_data, ctx, skip_suffixes=_WAF_SKIP):
        seen: dict[str, list[str]] = {}
        for rule in rules:
            conditions = rule.get("conditions", [])
            if not conditions:
                continue
            ref = str(rule.get("ref", ""))
            key = tuple(_condition_key(c) for c in conditions)
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

    When ``ctx.plan_tier`` matches a known tier (e.g. "basic", "advanced"),
    only check against that tier's limit.  When it is unknown or the
    default ("enterprise"), fall back to warning for the lowest tier
    exceeded — the previous behaviour.
    """
    tier = ctx.plan_tier.lower()

    for phase_name, rules in _iter_phases(rules_data, ctx):
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


# Terminating actions — block/challenge/allow/bypass stop rule evaluation.
# log does NOT terminate (it logs and continues to the next rule).
_TERMINATING_ACTIONS = frozenset({"block", "challenge", "allow", "bypass"})

# Operators used by detect_sqli/detect_xss — not relevant for catch-all.
_DETECT_OPERATORS = frozenset({"detect_sqli", "detect_xss"})


def _is_catch_all_condition(cond: dict) -> bool:
    """Return True if this single condition matches all traffic (BN108 patterns)."""
    op = cond.get("operator", "")
    if not isinstance(op, str) or op in _DETECT_OPERATORS:
        return False
    value = cond.get("value", "")
    if not isinstance(value, str):
        return False
    if op in ("contains", "contains_word", "within") and value == "":
        return True
    if op == "begins_with" and value == "/":
        return True
    if op == "rx" and value in (".*", "^.*$", ".+", ""):
        return True
    return False


def _check_unreachable_rules(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """BN503: Detect rules unreachable after a catch-all terminating rule.

    Bunny evaluates rules in list order. If a rule has a single catch-all
    condition (matches all traffic) and a terminating action, all subsequent
    enabled rules in that phase are unreachable.
    """
    for phase_name, rules in _iter_phases(rules_data, ctx, skip_suffixes=_WAF_SKIP):
        found_terminating = False
        terminating_ref = ""
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            ref = str(rule.get("ref", ""))
            enabled = rule.get("enabled", True)
            if not enabled:
                continue

            if found_terminating:
                ctx.add(
                    LintResult(
                        rule_id="BN503",
                        severity=Severity.WARNING,
                        message=(
                            f"Rule likely unreachable — preceded by catch-all"
                            f" terminating rule {terminating_ref!r}"
                        ),
                        phase=phase_name,
                        ref=ref,
                    )
                )
                continue

            action = rule.get("action", "")
            conditions = rule.get("conditions", [])
            if (
                isinstance(action, str)
                and action in _TERMINATING_ACTIONS
                and isinstance(conditions, list)
                and len(conditions) == 1
                and isinstance(conditions[0], dict)
                and _is_catch_all_condition(conditions[0])
            ):
                found_terminating = True
                terminating_ref = ref


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
    _check_unreachable_rules(rules_data, ctx)
