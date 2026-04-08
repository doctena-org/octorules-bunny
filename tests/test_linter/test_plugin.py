"""Tests for Bunny Shield linter plugin integration."""

from octorules.linter.engine import LintContext

from octorules_bunny.linter._plugin import BN_RULE_IDS, bunny_lint
from octorules_bunny.linter._rules import BN_RULE_METAS


def _ctx(*, phase_filter=None, plan_tier=""):
    ctx = LintContext(phase_filter=phase_filter, plan_tier=plan_tier)
    return ctx


class TestRuleRegistration:
    def test_all_rule_ids_start_with_bn(self):
        for meta in BN_RULE_METAS:
            assert meta.rule_id.startswith("BN"), f"{meta.rule_id} should start with BN"

    def test_rule_ids_are_unique(self):
        ids = [m.rule_id for m in BN_RULE_METAS]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {ids}"

    def test_minimum_rule_count(self):
        assert len(BN_RULE_METAS) >= 35

    def test_plugin_rule_ids_match_metas(self):
        meta_ids = frozenset(r.rule_id for r in BN_RULE_METAS)
        assert BN_RULE_IDS == meta_ids, (
            f"BN_RULE_IDS and BN_RULE_METAS are out of sync: "
            f"missing from metas: {BN_RULE_IDS - meta_ids}, "
            f"missing from plugin: {meta_ids - BN_RULE_IDS}"
        )


class TestBunnyLint:
    def test_valid_rules_no_validation_errors(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "Test rule",
                    "action": "block",
                    "severity": "info",
                    "description": "A test",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/bad"},
                    ],
                }
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        # BN501 (plan tier warning) is expected; no validation errors
        non_tier = [r for r in ctx.results if r.rule_id != "BN501"]
        assert len(non_tier) == 0

    def test_invalid_rule_produces_results(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {"action": "block", "conditions": [{"variable": "request_uri"}]},
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN001" in rule_ids

    def test_phase_filter(self):
        rules_data = {
            "bunny_waf_custom_rules": [{"action": "block"}],
            "bunny_waf_rate_limit_rules": [{"action": "block"}],
        }
        ctx = _ctx(phase_filter={"bunny_waf_rate_limit_rules"})
        bunny_lint(rules_data, ctx)
        phases = {r.phase for r in ctx.results}
        assert "bunny_waf_custom_rules" not in phases

    def test_non_bunny_phases_ignored(self):
        rules_data = {"http_request_firewall_custom": [{"ref": "cf-rule"}]}
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        assert len(ctx.results) == 0

    def test_non_list_phase_produces_bn007(self):
        rules_data = {"bunny_waf_custom_rules": "not a list"}
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN007" in rule_ids
        result = next(r for r in ctx.results if r.rule_id == "BN007")
        assert result.phase == "bunny_waf_custom_rules"
        assert "not a list" in result.message

    def test_non_list_phase_dict_produces_bn007(self):
        rules_data = {"bunny_waf_custom_rules": {"key": "value"}}
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN007" in rule_ids

    def test_non_list_phase_skipped_by_filter(self):
        rules_data = {"bunny_waf_custom_rules": "not a list"}
        ctx = _ctx(phase_filter={"bunny_waf_rate_limit_rules"})
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN007" not in rule_ids


class TestCrossPhaseChecks:
    def test_bn500_duplicate_conditions(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "Rule A",
                    "action": "block",
                    "severity": "info",
                    "description": "test",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/bad"},
                    ],
                },
                {
                    "ref": "Rule B",
                    "action": "log",
                    "severity": "info",
                    "description": "test",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/bad"},
                    ],
                },
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN500" in rule_ids

    def test_bn501_exceeds_free_limit(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": f"Rule {i}",
                    "action": "block",
                    "severity": "info",
                    "description": "test",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": f"/{i}"},
                    ],
                }
                for i in range(3)
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN501" in rule_ids

    def test_bn502_conflicting_access_lists(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": "1",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": "1.2.3.4",
                },
                {
                    "ref": "2",
                    "type": "ip",
                    "action": "allow",
                    "enabled": True,
                    "content": "1.2.3.4",
                },
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN502" in rule_ids

    def test_bn502_no_conflict_different_ips(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": "1",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": "1.2.3.4",
                },
                {
                    "ref": "2",
                    "type": "ip",
                    "action": "allow",
                    "enabled": True,
                    "content": "5.6.7.8",
                },
            ]
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "BN502" not in rule_ids
