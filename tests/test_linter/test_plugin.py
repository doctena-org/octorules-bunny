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

    def test_bn501_respects_plan_tier_free(self):
        """When plan_tier='free', BN501 checks only the free limit."""
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
        ctx = _ctx(plan_tier="free")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 1
        assert "free" in bn501[0].message

    def test_bn501_respects_plan_tier_advanced_under_limit(self):
        """When plan_tier='advanced' and rule count is within limit, no BN501."""
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
        ctx = _ctx(plan_tier="advanced")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 0

    def test_bn501_respects_plan_tier_advanced_over_limit(self):
        """When plan_tier='advanced' and rule count exceeds limit, BN501 fires."""
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
                for i in range(11)
            ]
        }
        ctx = _ctx(plan_tier="advanced")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 1
        assert "advanced" in bn501[0].message

    def test_bn501_enterprise_tier_falls_back(self):
        """When plan_tier='enterprise' (unknown), fall back to lowest-tier-exceeded."""
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
        ctx = _ctx(plan_tier="enterprise")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        # 3 rules exceeds free limit of 0, so should warn
        assert len(bn501) == 1
        assert "free" in bn501[0].message

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


class TestBN503Unreachable:
    """BN503: Rule unreachable after catch-all terminating rule."""

    @staticmethod
    def _catch_all_rule(ref: str, action: str = "block"):
        return {
            "ref": ref,
            "action": action,
            "enabled": True,
            "conditions": [
                {"variable": "request_url", "operator": "contains", "value": ""},
            ],
        }

    @staticmethod
    def _normal_rule(ref: str):
        return {
            "ref": ref,
            "action": "block",
            "enabled": True,
            "conditions": [
                {"variable": "request_url", "operator": "contains", "value": "/admin"},
            ],
        }

    def test_bn503_unreachable_after_catch_all_block(self):
        ctx = _ctx()
        rules_data = {
            "bunny_waf_custom_rules": [
                self._catch_all_rule("catch-all"),
                self._normal_rule("after"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 1
        assert bn503[0].ref == "after"

    def test_bn503_no_flag_for_log_action(self):
        """Log doesn't terminate — subsequent rules should NOT be flagged."""
        ctx = _ctx()
        rules_data = {
            "bunny_waf_custom_rules": [
                self._catch_all_rule("logger", action="log"),
                self._normal_rule("after"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 0

    def test_bn503_no_flag_for_normal_rule(self):
        """A rule with a specific condition is not catch-all."""
        ctx = _ctx()
        rules_data = {
            "bunny_waf_custom_rules": [
                self._normal_rule("first"),
                self._normal_rule("second"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 0

    def test_bn503_disabled_catch_all_no_flag(self):
        """Disabled catch-all should not make subsequent rules unreachable."""
        ctx = _ctx()
        catch_all = self._catch_all_rule("disabled")
        catch_all["enabled"] = False
        rules_data = {
            "bunny_waf_custom_rules": [
                catch_all,
                self._normal_rule("after"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 0

    def test_bn503_multiple_unreachable(self):
        """Multiple rules after catch-all should all be flagged."""
        ctx = _ctx()
        rules_data = {
            "bunny_waf_custom_rules": [
                self._catch_all_rule("catch-all"),
                self._normal_rule("after1"),
                self._normal_rule("after2"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 2

    def test_bn503_multi_condition_not_catch_all(self):
        """A rule with 2 conditions (even if one is catch-all) is not catch-all."""
        ctx = _ctx()
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "multi",
                    "action": "block",
                    "enabled": True,
                    "conditions": [
                        {"variable": "request_url", "operator": "contains", "value": ""},
                        {"variable": "request_url", "operator": "contains", "value": "/admin"},
                    ],
                },
                self._normal_rule("after"),
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 0

    def test_bn503_skips_access_list_phase(self):
        """Access list phases don't have conditions — should be skipped."""
        ctx = _ctx()
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": "r1",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": "1.2.3.4",
                },
            ]
        }
        bunny_lint(rules_data, ctx)
        bn503 = [r for r in ctx.results if r.rule_id == "BN503"]
        assert len(bn503) == 0
