"""Tests for cross-phase checks (BN500, BN501, BN502)."""

from octorules.linter.engine import LintContext

from octorules_bunny.linter._plugin import bunny_lint


def _ctx(*, phase_filter=None, plan_tier=""):
    return LintContext(phase_filter=phase_filter, plan_tier=plan_tier)


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

    def test_bn501_respects_plan_tier_basic(self):
        """When plan_tier='basic', BN501 checks only the basic limit."""
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
        ctx = _ctx(plan_tier="basic")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 1
        assert "basic" in bn501[0].message

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
        assert "basic" in bn501[0].message

    def test_bn501_access_list_count_basic(self):
        """Basic tier: 1 access list allowed, 2 should trigger BN501."""
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": f"list-{i}",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": f"1.2.3.{i}",
                }
                for i in range(2)
            ]
        }
        ctx = _ctx(plan_tier="basic")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 1
        assert "access_list" in bn501[0].phase

    def test_bn501_access_list_count_advanced_under(self):
        """Advanced tier: 5 access lists allowed, 3 should not trigger."""
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": f"list-{i}",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": f"1.2.3.{i}",
                }
                for i in range(3)
            ]
        }
        ctx = _ctx(plan_tier="advanced")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 0

    def test_bn501_access_list_count_advanced_over(self):
        """Advanced tier: 5 access lists allowed, 6 should trigger."""
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": f"list-{i}",
                    "type": "ip",
                    "action": "block",
                    "enabled": True,
                    "content": f"1.2.3.{i}",
                }
                for i in range(6)
            ]
        }
        ctx = _ctx(plan_tier="advanced")
        bunny_lint(rules_data, ctx)
        bn501 = [r for r in ctx.results if r.rule_id == "BN501"]
        assert len(bn501) == 1

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
