"""Tests for BN503 (unreachable rules after catch-all terminating rule)."""

from octorules.linter.engine import LintContext

from octorules_bunny.linter._plugin import bunny_lint


def _ctx(*, phase_filter=None, plan_tier=""):
    return LintContext(phase_filter=phase_filter, plan_tier=plan_tier)


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
