"""Tests for phase filtering and basic lint orchestration."""

from octorules.linter.engine import LintContext

from octorules_bunny.linter._plugin import bunny_lint


def _ctx(*, phase_filter=None, plan_tier=""):
    return LintContext(phase_filter=phase_filter, plan_tier=plan_tier)


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
