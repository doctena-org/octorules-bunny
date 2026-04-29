"""Tests for additional lint rules: BN009, BN119, BN713, BN715."""

from octorules.linter.engine import LintContext
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_bunny.linter._plugin import bunny_lint
from octorules_bunny.validate import validate_rules


def _ctx(*, phase_filter=None, plan_tier=""):
    return LintContext(phase_filter=phase_filter, plan_tier=plan_tier)


# ---------------------------------------------------------------------------
# BN009 — Duplicate ref across different phases
# ---------------------------------------------------------------------------
class TestBN009CrossPhaseDupRef:
    def test_same_ref_in_custom_and_rate_limit(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "API protection",
                    "action": "log",
                    "severity": "info",
                    "description": "x",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/api"}
                    ],
                },
            ],
            "bunny_waf_rate_limit_rules": [
                {
                    "ref": "API protection",
                    "action": "block",
                    "severity": "warning",
                    "description": "x",
                    "conditions": [
                        {"variable": "request_uri", "operator": "begins_with", "value": "/api"}
                    ],
                    "request_count": 100,
                    "timeframe": "1m",
                    "block_time": "5m",
                    "counter_key_type": "ip",
                },
            ],
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        assert_lint(ctx, "BN009")

    def test_unique_refs_across_phases_ok(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "block sqli",
                    "action": "block",
                    "severity": "error",
                    "description": "x",
                    "conditions": [{"variable": "request_body", "operator": "detect_sqli"}],
                },
            ],
            "bunny_waf_rate_limit_rules": [
                {
                    "ref": "api throttle",
                    "action": "block",
                    "severity": "warning",
                    "description": "x",
                    "conditions": [
                        {"variable": "request_uri", "operator": "begins_with", "value": "/api"}
                    ],
                    "request_count": 100,
                    "timeframe": "1m",
                    "block_time": "5m",
                    "counter_key_type": "ip",
                },
            ],
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        assert_no_lint(ctx, "BN009")

    def test_within_phase_dup_still_bn002(self):
        """Same ref within a phase triggers BN002, not BN009."""
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "same",
                    "action": "log",
                    "severity": "info",
                    "description": "x",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/a"}
                    ],
                },
                {
                    "ref": "same",
                    "action": "log",
                    "severity": "info",
                    "description": "x",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/b"}
                    ],
                },
            ],
        }
        ctx = _ctx()
        bunny_lint(rules_data, ctx)
        assert_lint(ctx, "BN002")


# ---------------------------------------------------------------------------
# BN119 — Regex with leading .* (performance footgun)
# ---------------------------------------------------------------------------
class TestBN119RegexLeadingWildcard:
    def test_dotstar_prefix_warns(self):
        rule = {
            "ref": "test",
            "action": "block",
            "severity": "error",
            "description": "x",
            "conditions": [
                {"variable": "request_uri", "operator": "rx", "value": ".*/admin"},
            ],
        }
        results = validate_rules([rule], phase="bunny_waf_custom_rules")
        assert_lint(results, "BN119")

    def test_dotplus_prefix_warns(self):
        rule = {
            "ref": "test",
            "action": "block",
            "severity": "error",
            "description": "x",
            "conditions": [
                {"variable": "request_uri", "operator": "rx", "value": ".+admin"},
            ],
        }
        results = validate_rules([rule], phase="bunny_waf_custom_rules")
        assert_lint(results, "BN119")

    def test_anchored_dotstar_ok(self):
        """^.* is a valid catch-all pattern (handled by BN108), not a perf issue."""
        rule = {
            "ref": "test",
            "action": "block",
            "severity": "error",
            "description": "x",
            "conditions": [
                {"variable": "request_uri", "operator": "rx", "value": "^admin"},
            ],
        }
        results = validate_rules([rule], phase="bunny_waf_custom_rules")
        assert_no_lint(results, "BN119")

    def test_no_leading_wildcard_ok(self):
        rule = {
            "ref": "test",
            "action": "block",
            "severity": "error",
            "description": "x",
            "conditions": [
                {"variable": "request_uri", "operator": "rx", "value": "/admin/[0-9]+"},
            ],
        }
        results = validate_rules([rule], phase="bunny_waf_custom_rules")
        assert_no_lint(results, "BN119")

    def test_non_rx_operator_not_checked(self):
        rule = {
            "ref": "test",
            "action": "block",
            "severity": "error",
            "description": "x",
            "conditions": [
                {"variable": "request_uri", "operator": "contains", "value": ".*admin"},
            ],
        }
        results = validate_rules([rule], phase="bunny_waf_custom_rules")
        assert_no_lint(results, "BN119")


# ---------------------------------------------------------------------------
# BN713 — Edge rule URL trigger pattern must start with / or http or *
# ---------------------------------------------------------------------------
def _edge_rule(
    patterns,
    trigger_type="url",
    action_type="block_request",
    action_parameter_1="",
    action_parameter_2="",
):
    return {
        "ref": "test",
        "enabled": True,
        "description": "test",
        "action_type": action_type,
        "action_parameter_1": action_parameter_1,
        "action_parameter_2": action_parameter_2,
        "trigger_matching_type": "all",
        "triggers": [
            {
                "type": trigger_type,
                "pattern_matching_type": "any",
                "pattern_matches": patterns,
            }
        ],
    }


class TestBN713UrlPatternFormat:
    def test_pattern_without_slash_or_http_rejected(self):
        rule = _edge_rule(["admin"])
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_lint(results, "BN713")

    def test_slash_prefix_ok(self):
        rule = _edge_rule(["/admin", "/api/*"])
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN713")

    def test_http_prefix_ok(self):
        rule = _edge_rule(["http://*", "https://example.com/*"])
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN713")

    def test_wildcard_prefix_ok(self):
        rule = _edge_rule(["*"])
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN713")

    def test_lua_pattern_bypasses_check(self):
        rule = _edge_rule(["pattern:^admin$"])
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN713")

    def test_non_url_trigger_not_checked(self):
        rule = _edge_rule(["US"], trigger_type="country_code")
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN713")


# ---------------------------------------------------------------------------
# BN715 — Redirect action_parameter_2 (status code) must be 300-399
# ---------------------------------------------------------------------------
class TestBN715RedirectStatusCode:
    def test_status_200_rejected(self):
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="200",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_lint(results, "BN715")

    def test_status_404_rejected(self):
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="404",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_lint(results, "BN715")

    def test_status_301_ok(self):
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="301",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN715")

    def test_status_302_ok(self):
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="302",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN715")

    def test_non_numeric_rejected(self):
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="redirect-me",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_lint(results, "BN715")

    def test_non_redirect_action_not_checked(self):
        """Other actions can use action_parameter_2 for anything."""
        rule = _edge_rule(
            ["/api"],
            action_type="set_response_header",
            action_parameter_1="X-Cache",
            action_parameter_2="HIT",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_no_lint(results, "BN715")

    def test_empty_param2_handled_by_bn706(self):
        """Missing param2 is BN706, not BN715."""
        rule = _edge_rule(
            ["/old"],
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="",
        )
        results = validate_rules([rule], phase="bunny_edge_rules")
        assert_lint(results, "BN706")
        assert_no_lint(results, "BN715")
