"""Tests for edge rule pattern content validation (BN707-BN712)."""

from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_bunny.validate import validate_rules

_PHASE = "bunny_edge_rules"


def _rule(trigger_type, patterns, **overrides):
    base = {
        "ref": "test",
        "enabled": True,
        "description": "test",
        "action_type": "block_request",
        "action_parameter_1": "",
        "action_parameter_2": "",
        "trigger_matching_type": "all",
        "triggers": [
            {
                "type": trigger_type,
                "pattern_matching_type": "any",
                "pattern_matches": patterns,
            }
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# BN707 — empty/whitespace pattern in list
# ---------------------------------------------------------------------------
class TestBN707EmptyPattern:
    def test_empty_string_rejected(self):
        rule = _rule("url", ["http://*", ""])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN707")

    def test_whitespace_only_rejected(self):
        rule = _rule("url", ["   "])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN707")

    def test_tab_only_rejected(self):
        rule = _rule("url", ["\t\n"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN707")

    def test_valid_pattern_ok(self):
        rule = _rule("url", ["http://*"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN707")


# ---------------------------------------------------------------------------
# BN708 — invalid country code
# ---------------------------------------------------------------------------
class TestBN708InvalidCountryCode:
    def test_three_letters_rejected(self):
        rule = _rule("country_code", ["USA"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN708")

    def test_lowercase_rejected(self):
        rule = _rule("country_code", ["us"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN708")

    def test_numeric_rejected(self):
        rule = _rule("country_code", ["42"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN708")

    def test_valid_two_letter_ok(self):
        rule = _rule("country_code", ["US", "GB", "DE"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN708")

    def test_only_country_code_trigger_checked(self):
        """BN708 must not fire on url triggers with 2-letter strings."""
        rule = _rule("url", ["/admin"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN708")


# ---------------------------------------------------------------------------
# BN709 — invalid IP/CIDR in remote_ip trigger
# ---------------------------------------------------------------------------
class TestBN709InvalidIp:
    def test_invalid_ip_rejected(self):
        rule = _rule("remote_ip", ["not-an-ip"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN709")

    def test_valid_ipv4_ok(self):
        rule = _rule("remote_ip", ["192.168.1.1"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN709")

    def test_valid_cidr_ok(self):
        rule = _rule("remote_ip", ["10.0.0.0/8", "192.168.0.0/16"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN709")

    def test_valid_ipv6_ok(self):
        rule = _rule("remote_ip", ["2001:db8::1", "fe80::/10"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN709")

    def test_only_remote_ip_trigger_checked(self):
        """BN709 must not fire on url triggers."""
        rule = _rule("url", ["not-an-ip"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN709")


# ---------------------------------------------------------------------------
# BN710 — invalid HTTP method
# ---------------------------------------------------------------------------
class TestBN710InvalidMethod:
    def test_unknown_method_rejected(self):
        rule = _rule("request_method", ["YEET"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN710")

    def test_lowercase_rejected(self):
        rule = _rule("request_method", ["get"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN710")

    def test_all_standard_methods_ok(self):
        rule = _rule(
            "request_method",
            ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"],
        )
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN710")

    def test_only_request_method_trigger_checked(self):
        rule = _rule("url", ["YEET"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN710")


# ---------------------------------------------------------------------------
# BN711 — status code out of range (100-900)
# ---------------------------------------------------------------------------
class TestBN711StatusCodeRange:
    def test_below_100_rejected(self):
        rule = _rule("status_code", ["99"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN711")

    def test_above_900_rejected(self):
        rule = _rule("status_code", ["999"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN711")

    def test_non_numeric_rejected(self):
        rule = _rule("status_code", ["forbidden"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN711")

    def test_valid_codes_ok(self):
        rule = _rule("status_code", ["200", "404", "503", "100", "900"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN711")

    def test_only_status_code_trigger_checked(self):
        rule = _rule("url", ["999"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN711")


# ---------------------------------------------------------------------------
# BN712 — malformed Lua pattern (pattern: prefix)
# ---------------------------------------------------------------------------
class TestBN712LuaPattern:
    def test_unclosed_bracket_rejected(self):
        rule = _rule("url", ["pattern:[bad"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN712")

    def test_unclosed_negated_bracket_rejected(self):
        rule = _rule("url", ["pattern:[^abc"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN712")

    def test_trailing_escape_rejected(self):
        rule = _rule("url", ["pattern:foo%"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN712")

    def test_valid_lua_ok(self):
        rule = _rule(
            "url",
            [
                "pattern:^https://.*$",
                "pattern:%a+%d+",
                "pattern:[abc]+",
                "pattern:[^/]*",
                "pattern:^.*/video_chunk%-[^%-]+%-[^%-]+%.dash$",
            ],
        )
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN712")

    def test_glob_without_prefix_not_checked(self):
        """Patterns without 'pattern:' prefix are globs, not Lua — skip Lua validation."""
        rule = _rule("url", ["[bad", "http://*"])
        results = validate_rules([rule], phase=_PHASE)
        assert_no_lint(results, "BN712")

    def test_empty_lua_pattern_rejected(self):
        """pattern: with no body is invalid."""
        rule = _rule("url", ["pattern:"])
        results = validate_rules([rule], phase=_PHASE)
        assert_lint(results, "BN712")
