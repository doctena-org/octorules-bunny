"""Tests for Bunny Shield rule validation."""

import pytest
from octorules.testing.lint import assert_lint, assert_no_lint

from octorules_bunny.validate import validate_rules

_C = "bunny_waf_custom_rules"
_R = "bunny_waf_rate_limit_rules"
_A = "bunny_waf_access_list_rules"


def _custom(**overrides):
    """Build a minimal valid custom WAF rule with overrides."""
    base = {
        "ref": "Test rule",
        "action": "block",
        "severity": "info",
        "description": "A test rule",
        "conditions": [
            {"variable": "request_uri", "operator": "contains", "value": "/bad"},
        ],
    }
    base.update(overrides)
    return base


def _rate_limit(**overrides):
    """Build a minimal valid rate limit rule with overrides."""
    base = {
        "ref": "Rate test",
        "action": "block",
        "severity": "info",
        "description": "A rate limit rule",
        "request_count": 100,
        "timeframe": "1m",
        "block_time": "5m",
        "counter_key_type": "ip",
        "conditions": [
            {"variable": "request_uri", "operator": "begins_with", "value": "/api/"},
        ],
    }
    base.update(overrides)
    return base


def _access_list(**overrides):
    """Build a minimal valid access list with overrides."""
    base = {
        "ref": "42",
        "type": "country",
        "action": "block",
        "enabled": True,
        "content": "CN\nRU",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
class TestValidRules:
    def test_custom_no_errors(self):
        results = validate_rules([_custom()], phase=_C)
        # Only BN601 (no description) if description is present, should be clean
        assert results == []

    def test_rate_limit_no_errors(self):
        assert validate_rules([_rate_limit()], phase=_R) == []

    def test_access_list_no_errors(self):
        assert validate_rules([_access_list()], phase=_A) == []

    def test_empty_list(self):
        assert validate_rules([]) == []


# ---------------------------------------------------------------------------
# BN001 — Missing ref
# ---------------------------------------------------------------------------
class TestMissingRef:
    def test_bn001_custom(self):
        r = _custom()
        del r["ref"]
        assert_lint(validate_rules([r], phase=_C), "BN001")

    def test_bn001_empty_ref(self):
        assert_lint(validate_rules([_custom(ref="")], phase=_C), "BN001")

    def test_bn001_access_list(self):
        r = _access_list()
        del r["ref"]
        assert_lint(validate_rules([r], phase=_A), "BN001")


# ---------------------------------------------------------------------------
# BN002 — Duplicate ref
# ---------------------------------------------------------------------------
class TestDuplicateRef:
    def test_bn002(self):
        rules = [_custom(ref="dup"), _custom(ref="dup")]
        assert_lint(validate_rules(rules, phase=_C), "BN002")

    def test_unique_ok(self):
        rules = [_custom(ref="a"), _custom(ref="b")]
        assert_no_lint(validate_rules(rules, phase=_C), "BN002")

    def test_bn002_fires_once_for_triple(self):
        rules = [_custom(ref="dup")] * 3
        bn002 = [r for r in validate_rules(rules, phase=_C) if r.rule_id == "BN002"]
        assert len(bn002) == 1


# ---------------------------------------------------------------------------
# BN004 — Unknown fields
# ---------------------------------------------------------------------------
class TestUnknownFields:
    def test_bn004_custom(self):
        r = _custom(unknown_field="x")
        assert_lint(validate_rules([r], phase=_C), "BN004")

    def test_bn004_access_list(self):
        r = _access_list(bogus="y")
        assert_lint(validate_rules([r], phase=_A), "BN004")

    def test_bn004_api_id_not_flagged(self):
        r = _custom(_api_id=123)
        assert_no_lint(validate_rules([r], phase=_C), "BN004")


# ---------------------------------------------------------------------------
# BN005 — Type mismatch
# ---------------------------------------------------------------------------
class TestTypeMismatch:
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("severity", 2),
            ("action", 1),
            ("conditions", "bad"),
        ],
    )
    def test_bn005_custom_field_wrong_type(self, field, bad_value):
        assert_lint(validate_rules([_custom(**{field: bad_value})], phase=_C), "BN005")

    def test_bn005_access_list_enabled_not_bool(self):
        # access_list has different fields than custom — kept separate
        # so the phase + builder are obvious from the test name.
        r = _access_list(enabled="yes")
        assert_lint(validate_rules([r], phase=_A), "BN005")


# ---------------------------------------------------------------------------
# BN010 — Invalid ref format
# ---------------------------------------------------------------------------
class TestRefFormat:
    def test_bn010_hyphen(self):
        assert_lint(validate_rules([_custom(ref="bad-ref")], phase=_C), "BN010")

    def test_bn010_underscore(self):
        assert_lint(validate_rules([_custom(ref="bad_ref")], phase=_C), "BN010")

    def test_bn010_valid_with_space(self):
        rules = [_custom(ref="My Rule 1")]
        assert_no_lint(validate_rules(rules, phase=_C), "BN010")

    def test_bn010_unicode(self):
        assert_lint(validate_rules([_custom(ref="Rul\u00e9")], phase=_C), "BN010")


# ---------------------------------------------------------------------------
# BN011 — Description too long
# ---------------------------------------------------------------------------
class TestDescription:
    def test_bn011_too_long(self):
        r = _custom(description="x" * 256)
        assert_lint(validate_rules([r], phase=_C), "BN011")

    def test_bn011_max_ok(self):
        r = _custom(description="x" * 255)
        assert_no_lint(validate_rules([r], phase=_C), "BN011")


# ---------------------------------------------------------------------------
# BN100 — Invalid action
# ---------------------------------------------------------------------------
class TestAction:
    def test_bn100_invalid(self):
        r = [_custom(action="explode")]
        assert_lint(validate_rules(r, phase=_C), "BN100")

    def test_bn003_missing(self):
        r = _custom()
        del r["action"]
        assert_lint(validate_rules([r], phase=_C), "BN003")

    def test_all_valid_actions(self):
        for a in ("block", "log", "challenge", "allow", "bypass"):
            assert_no_lint(validate_rules([_custom(action=a)], phase=_C), "BN100")


# ---------------------------------------------------------------------------
# BN101 — Invalid operator
# ---------------------------------------------------------------------------
class TestOperator:
    def test_bn101_unknown(self):
        r = _custom(conditions=[{"variable": "request_uri", "operator": "nope", "value": "x"}])
        assert_lint(validate_rules([r], phase=_C), "BN101")

    def test_all_valid_operators(self):
        for op in ("begins_with", "ends_with", "contains", "rx", "str_eq"):
            c = [{"variable": "request_uri", "operator": op, "value": "x"}]
            assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN101")


# ---------------------------------------------------------------------------
# BN102 — Unknown variable
# ---------------------------------------------------------------------------
class TestVariable:
    def test_bn102_unknown(self):
        c = [{"variable": "not_a_var", "operator": "contains", "value": "x"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN102")

    def test_all_known_variables(self):
        for var in ("request_uri", "remote_addr", "geo", "request_headers"):
            c = [{"variable": var, "operator": "contains", "value": "x"}]
            assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN102")


# ---------------------------------------------------------------------------
# BN103 — Unknown transformation
# ---------------------------------------------------------------------------
class TestTransformation:
    def test_bn103_unknown(self):
        r = _custom(transformations=["not_a_transform"])
        assert_lint(validate_rules([r], phase=_C), "BN103")

    def test_bn103_valid(self):
        r = _custom(transformations=["lowercase", "url_decode"])
        assert_no_lint(validate_rules([r], phase=_C), "BN103")


# ---------------------------------------------------------------------------
# BN104 — Invalid severity
# ---------------------------------------------------------------------------
class TestSeverity:
    def test_bn104_unknown(self):
        assert_lint(validate_rules([_custom(severity="fatal")], phase=_C), "BN104")

    def test_bn104_valid(self):
        for s in ("info", "warning", "error"):
            assert_no_lint(validate_rules([_custom(severity=s)], phase=_C), "BN104")


# ---------------------------------------------------------------------------
# BN105 — Invalid regex
# ---------------------------------------------------------------------------
class TestRegex:
    def test_bn105_invalid_pattern(self):
        c = [{"variable": "request_uri", "operator": "rx", "value": "[invalid"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN105")

    def test_bn105_valid_pattern(self):
        c = [{"variable": "request_uri", "operator": "rx", "value": "^/api/v[12]"}]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN105")


# ---------------------------------------------------------------------------
# BN106 — Operator requires value
# ---------------------------------------------------------------------------
class TestOperatorRequiresValue:
    def test_bn106_contains_without_value(self):
        c = [{"variable": "request_uri", "operator": "contains"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN106")

    def test_bn106_detect_sqli_without_value_ok(self):
        c = [{"variable": "request_body", "operator": "detect_sqli"}]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN106")


# ---------------------------------------------------------------------------
# BN107 — Numeric operator on non-numeric variable
# ---------------------------------------------------------------------------
class TestNumericOperator:
    def test_bn107_lt_on_request_uri(self):
        c = [{"variable": "request_uri", "operator": "lt", "value": "5"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN107")

    def test_bn107_lt_on_response_status_ok(self):
        c = [{"variable": "response_status", "operator": "lt", "value": "500"}]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN107")


# ---------------------------------------------------------------------------
# BN115-BN117 — Sub-value validation
# ---------------------------------------------------------------------------
class TestSubValues:
    def test_bn115_geo_without_subvalue(self):
        c = [{"variable": "geo", "operator": "str_eq", "value": "US"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN115")

    def test_bn116_invalid_geo_subvalue(self):
        c = [{"variable": "geo", "variable_value": "INVALID", "operator": "str_eq", "value": "US"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN116")

    def test_bn116_valid_geo_subvalue(self):
        c = [
            {
                "variable": "geo",
                "variable_value": "COUNTRY_CODE",
                "operator": "str_eq",
                "value": "US",
            }
        ]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN116")
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN115")

    def test_bn117_request_headers_without_subvalue(self):
        c = [{"variable": "request_headers", "operator": "contains", "value": "x"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN117")

    def test_bn117_request_headers_with_subvalue_ok(self):
        c = [
            {
                "variable": "request_headers",
                "variable_value": "User-Agent",
                "operator": "contains",
                "value": "bot",
            }
        ]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN117")

    def test_bn117_request_cookies_without_subvalue(self):
        c = [{"variable": "request_cookies", "operator": "contains", "value": "x"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN117")

    def test_bn103_subvalue_on_unsupported_variable(self):
        c = [
            {
                "variable": "request_uri",
                "variable_value": "something",
                "operator": "contains",
                "value": "x",
            }
        ]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN109")


# ---------------------------------------------------------------------------
# BN125 — Duplicate transformation
# ---------------------------------------------------------------------------
class TestDuplicateTransformation:
    def test_bn125(self):
        r = _custom(transformations=["lowercase", "lowercase"])
        assert_lint(validate_rules([r], phase=_C), "BN125")

    def test_bn125_different_ok(self):
        r = _custom(transformations=["lowercase", "url_decode"])
        assert_no_lint(validate_rules([r], phase=_C), "BN125")


# ---------------------------------------------------------------------------
# BN2xx — Rate limit specific
# ---------------------------------------------------------------------------
class TestRateLimit:
    def test_bn200_missing_request_count(self):
        r = _rate_limit()
        del r["request_count"]
        assert_lint(validate_rules([r], phase=_R), "BN200")

    def test_bn200_negative(self):
        assert_lint(validate_rules([_rate_limit(request_count=-1)], phase=_R), "BN200")

    def test_bn200_zero(self):
        assert_lint(validate_rules([_rate_limit(request_count=0)], phase=_R), "BN200")

    def test_bn200_boolean(self):
        assert_lint(validate_rules([_rate_limit(request_count=True)], phase=_R), "BN200")

    def test_bn201_invalid_timeframe(self):
        assert_lint(validate_rules([_rate_limit(timeframe="99s")], phase=_R), "BN201")

    def test_bn202_invalid_block_time(self):
        assert_lint(validate_rules([_rate_limit(block_time="99s")], phase=_R), "BN202")

    def test_bn203_invalid_counter_key(self):
        r = _rate_limit(counter_key_type="invalid")
        assert_lint(validate_rules([r], phase=_R), "BN203")

    def test_bn210_short_block_time(self):
        assert_lint(validate_rules([_rate_limit(block_time="30s")], phase=_R), "BN210")


# ---------------------------------------------------------------------------
# BN3xx — Access list specific
# ---------------------------------------------------------------------------
class TestAccessList:
    def test_bn300_invalid_type(self):
        assert_lint(validate_rules([_access_list(type="unknown")], phase=_A), "BN300")

    def test_bn300_missing_type(self):
        r = _access_list()
        del r["type"]
        assert_lint(validate_rules([r], phase=_A), "BN300")

    def test_bn301_empty_content(self):
        assert_lint(validate_rules([_access_list(content="")], phase=_A), "BN301")

    def test_bn301_whitespace_only(self):
        assert_lint(validate_rules([_access_list(content="  \n  ")], phase=_A), "BN301")

    def test_bn302_invalid_cidr(self):
        r = _access_list(type="cidr", content="not-a-cidr")
        assert_lint(validate_rules([r], phase=_A), "BN302")

    def test_bn302_valid_cidr(self):
        r = _access_list(type="cidr", content="10.0.0.0/8\n192.168.0.0/16")
        assert_no_lint(validate_rules([r], phase=_A), "BN302")

    def test_bn302_invalid_ip(self):
        r = _access_list(type="ip", content="not-an-ip")
        assert_lint(validate_rules([r], phase=_A), "BN302")

    def test_bn303_invalid_asn(self):
        r = _access_list(type="asn", content="not-asn")
        assert_lint(validate_rules([r], phase=_A), "BN303")

    def test_bn303_valid_asn(self):
        r = _access_list(type="asn", content="AS13335\n15169")
        assert_no_lint(validate_rules([r], phase=_A), "BN303")

    def test_bn304_invalid_country(self):
        assert_lint(validate_rules([_access_list(content="usa")], phase=_A), "BN304")

    def test_bn304_valid_country(self):
        assert_no_lint(validate_rules([_access_list(content="US\nDE")], phase=_A), "BN304")

    def test_bn304_lowercase_country(self):
        assert_lint(validate_rules([_access_list(content="us")], phase=_A), "BN304")

    def test_bn305_private_ip(self):
        r = _access_list(type="ip", content="192.168.1.1")
        assert_lint(validate_rules([r], phase=_A), "BN305")

    def test_bn305_private_cidr(self):
        r = _access_list(type="cidr", content="10.0.0.0/8")
        assert_lint(validate_rules([r], phase=_A), "BN305")

    def test_bn305_public_ip_ok(self):
        r = _access_list(type="ip", content="8.8.8.8")
        assert_no_lint(validate_rules([r], phase=_A), "BN305")

    def test_bn305_message_includes_range_description(self):
        """The BN305 finding identifies which reserved category was matched.

        Range coverage (CGNAT, RFC5737, link-local, benchmark, IPv6 doc, …)
        is tested in ``octorules.reserved_ips``. Here we only verify Bunny
        wires the rule emission correctly and surfaces the description.
        """
        r = _access_list(type="cidr", content="100.64.1.0/24")
        results = validate_rules([r], phase=_A)
        bn305 = assert_lint(results, "BN305")
        assert "CGNAT" in bn305[0].message

    def test_mixed_entries_partial_invalid(self):
        """Some entries valid, some invalid — each flagged individually."""
        r = _access_list(type="ip", content="8.8.8.8\nnot-valid\n1.1.1.1")
        results = validate_rules([r], phase=_A)
        bn302_count = sum(1 for res in results if res.rule_id == "BN302")
        assert bn302_count == 1

    def test_trailing_newlines_handled(self):
        r = _access_list(content="US\n\nDE\n")
        assert validate_rules([r], phase=_A) == []

    # --- BN311: catch-all CIDR -------------------------------------------
    def test_bn311_ipv4_catch_all(self):
        r = _access_list(type="cidr", content="0.0.0.0/0")
        assert_lint(validate_rules([r], phase=_A), "BN311")

    def test_bn311_ipv6_catch_all(self):
        r = _access_list(type="cidr", content="::/0")
        assert_lint(validate_rules([r], phase=_A), "BN311")

    def test_bn311_non_catch_all_not_flagged(self):
        r = _access_list(type="cidr", content="10.0.0.0/8\n8.8.8.0/24")
        assert_no_lint(validate_rules([r], phase=_A), "BN311")

    def test_bn311_catch_all_does_not_double_fire_bn307(self):
        # Regression for v0.3.2: 0.0.0.0/0 used to make BN307 (overlap)
        # fire against every other entry in the list.  After v0.3.2 the
        # catch-all is BN311's exclusive domain.
        r = _access_list(type="cidr", content="0.0.0.0/0\n10.0.0.0/8\n192.168.0.0/16")
        results = validate_rules([r], phase=_A)
        assert_lint(results, "BN311")
        bn307 = [x for x in results if x.rule_id == "BN307"]
        # 10.0.0.0/8 and 192.168.0.0/16 don't overlap each other → zero BN307.
        assert bn307 == [], [x.message for x in bn307]

    def test_bn307_sweep_line_fast_on_large_input(self):
        # Regression for v0.3.2: BN307 used to be O(n²) pairwise comparison.
        # Rewritten to sweep-line O(n log n) — 1,000 disjoint /32s should
        # lint in well under a second.  The original brute-force pass
        # multiplied out to ~500k comparisons at this size.
        import time

        content = "\n".join(f"203.0.{i // 256}.{i % 256}/32" for i in range(1000))
        r = _access_list(type="cidr", content=content)
        start = time.monotonic()
        results = validate_rules([r], phase=_A)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"BN307 sweep-line too slow: {elapsed:.2f}s for 1000 entries"
        # Disjoint /32s → zero overlap findings.
        assert [x for x in results if x.rule_id == "BN307"] == []

    def test_bn307_subnet_still_detected_after_sweep_line(self):
        r = _access_list(type="cidr", content="10.0.0.0/8\n10.1.0.0/16")
        results = validate_rules([r], phase=_A)
        bn307 = [x for x in results if x.rule_id == "BN307"]
        assert len(bn307) == 1
        assert "10.0.0.0/8" in bn307[0].message
        assert "10.1.0.0/16" in bn307[0].message


# ---------------------------------------------------------------------------
# BN4xx — Condition validation
# ---------------------------------------------------------------------------
class TestConditions:
    def test_bn400_missing_variable(self):
        c = [{"operator": "contains", "value": "x"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN400")

    def test_bn401_missing_operator(self):
        c = [{"variable": "request_uri", "value": "x"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN401")

    def test_bn402_detect_sqli_with_value(self):
        c = [{"variable": "request_body", "operator": "detect_sqli", "value": "test"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN402")

    def test_bn402_detect_xss_with_value(self):
        c = [{"variable": "request_body", "operator": "detect_xss", "value": "test"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN402")

    def test_bn402_detect_sqli_no_value_ok(self):
        c = [{"variable": "request_body", "operator": "detect_sqli"}]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN402")

    def test_bn403_duplicate_condition(self):
        c = [
            {"variable": "request_uri", "operator": "contains", "value": "/bad"},
            {"variable": "request_uri", "operator": "contains", "value": "/bad"},
        ]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN403")

    def test_bn403_different_conditions_ok(self):
        c = [
            {"variable": "request_uri", "operator": "contains", "value": "/bad"},
            {"variable": "remote_addr", "operator": "str_eq", "value": "1.2.3.4"},
        ]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN403")

    def test_bn404_too_many_conditions(self):
        c = [
            {"variable": "request_uri", "operator": "contains", "value": f"/{i}"} for i in range(11)
        ]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN404")

    def test_bn404_ten_conditions_ok(self):
        c = [
            {"variable": "request_uri", "operator": "contains", "value": f"/{i}"} for i in range(10)
        ]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN404")


# ---------------------------------------------------------------------------
# BN600/BN601 — Best practice
# ---------------------------------------------------------------------------
class TestBestPractice:
    def test_bn600_very_short_name(self):
        assert_lint(validate_rules([_custom(ref="X")], phase=_C), "BN600")

    def test_bn600_ok_length(self):
        assert_no_lint(validate_rules([_custom(ref="Block bots")], phase=_C), "BN600")

    def test_bn601_no_description(self):
        r = _custom()
        del r["description"]
        assert_lint(validate_rules([r], phase=_C), "BN601")

    def test_bn601_with_description_ok(self):
        assert_no_lint(validate_rules([_custom()], phase=_C), "BN601")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_none_action(self):
        """None values should not crash validation."""
        r = _custom(action=None)
        validate_rules([r], phase=_C)  # Should not raise

    def test_empty_conditions_list(self):
        r = _custom(conditions=[])
        assert_lint(validate_rules([r], phase=_C), "BN003")

    def test_rule_with_only_ref(self):
        """Minimal invalid rule — should produce errors, not crash."""
        results = validate_rules([{"ref": "Bare rule"}], phase=_C)
        assert len(results) > 0

    def test_access_list_content_integer(self):
        """Content as non-string shouldn't crash."""
        r = _access_list(content=12345)
        validate_rules([r], phase=_A)  # Should not raise


# ---------------------------------------------------------------------------
# BN108 — Catch-all condition
# ---------------------------------------------------------------------------
class TestCatchAll:
    def test_bn108_contains_empty(self):
        c = [{"variable": "request_uri", "operator": "contains", "value": ""}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN108")

    def test_bn108_begins_with_slash(self):
        c = [{"variable": "request_uri", "operator": "begins_with", "value": "/"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN108")

    def test_bn108_rx_dot_star(self):
        c = [{"variable": "request_uri", "operator": "rx", "value": ".*"}]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN108")

    def test_bn108_specific_value_ok(self):
        c = [{"variable": "request_uri", "operator": "contains", "value": "/admin"}]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN108")


# ---------------------------------------------------------------------------
# BN109 — Sub-value on unsupported variable
# ---------------------------------------------------------------------------
class TestSubValueMisuse:
    def test_bn109_subvalue_on_request_uri(self):
        c = [
            {
                "variable": "request_uri",
                "variable_value": "something",
                "operator": "contains",
                "value": "x",
            }
        ]
        assert_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN109")

    def test_bn109_subvalue_on_geo_ok(self):
        c = [
            {
                "variable": "geo",
                "variable_value": "COUNTRY_CODE",
                "operator": "str_eq",
                "value": "US",
            }
        ]
        assert_no_lint(validate_rules([_custom(conditions=c)], phase=_C), "BN109")


# ---------------------------------------------------------------------------
# BN306 — CIDR host bits set
# ---------------------------------------------------------------------------
class TestCIDRHostBits:
    @pytest.mark.parametrize(
        "cidr,should_fire",
        [
            ("10.0.0.1/24", True),  # IPv4 with host bits
            ("10.0.0.0/24", False),  # IPv4 clean
            ("2001:db8::1/32", True),  # IPv6 with host bits
            ("2001:db8::/32", False),  # IPv6 clean
        ],
    )
    def test_bn306_host_bits(self, cidr, should_fire):
        r = _access_list(type="cidr", content=cidr)
        results = validate_rules([r], phase=_A)
        if should_fire:
            assert_lint(results, "BN306")
        else:
            assert_no_lint(results, "BN306")

    def test_ipv6_cidr_valid(self):
        r = _access_list(type="cidr", content="2001:db8::/32\nfc00::/7")
        results = validate_rules([r], phase=_A)
        assert_no_lint(results, "BN301")  # not invalid
        assert_lint(results, "BN305")  # fc00::/7 is private


# ---------------------------------------------------------------------------
# BN307 — Overlapping CIDRs
# ---------------------------------------------------------------------------
class TestOverlappingCIDRs:
    def test_bn307_overlap(self):
        r = _access_list(type="cidr", content="10.0.0.0/8\n10.1.0.0/16")
        assert_lint(validate_rules([r], phase=_A), "BN307")

    def test_bn307_no_overlap(self):
        r = _access_list(type="cidr", content="10.0.0.0/8\n172.16.0.0/12")
        assert_no_lint(validate_rules([r], phase=_A), "BN307")


# ---------------------------------------------------------------------------
# BN309 — Duplicate IP in access list
# ---------------------------------------------------------------------------
class TestDuplicateIP:
    def test_bn309_duplicate_ip(self):
        r = _access_list(type="ip", content="8.8.8.8\n1.1.1.1\n8.8.8.8")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_no_duplicates(self):
        r = _access_list(type="ip", content="8.8.8.8\n1.1.1.1\n9.9.9.9")
        assert_no_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_single_entry(self):
        r = _access_list(type="ip", content="8.8.8.8")
        assert_no_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_fires_once_per_duplicate(self):
        """Triple duplicate fires once (on second occurrence)."""
        r = _access_list(type="ip", content="8.8.8.8\n8.8.8.8\n8.8.8.8")
        bn309 = [res for res in validate_rules([r], phase=_A) if res.rule_id == "BN309"]
        assert len(bn309) == 2  # second and third occurrence

    def test_bn309_ipv6_duplicate(self):
        r = _access_list(type="ip", content="2001:db8::1\n2001:db8::1")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_ipv6_case_insensitive(self):
        """Mixed-case IPv6 addresses are detected as duplicates (M3 regression)."""
        r = _access_list(type="ip", content="2001:DB8::1\n2001:db8::1")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_cidr_exact_duplicate(self):
        """BN309 also fires for exact duplicate CIDRs in cidr-type lists."""
        r = _access_list(type="cidr", content="10.0.0.0/24\n10.0.0.0/24")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_cidr_normalised_duplicate(self):
        """10.0.0.1/24 and 10.0.0.0/24 normalise to the same network."""
        r = _access_list(type="cidr", content="10.0.0.1/24\n10.0.0.0/24")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_cidr_no_false_positive_on_different_nets(self):
        r = _access_list(type="cidr", content="10.0.0.0/24\n10.0.1.0/24")
        assert_no_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_cidr_ipv6_duplicate(self):
        r = _access_list(type="cidr", content="2001:db8::/32\n2001:db8::/32")
        assert_lint(validate_rules([r], phase=_A), "BN309")

    def test_bn309_message_contains_ip(self):
        r = _access_list(type="ip", content="8.8.8.8\n8.8.8.8")
        results = [res for res in validate_rules([r], phase=_A) if res.rule_id == "BN309"]
        assert len(results) == 1
        assert "8.8.8.8" in results[0].message


# ---------------------------------------------------------------------------
# BN310 — Duplicate organization in access list
# ---------------------------------------------------------------------------
class TestDuplicateOrganization:
    def test_bn310_duplicate_organization(self):
        r = _access_list(type="organization", content="Org1\nOrg2\nOrg1")
        assert_lint(validate_rules([r], phase=_A), "BN310")

    def test_bn310_no_duplicates(self):
        r = _access_list(type="organization", content="Org1\nOrg2\nOrg3")
        assert_no_lint(validate_rules([r], phase=_A), "BN310")

    def test_bn310_case_insensitive(self):
        """Organization duplicates are detected case-insensitively."""
        r = _access_list(type="organization", content="Org1\nORG1")
        assert_lint(validate_rules([r], phase=_A), "BN310")


# ---------------------------------------------------------------------------
# BN602 — Disabled access list
# ---------------------------------------------------------------------------
class TestDisabledAccessList:
    def test_bn602_disabled(self):
        r = _access_list(enabled=False)
        assert_lint(validate_rules([r], phase=_A), "BN602")

    def test_bn602_enabled_ok(self):
        r = _access_list(enabled=True)
        assert_no_lint(validate_rules([r], phase=_A), "BN602")


# ---------------------------------------------------------------------------
# BN308 — JA4 fingerprint validation
# ---------------------------------------------------------------------------
class TestJA4Fingerprint:
    def test_bn308_valid_chrome(self):
        r = _access_list(type="ja4", content="t13d1516h2_8daaf6152771_e5627efa2ab1")
        assert_no_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_valid_quic(self):
        r = _access_list(type="ja4", content="q13d0312h3_55b375c5d22e_06cda9e17597")
        assert_no_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_valid_zero_hashes(self):
        r = _access_list(type="ja4", content="t13d1310h2_000000000000_000000000000")
        assert_no_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_too_short(self):
        r = _access_list(type="ja4", content="t13d1516h2_short")
        assert_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_missing_underscores(self):
        r = _access_list(type="ja4", content="t13d1516h28daaf6152771e5627efa2ab1")
        assert_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_invalid_protocol(self):
        r = _access_list(type="ja4", content="x13d1516h2_8daaf6152771_e5627efa2ab1")
        assert_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_invalid_tls_version(self):
        r = _access_list(type="ja4", content="t99d1516h2_8daaf6152771_e5627efa2ab1")
        assert_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_uppercase_hash_rejected(self):
        r = _access_list(type="ja4", content="t13d1516h2_8DAAF6152771_E5627EFA2AB1")
        assert_lint(validate_rules([r], phase=_A), "BN308")

    def test_bn308_multiple_entries(self):
        """Multiple fingerprints — one valid, one invalid."""
        content = "t13d1516h2_8daaf6152771_e5627efa2ab1\nbogus"
        r = _access_list(type="ja4", content=content)
        results = validate_rules([r], phase=_A)
        bn308_count = sum(1 for res in results if res.rule_id == "BN308")
        assert bn308_count == 1

    def test_bn308_dtls_protocol(self):
        r = _access_list(type="ja4", content="d12d1516h2_8daaf6152771_e5627efa2ab1")
        assert_no_lint(validate_rules([r], phase=_A), "BN308")


# ---------------------------------------------------------------------------
# BN006: Rule entry is not a dict
# ---------------------------------------------------------------------------
class TestRuleEntryNotDict:
    def test_string_entry(self):
        """Non-dict rule entry produces BN006 error."""
        results = validate_rules(["not a dict"], phase=_C)
        assert_lint(results, "BN006")

    def test_int_entry(self):
        results = validate_rules([42], phase=_C)
        assert_lint(results, "BN006")

    def test_list_entry(self):
        results = validate_rules([[1, 2, 3]], phase=_C)
        assert_lint(results, "BN006")

    def test_mixed_valid_and_invalid(self):
        """Valid dict rules still validated alongside non-dict entries."""
        r = _custom()
        results = validate_rules(["bad", r], phase=_C)
        assert_lint(results, "BN006")
        bn006_count = sum(1 for res in results if res.rule_id == "BN006")
        assert bn006_count == 1
