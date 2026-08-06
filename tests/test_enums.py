"""Tests for Bunny Shield enum maps."""

import pytest

from octorules_bunny._enums import (
    ACCESS_LIST_ACTION,
    ACCESS_LIST_TYPE,
    ACTION,
    BLOCKTIME,
    BOT_EXECUTION_MODE,
    COUNTER_KEY,
    DDOS_EXECUTION_MODE,
    DDOS_SENSITIVITY,
    EDGE_ACTION,
    EDGE_PATTERN_MATCH,
    EDGE_TRIGGER,
    EDGE_TRIGGER_MATCH,
    OPERATOR,
    SENSITIVITY,
    SEVERITY,
    TIMEFRAME,
    TRANSFORMATION,
    VARIABLE,
    EnumMap,
)

# All EnumMap instances to test.
_ALL_MAPS = [
    (ACTION, "action", 5),
    (ACCESS_LIST_ACTION, "access_list_action", 6),
    (OPERATOR, "operator", 15),
    (VARIABLE, "variable", 26),
    (TRANSFORMATION, "transformation", 21),
    (SEVERITY, "severity", 3),
    (TIMEFRAME, "timeframe", 6),
    (BLOCKTIME, "blocktime", 6),
    (ACCESS_LIST_TYPE, "access_list_type", 6),
    (COUNTER_KEY, "counter_key", 8),
    (BOT_EXECUTION_MODE, "bot_execution_mode", 2),
    (DDOS_EXECUTION_MODE, "ddos_execution_mode", 2),
    (SENSITIVITY, "sensitivity", 4),
    (DDOS_SENSITIVITY, "ddos_sensitivity", 5),
    (EDGE_ACTION, "edge_action", 35),
    (EDGE_TRIGGER, "edge_trigger", 14),
    (EDGE_PATTERN_MATCH, "edge_pattern_match", 3),
    (EDGE_TRIGGER_MATCH, "edge_trigger_match", 3),
]


def _map_id(x):
    return x[1] if isinstance(x, tuple) else ""


# ---------------------------------------------------------------------------
# EnumMap class tests
# ---------------------------------------------------------------------------
class TestEnumMapClass:
    """Core EnumMap class behaviour."""

    def test_resolve_known_int(self):
        em = EnumMap({1: "block", 2: "log"})
        assert em.resolve(1) == "block"

    def test_resolve_unknown_int_returns_str(self):
        em = EnumMap({1: "block"})
        assert em.resolve(99) == "99"

    def test_resolve_passthrough_str(self):
        em = EnumMap({1: "block"})
        assert em.resolve("block") == "block"
        assert em.resolve("unknown") == "unknown"

    def test_unresolve_known_str(self):
        em = EnumMap({1: "block", 2: "log"})
        assert em.unresolve("block") == 1

    def test_unresolve_unknown_str_returns_str(self):
        em = EnumMap({1: "block"})
        assert em.unresolve("unknown") == "unknown"

    def test_unresolve_passthrough_int(self):
        em = EnumMap({1: "block"})
        assert em.unresolve(1) == 1

    def test_contains_str(self):
        em = EnumMap({1: "block", 2: "log"})
        assert "block" in em
        assert "log" in em
        assert "unknown" not in em

    def test_iter_yields_str_names(self):
        em = EnumMap({1: "block", 2: "log"})
        assert sorted(em) == ["block", "log"]

    def test_len(self):
        em = EnumMap({1: "a", 2: "b", 3: "c"})
        assert len(em) == 3

    def test_empty_map(self):
        em = EnumMap({})
        assert len(em) == 0
        assert em.resolve(1) == "1"
        assert em.unresolve("x") == "x"
        assert list(em) == []

    def test_repr(self):
        em = EnumMap({1: "block"})
        r = repr(em)
        assert "EnumMap" in r
        assert "block" in r


class TestApiContractMappings:
    """Pin maps whose exact int values are an API contract.

    These mirror the Shield OpenAPI schemas verbatim — a consistent-but-
    wrong mapping round-trips internally and only breaks in production,
    which is exactly how the pre-fix COUNTER_KEY shipped wrong values.
    """

    def test_counter_key_matches_waf_ratelimit_counter_key_type(self):
        # WafRatelimitCounterKeyType (api.bunny.net/shield/docs/v1/swagger.json)
        expected = {
            0: "ip",
            1: "host",
            2: "country",
            3: "city",
            4: "asn",
            5: "organization",
            6: "ja4",
            7: "ip_ja4",
        }
        for num, name in expected.items():
            assert COUNTER_KEY.resolve(num) == name
            assert COUNTER_KEY.unresolve(name) == num
        assert len(COUNTER_KEY) == len(expected)

    def test_ddos_sensitivity_matches_ddos_shield_sensitivity(self):
        # DDoSShieldSensitivity: 0=Off 1=Low 2=Medium 3=High 4=Challenge
        # (dashboard/docs name for 4 is "Extreme" / Always-On Mode).
        expected = {0: "off", 1: "low", 2: "medium", 3: "high", 4: "extreme"}
        for num, name in expected.items():
            assert DDOS_SENSITIVITY.resolve(num) == name
            assert DDOS_SENSITIVITY.unresolve(name) == num
        assert len(DDOS_SENSITIVITY) == len(expected)

    def test_sensitivity_matches_bot_detection_sensitivity(self):
        # BotDetectionSensitivity: 0=Off 1=Low 2=Medium 3=High (no level 4)
        expected = {0: "off", 1: "low", 2: "medium", 3: "high"}
        for num, name in expected.items():
            assert SENSITIVITY.resolve(num) == name
            assert SENSITIVITY.unresolve(name) == num
        assert len(SENSITIVITY) == len(expected)

    def test_bijective_requirement(self):
        """Duplicate string values should raise ValueError."""
        with pytest.raises(ValueError, match="duplicate"):
            EnumMap({1: "block", 2: "block"})


# ---------------------------------------------------------------------------
# Round-trip tests on all module-level EnumMap instances
# ---------------------------------------------------------------------------
class TestEnumRoundTrip:
    @pytest.mark.parametrize("em,name,_count", _ALL_MAPS, ids=_map_id)
    def test_round_trip(self, em, name, _count):
        """Every int key round-trips through resolve then unresolve.

        Round-trip implies bijection: if two ints A and B both mapped to
        the same string S, then ``unresolve(S)`` would return A (or B)
        deterministically, and the round-trip for the other value would
        fail. So a passing round-trip already proves no duplicate values.
        """
        for int_val, str_val in em.items():
            got = em.unresolve(str_val)
            assert got == int_val, f"{name}: {int_val} -> {str_val!r} -> {got}"


class TestEnumCounts:
    @pytest.mark.parametrize("em,name,expected", _ALL_MAPS, ids=_map_id)
    def test_count(self, em, name, expected):
        assert len(em) == expected, f"{name}: expected {expected}, got {len(em)}"


class TestOperatorGaps:
    """Operator enum has gaps at 10, 11, 13, 16."""

    def test_gap_values_not_in_map(self):
        for gap in (10, 11, 13, 16):
            assert OPERATOR.resolve(gap) == str(gap)


class TestResolveHelpers:
    """Sanity check that resolve/unresolve work on a real production EnumMap.

    The exhaustive resolve/unresolve semantics are covered against synthetic
    maps in :class:`TestEnumMapClass`; this single test guards against an
    accidentally-broken module-level instance.
    """

    def test_action_resolve_round_trip(self):
        assert ACTION.resolve(1) == "block"
        assert ACTION.unresolve("block") == 1


class TestEnumMapItems:
    """items() yields (int, str) pairs like dict.items()."""

    def test_items_returns_pairs(self):
        em = EnumMap({1: "a", 2: "b"})
        assert sorted(em.items()) == [(1, "a"), (2, "b")]

    def test_action_items_known(self):
        pairs = dict(ACTION.items())
        assert pairs[1] == "block"
        assert pairs[4] == "allow"
