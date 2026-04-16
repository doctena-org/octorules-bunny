"""Tests for Bunny Shield enum maps."""

import pytest

from octorules_bunny._enums import (
    ACCESS_LIST_ACTION,
    ACCESS_LIST_TYPE,
    ACTION,
    BLOCKTIME,
    COUNTER_KEY,
    EDGE_ACTION,
    EDGE_PATTERN_MATCH,
    EDGE_TRIGGER,
    EDGE_TRIGGER_MATCH,
    EXECUTION_MODE,
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
    (ACCESS_LIST_ACTION, "access_list_action", 5),
    (OPERATOR, "operator", 15),
    (VARIABLE, "variable", 26),
    (TRANSFORMATION, "transformation", 21),
    (SEVERITY, "severity", 3),
    (TIMEFRAME, "timeframe", 6),
    (BLOCKTIME, "blocktime", 6),
    (ACCESS_LIST_TYPE, "access_list_type", 6),
    (COUNTER_KEY, "counter_key", 8),
    (EXECUTION_MODE, "execution_mode", 3),
    (SENSITIVITY, "sensitivity", 4),
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
        """Every int key round-trips through resolve then unresolve."""
        for int_val, str_val in em.items():
            got = em.unresolve(str_val)
            assert got == int_val, f"{name}: {int_val} -> {str_val!r} -> {got}"

    @pytest.mark.parametrize("em,name,_count", _ALL_MAPS, ids=_map_id)
    def test_no_duplicate_values(self, em, name, _count):
        """Bijective: no two int keys map to the same string."""
        strs = [s for _, s in em.items()]
        assert len(set(strs)) == len(strs), f"{name}: dupes"


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
    """Backward-compat: resolve/unresolve methods match old _resolve/_unresolve."""

    def test_resolve_int(self):
        assert ACTION.resolve(1) == "block"

    def test_resolve_unknown_int(self):
        assert ACTION.resolve(99) == "99"

    def test_resolve_passthrough_str(self):
        assert ACTION.resolve("block") == "block"

    def test_unresolve_str(self):
        assert ACTION.unresolve("block") == 1

    def test_unresolve_unknown_str(self):
        assert ACTION.unresolve("unknown") == "unknown"

    def test_unresolve_passthrough_int(self):
        assert ACTION.unresolve(1) == 1


class TestEnumMapItems:
    """items() yields (int, str) pairs like dict.items()."""

    def test_items_returns_pairs(self):
        em = EnumMap({1: "a", 2: "b"})
        assert sorted(em.items()) == [(1, "a"), (2, "b")]

    def test_action_items_known(self):
        pairs = dict(ACTION.items())
        assert pairs[1] == "block"
        assert pairs[4] == "allow"
