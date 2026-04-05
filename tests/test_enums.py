"""Tests for Bunny Shield enum maps."""

import pytest

from octorules_bunny._enums import (
    ACCESS_LIST_TYPE_TO_STR,
    ACTION_TO_STR,
    BLOCKTIME_TO_STR,
    COUNTER_KEY_TO_STR,
    EXECUTION_MODE_TO_STR,
    OPERATOR_TO_STR,
    SENSITIVITY_TO_STR,
    SEVERITY_TO_STR,
    STR_TO_ACCESS_LIST_TYPE,
    STR_TO_ACTION,
    STR_TO_BLOCKTIME,
    STR_TO_COUNTER_KEY,
    STR_TO_EXECUTION_MODE,
    STR_TO_OPERATOR,
    STR_TO_SENSITIVITY,
    STR_TO_SEVERITY,
    STR_TO_TIMEFRAME,
    STR_TO_TRANSFORMATION,
    STR_TO_VARIABLE,
    TIMEFRAME_TO_STR,
    TRANSFORMATION_TO_STR,
    VARIABLE_TO_STR,
    _resolve,
    _unresolve,
)

# All (forward, reverse) map pairs to test.
_ENUM_PAIRS = [
    (ACTION_TO_STR, STR_TO_ACTION, "action"),
    (OPERATOR_TO_STR, STR_TO_OPERATOR, "operator"),
    (VARIABLE_TO_STR, STR_TO_VARIABLE, "variable"),
    (TRANSFORMATION_TO_STR, STR_TO_TRANSFORMATION, "transformation"),
    (SEVERITY_TO_STR, STR_TO_SEVERITY, "severity"),
    (TIMEFRAME_TO_STR, STR_TO_TIMEFRAME, "timeframe"),
    (BLOCKTIME_TO_STR, STR_TO_BLOCKTIME, "blocktime"),
    (ACCESS_LIST_TYPE_TO_STR, STR_TO_ACCESS_LIST_TYPE, "access_list_type"),
    (COUNTER_KEY_TO_STR, STR_TO_COUNTER_KEY, "counter_key"),
    (EXECUTION_MODE_TO_STR, STR_TO_EXECUTION_MODE, "execution_mode"),
    (SENSITIVITY_TO_STR, STR_TO_SENSITIVITY, "sensitivity"),
]


def _enum_id(x):
    return x if isinstance(x, str) else ""


class TestEnumRoundTrip:
    @pytest.mark.parametrize("forward,reverse,name", _ENUM_PAIRS, ids=_enum_id)
    def test_round_trip(self, forward, reverse, name):
        """Every int key round-trips through forward then reverse."""
        for int_val, str_val in forward.items():
            got = reverse.get(str_val)
            assert got == int_val, f"{name}: {int_val} -> {str_val!r} -> {got}"

    @pytest.mark.parametrize("forward,reverse,name", _ENUM_PAIRS, ids=_enum_id)
    def test_same_length(self, forward, reverse, name):
        """Forward and reverse maps have the same number of entries."""
        assert len(forward) == len(reverse), f"{name}: mismatch"

    @pytest.mark.parametrize("forward,reverse,name", _ENUM_PAIRS, ids=_enum_id)
    def test_no_duplicate_values(self, forward, reverse, name):
        """No two int keys map to the same string (bijective)."""
        assert len(set(forward.values())) == len(forward), f"{name}: dupes"


class TestEnumCounts:
    def test_action_count(self):
        assert len(ACTION_TO_STR) == 5

    def test_operator_count(self):
        assert len(OPERATOR_TO_STR) == 15

    def test_variable_count(self):
        assert len(VARIABLE_TO_STR) == 26

    def test_transformation_count(self):
        assert len(TRANSFORMATION_TO_STR) == 21

    def test_access_list_type_count(self):
        assert len(ACCESS_LIST_TYPE_TO_STR) == 6


class TestOperatorGaps:
    """Operator enum has gaps at 10, 11, 13, 16."""

    def test_gap_values_not_in_map(self):
        for gap in (10, 11, 13, 16):
            assert gap not in OPERATOR_TO_STR


class TestResolveHelpers:
    def test_resolve_int(self):
        assert _resolve(ACTION_TO_STR, 1) == "block"

    def test_resolve_unknown_int(self):
        assert _resolve(ACTION_TO_STR, 99) == "99"

    def test_resolve_passthrough_str(self):
        assert _resolve(ACTION_TO_STR, "block") == "block"

    def test_unresolve_str(self):
        assert _unresolve(STR_TO_ACTION, "block") == 1

    def test_unresolve_unknown_str(self):
        assert _unresolve(STR_TO_ACTION, "unknown") == "unknown"

    def test_unresolve_passthrough_int(self):
        assert _unresolve(STR_TO_ACTION, 1) == 1
