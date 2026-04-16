"""Tests for tuple-based condition keys (replacing json.dumps for dedup)."""

from octorules_bunny.validate import _condition_key


class TestConditionKey:
    """_condition_key produces deterministic, hashable keys for conditions."""

    def test_basic_condition(self):
        cond = {"variable": "request_uri", "operator": "contains", "value": "/admin"}
        key = _condition_key(cond)
        assert isinstance(key, tuple)
        assert key == ("request_uri", "contains", "/admin", "")

    def test_with_variable_value(self):
        cond = {
            "variable": "request_headers",
            "operator": "contains",
            "value": "bot",
            "variable_value": "User-Agent",
        }
        key = _condition_key(cond)
        assert key == ("request_headers", "contains", "bot", "User-Agent")

    def test_missing_fields_use_empty_string(self):
        cond = {}
        key = _condition_key(cond)
        assert key == ("", "", "", "")

    def test_same_conditions_produce_same_key(self):
        c1 = {"variable": "geo", "operator": "eq", "value": "US", "variable_value": "COUNTRY_CODE"}
        c2 = {"variable": "geo", "operator": "eq", "value": "US", "variable_value": "COUNTRY_CODE"}
        assert _condition_key(c1) == _condition_key(c2)

    def test_different_conditions_produce_different_keys(self):
        c1 = {"variable": "geo", "operator": "eq", "value": "US"}
        c2 = {"variable": "geo", "operator": "eq", "value": "DE"}
        assert _condition_key(c1) != _condition_key(c2)

    def test_hashable(self):
        """Keys must be usable as dict keys / set members."""
        cond = {"variable": "request_uri", "operator": "rx", "value": ".*"}
        key = _condition_key(cond)
        d = {key: True}
        assert key in d

    def test_key_for_conditions_list(self):
        """A list of conditions should produce a hashable composite key."""
        conditions = [
            {"variable": "request_uri", "operator": "contains", "value": "/admin"},
            {"variable": "remote_addr", "operator": "eq", "value": "1.2.3.4"},
        ]
        composite = tuple(_condition_key(c) for c in conditions)
        assert isinstance(composite, tuple)
        assert len(composite) == 2
        # Must be hashable for use in dicts
        d = {composite: True}
        assert composite in d
