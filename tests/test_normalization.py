"""Normalization/denormalization round-trip tests.

These are critical for regression prevention — if normalize -> denormalize
doesn't produce a structurally equivalent result, rules will drift on sync.
"""

from octorules_bunny._phases import BUNNY_PHASES, _bn_prepare_rule
from octorules_bunny.provider import (
    _denormalize_access_list_config,
    _denormalize_access_list_create,
    _denormalize_access_list_update,
    _denormalize_custom_rule,
    _denormalize_rate_limit,
    _normalize_access_list,
    _normalize_condition,
    _normalize_custom_rule,
    _normalize_rate_limit,
)


class TestCustomRuleRoundTrip:
    def test_simple_rule(self):
        api_rule = {
            "id": 101,
            "shieldZoneId": 999,
            "ruleName": "Block SQLi",
            "ruleDescription": "Test",
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 17,
                "severityType": 2,
                "value": "",
                "variableTypes": {"13": ""},
                "transformationTypes": [8, 19],
                "chainedRuleConditions": [],
            },
        }
        normalized = _normalize_custom_rule(api_rule)
        assert normalized["ref"] == "Block SQLi"
        assert normalized["action"] == "block"
        assert normalized["severity"] == "error"
        assert normalized["_api_id"] == 101
        assert len(normalized["conditions"]) == 1
        assert normalized["conditions"][0]["operator"] == "detect_sqli"
        assert normalized["transformations"] == ["lowercase", "url_decode"]

        denormalized = _denormalize_custom_rule(normalized, 999)
        assert denormalized["ruleName"] == "Block SQLi"
        assert denormalized["shieldZoneId"] == 999
        config = denormalized["ruleConfiguration"]
        assert config["actionType"] == 1
        assert config["operatorType"] == 17
        assert config["severityType"] == 2

    def test_chained_conditions(self):
        api_rule = {
            "id": 102,
            "shieldZoneId": 999,
            "ruleName": "Complex rule",
            "ruleDescription": "",
            "ruleConfiguration": {
                "actionType": 3,
                "operatorType": 14,
                "severityType": 1,
                "value": "(curl|wget)",
                "variableTypes": {"18": "User-Agent"},
                "transformationTypes": [8],
                "chainedRuleConditions": [
                    {
                        "variableTypes": {"9": "COUNTRY_CODE"},
                        "operatorType": 15,
                        "value": "CN",
                    },
                    {
                        "variableTypes": {"0": ""},
                        "operatorType": 0,
                        "value": "/api/",
                    },
                ],
            },
        }
        normalized = _normalize_custom_rule(api_rule)
        assert len(normalized["conditions"]) == 3
        assert normalized["conditions"][0]["operator"] == "rx"
        assert normalized["conditions"][0]["value"] == "(curl|wget)"
        assert normalized["conditions"][1]["variable"] == "geo"
        assert normalized["conditions"][1]["variable_value"] == "COUNTRY_CODE"
        assert normalized["conditions"][2]["operator"] == "begins_with"

        denormalized = _denormalize_custom_rule(normalized, 999)
        config = denormalized["ruleConfiguration"]
        assert len(config.get("chainedRuleConditions", [])) == 2
        assert config["operatorType"] == 14  # Primary condition operator

    def test_no_transformations(self):
        api_rule = {
            "id": 103,
            "shieldZoneId": 999,
            "ruleName": "Simple",
            "ruleDescription": "",
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 2,
                "severityType": 0,
                "value": "/admin",
                "variableTypes": {"0": ""},
                "transformationTypes": [],
                "chainedRuleConditions": [],
            },
        }
        normalized = _normalize_custom_rule(api_rule)
        assert "transformations" not in normalized  # Empty list = omitted


class TestRateLimitRoundTrip:
    def test_full_rate_limit(self):
        """Rate limit fields live inside ruleConfiguration per the Bunny API spec."""
        api_rule = {
            "id": 201,
            "shieldZoneId": 999,
            "ruleName": "API rate limit",
            "ruleDescription": "",
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 0,
                "severityType": 0,
                "value": "/api/",
                "variableTypes": {"REQUEST_URI": ""},
                "transformationTypes": [],
                "chainedRuleConditions": [],
                "requestCount": 100,
                "timeframe": 60,
                "blockTime": 300,
                "counterKeyType": 0,
            },
        }
        normalized = _normalize_rate_limit(api_rule)
        assert normalized["request_count"] == 100
        assert normalized["timeframe"] == "1m"
        assert normalized["block_time"] == "5m"
        assert normalized["counter_key_type"] == "ip"
        assert normalized["conditions"][0]["variable"] == "request_uri"

        denormalized = _denormalize_rate_limit(normalized, 999)
        config = denormalized["ruleConfiguration"]
        assert config["requestCount"] == 100
        assert config["timeframe"] == 60
        assert config["blockTime"] == 300
        assert config["counterKeyType"] == 0
        assert "REQUEST_URI" in config["variableTypes"]


class TestAccessListRoundTrip:
    def test_country_list_from_list_endpoint(self):
        """AccessListDetails format (from the list endpoint)."""
        api_rule = {
            "listId": 301,
            "configurationId": 42,
            "name": "block bad country",
            "type": 3,
            "action": 2,
            "isEnabled": True,
            "content": "CN\nRU",
            "entryCount": 2,
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["ref"] == "block bad country"
        assert normalized["type"] == "country"
        assert normalized["action"] == "block"
        assert normalized["enabled"] is True
        assert normalized["content"] == "CN\nRU"
        assert normalized["_api_id"] == 301
        assert normalized["_config_id"] == 42

    def test_create_denormalize(self):
        normalized = {
            "ref": "block bad country",
            "type": "country",
            "action": "block",
            "enabled": True,
            "content": "CN\nRU",
        }
        create = _denormalize_access_list_create(normalized)
        assert create["name"] == "block bad country"
        assert create["type"] == 3
        assert create["content"] == "CN\nRU"
        assert "action" not in create
        assert "isEnabled" not in create

    def test_config_denormalize(self):
        normalized = {
            "ref": "block bad country",
            "type": "country",
            "action": "block",
            "enabled": True,
            "content": "CN\nRU",
        }
        config = _denormalize_access_list_config(normalized)
        assert config["isEnabled"] is True
        assert config["action"] == 2  # AccessListAction: 2=Block (different from WAF 1=Block)
        assert "content" not in config

    def test_update_denormalize(self):
        normalized = {
            "ref": "block bad country",
            "type": "country",
            "content": "CN\nRU\nKP",
        }
        update = _denormalize_access_list_update(normalized)
        assert update["name"] == "block bad country"
        assert update["content"] == "CN\nRU\nKP"
        assert "type" not in update

    def test_ip_list_from_api(self):
        """AccessListDetails format with new field names."""
        api_rule = {
            "listId": 302,
            "configurationId": 50,
            "name": "allowlist",
            "type": 0,
            "action": 1,  # AccessListAction: 1=Allow
            "isEnabled": False,
            "content": "10.0.0.1",
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["type"] == "ip"
        assert normalized["action"] == "allow"
        assert normalized["enabled"] is False
        assert normalized["_config_id"] == 50

    def test_unknown_enum_values_preserved(self):
        """Unknown enum ints should pass through as strings, not crash."""
        api_rule = {
            "listId": 999,
            "name": "unknown",
            "type": 99,
            "action": 99,
            "isEnabled": True,
            "content": "test",
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["type"] == "99"  # Unknown preserved as string
        assert normalized["action"] == "99"


class TestNullChainedRuleConditions:
    """Regression: API can return chainedRuleConditions: null (not [])."""

    def test_custom_rule_null_chained_conditions(self):
        api_rule = {
            "id": 110,
            "shieldZoneId": 999,
            "ruleName": "Null chained",
            "ruleDescription": "",
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 0,
                "severityType": 0,
                "value": "/admin",
                "variableTypes": {"0": ""},
                "transformationTypes": [],
                "chainedRuleConditions": None,
            },
        }
        normalized = _normalize_custom_rule(api_rule)
        assert normalized["ref"] == "Null chained"
        # Only the primary condition — no crash from iterating None
        assert len(normalized["conditions"]) == 1
        assert normalized["conditions"][0]["operator"] == "begins_with"

    def test_rate_limit_null_chained_conditions(self):
        """Rate limit rules also use chainedRuleConditions — test null there too."""
        from octorules_bunny.provider import _normalize_rate_limit

        api_rule = {
            "id": 210,
            "shieldZoneId": 999,
            "ruleName": "Rate null chained",
            "ruleDescription": "",
            "requestCount": 50,
            "timeframe": 60,
            "blockTime": 300,
            "counterKeyType": 0,
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 0,
                "severityType": 0,
                "value": "/api",
                "variableTypes": {"0": ""},
                "transformationTypes": [],
                "chainedRuleConditions": None,
            },
        }
        normalized = _normalize_rate_limit(api_rule)
        assert len(normalized["conditions"]) == 1


class TestVariableCaseNormalization:
    """Regression: API can return string variable keys in UPPER_CASE."""

    def test_uppercase_variable_lowered(self):
        """variableTypes key 'REQUEST_URI' normalizes to 'request_uri'."""
        cond = {
            "variableTypes": {"REQUEST_URI": ""},
            "operatorType": 0,
            "value": "/test",
        }
        normalized = _normalize_condition(cond)
        assert normalized["variable"] == "request_uri"

    def test_mixed_case_variable_lowered(self):
        """Mixed-case string keys are lowercased."""
        cond = {
            "variableTypes": {"Request_Headers": "Host"},
            "operatorType": 14,
            "value": "example.com",
        }
        normalized = _normalize_condition(cond)
        assert normalized["variable"] == "request_headers"
        assert normalized["variable_value"] == "Host"

    def test_numeric_key_still_resolved_via_mapping(self):
        """Numeric string keys ('0', '13', etc.) still resolve via int mapping."""
        cond = {
            "variableTypes": {"0": ""},
            "operatorType": 0,
            "value": "/admin",
        }
        normalized = _normalize_condition(cond)
        assert normalized["variable"] == "request_uri"


class TestSeverityPrepareRule:
    """Regression: severity int values in YAML must be normalized to strings."""

    def _get_waf_phase(self):
        """Get the bunny_waf_custom phase (has prepare_rule)."""
        for p in BUNNY_PHASES:
            if p.provider_id == "bunny_waf_custom":
                return p
        raise AssertionError("bunny_waf_custom phase not found")

    def test_severity_int_zero_to_info(self):
        phase = self._get_waf_phase()
        rule = {"ref": "test", "severity": 0}
        result = _bn_prepare_rule(rule, phase)
        assert result["severity"] == "info"
        assert result["ref"] == "test"

    def test_severity_int_one_to_warning(self):
        phase = self._get_waf_phase()
        rule = {"ref": "test", "severity": 1}
        result = _bn_prepare_rule(rule, phase)
        assert result["severity"] == "warning"

    def test_severity_int_two_to_error(self):
        phase = self._get_waf_phase()
        rule = {"ref": "test", "severity": 2}
        result = _bn_prepare_rule(rule, phase)
        assert result["severity"] == "error"

    def test_severity_string_passthrough(self):
        """String severity values pass through unchanged."""
        phase = self._get_waf_phase()
        rule = {"ref": "test", "severity": "info"}
        result = _bn_prepare_rule(rule, phase)
        assert result["severity"] == "info"

    def test_original_rule_not_mutated(self):
        """prepare_rule must return a copy, not mutate the input."""
        phase = self._get_waf_phase()
        rule = {"ref": "test", "severity": 0}
        result = _bn_prepare_rule(rule, phase)
        assert result["severity"] == "info"
        assert rule["severity"] == 0  # Original unchanged
