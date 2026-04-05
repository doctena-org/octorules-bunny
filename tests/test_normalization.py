"""Normalization/denormalization round-trip tests.

These are critical for regression prevention — if normalize -> denormalize
doesn't produce a structurally equivalent result, rules will drift on sync.
"""

from octorules_bunny.provider import (
    _denormalize_access_list,
    _denormalize_custom_rule,
    _denormalize_rate_limit,
    _normalize_access_list,
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
        api_rule = {
            "id": 201,
            "shieldZoneId": 999,
            "ruleName": "API rate limit",
            "ruleDescription": "",
            "requestCount": 100,
            "timeframe": 60,
            "blockTime": 300,
            "counterKeyType": 0,
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 0,
                "severityType": 0,
                "value": "/api/",
                "variableTypes": {"0": ""},
                "transformationTypes": [],
                "chainedRuleConditions": [],
            },
        }
        normalized = _normalize_rate_limit(api_rule)
        assert normalized["request_count"] == 100
        assert normalized["timeframe"] == "1m"
        assert normalized["block_time"] == "5m"
        assert normalized["counter_key_type"] == "ip"

        denormalized = _denormalize_rate_limit(normalized, 999)
        assert denormalized["requestCount"] == 100
        assert denormalized["timeframe"] == 60
        assert denormalized["blockTime"] == 300
        assert denormalized["counterKeyType"] == 0


class TestAccessListRoundTrip:
    def test_country_list(self):
        api_rule = {
            "id": 301,
            "shieldZoneId": 999,
            "accessListType": 3,
            "actionType": 1,
            "enabled": True,
            "content": "CN\nRU",
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["ref"] == "301"
        assert normalized["type"] == "country"
        assert normalized["action"] == "block"
        assert normalized["enabled"] is True
        assert normalized["content"] == "CN\nRU"

        denormalized = _denormalize_access_list(normalized, 999)
        assert denormalized["accessListType"] == 3
        assert denormalized["actionType"] == 1
        assert denormalized["content"] == "CN\nRU"

    def test_ip_list(self):
        api_rule = {
            "id": 302,
            "shieldZoneId": 999,
            "accessListType": 0,
            "actionType": 4,
            "enabled": False,
            "content": "10.0.0.1",
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["type"] == "ip"
        assert normalized["action"] == "allow"
        assert normalized["enabled"] is False

    def test_unknown_enum_values_preserved(self):
        """Unknown enum ints should pass through as strings, not crash."""
        api_rule = {
            "id": 999,
            "shieldZoneId": 999,
            "accessListType": 99,
            "actionType": 99,
            "enabled": True,
            "content": "test",
        }
        normalized = _normalize_access_list(api_rule)
        assert normalized["type"] == "99"  # Unknown preserved as string
        assert normalized["action"] == "99"
