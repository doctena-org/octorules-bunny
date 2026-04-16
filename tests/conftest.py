"""Shared fixtures for octorules-bunny tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_bunny_client():
    """Create a mock BunnyShieldClient."""
    return MagicMock()


@pytest.fixture
def sample_pull_zones():
    """Sample pull zone list API response."""
    return [
        {"Id": 100, "Name": "my-cdn"},
        {"Id": 200, "Name": "staging-cdn"},
    ]


@pytest.fixture
def sample_shield_zone():
    """Sample Shield Zone API response."""
    return {
        "shieldZoneId": 999,
        "pullZoneId": 100,
    }


@pytest.fixture
def sample_custom_rules():
    """Sample custom WAF rules API response."""
    return [
        {
            "id": 101,
            "shieldZoneId": 999,
            "ruleName": "Block SQLi",
            "ruleDescription": "Detect SQL injection",
            "ruleConfiguration": {
                "actionType": 1,
                "operatorType": 17,
                "severityType": 2,
                "value": "",
                "variableTypes": {"13": ""},
                "transformationTypes": [8, 19],
                "chainedRuleConditions": [],
            },
        },
        {
            "id": 102,
            "shieldZoneId": 999,
            "ruleName": "Block bad bots",
            "ruleDescription": "",
            "ruleConfiguration": {
                "actionType": 3,
                "operatorType": 14,
                "severityType": 1,
                "value": "(curl|wget)",
                "variableTypes": {"18": "User-Agent"},
                "transformationTypes": [8],
                "chainedRuleConditions": [],
            },
        },
    ]


@pytest.fixture
def sample_rate_limits():
    """Sample rate limit rules API response."""
    return [
        {
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
        },
    ]


@pytest.fixture
def sample_access_lists():
    """Sample access lists API response (AccessListDetails format from list endpoint)."""
    return [
        {
            "listId": 301,
            "configurationId": 42,
            "name": "block countries",
            "type": 3,
            "action": 2,  # AccessListAction: 2=Block
            "isEnabled": True,
            "entryCount": 2,
        },
        {
            "listId": 302,
            "configurationId": 43,
            "name": "allow ips",
            "type": 0,
            "action": 1,  # AccessListAction: 1=Allow
            "isEnabled": True,
            "entryCount": 2,
        },
    ]


@pytest.fixture
def sample_edge_rules():
    """Sample edge rules as returned inside a pull zone response."""
    return [
        {
            "Guid": "aaa-bbb-111",
            "ActionType": 0,
            "ActionParameter1": "",
            "ActionParameter2": "",
            "Triggers": [
                {
                    "Type": 0,
                    "PatternMatchingType": 0,
                    "PatternMatches": ["http://*"],
                    "Parameter1": "",
                },
            ],
            "TriggerMatchingType": 0,
            "Description": "Force HTTPS",
            "Enabled": True,
        },
        {
            "Guid": "ccc-ddd-222",
            "ActionType": 4,
            "ActionParameter1": "",
            "ActionParameter2": "",
            "Triggers": [
                {
                    "Type": 4,
                    "PatternMatchingType": 0,
                    "PatternMatches": ["CN", "RU"],
                    "Parameter1": "",
                },
            ],
            "TriggerMatchingType": 0,
            "Description": "Block countries",
            "Enabled": True,
        },
    ]


@pytest.fixture
def sample_pull_zone_with_edge_rules(sample_edge_rules):
    """Sample pull zone response including EdgeRules."""
    return {
        "Id": 100,
        "Name": "my-cdn",
        "EdgeRules": sample_edge_rules,
    }
