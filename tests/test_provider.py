"""Tests for the Bunny Shield WAF provider."""

import unittest.mock

import pytest
from octorules.config import ConfigError
from octorules.provider.base import BaseProvider, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderConnectionError, ProviderError

from octorules_bunny._client import BunnyAPIError, BunnyAuthError
from octorules_bunny.provider import BunnyShieldProvider


def _zs(zone_id: str = "999", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


class TestBaseProviderProtocol:
    def test_satisfies_protocol(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="test")
        assert isinstance(provider, BaseProvider)


class TestProperties:
    def test_max_workers(self, mock_bunny_client):
        provider = BunnyShieldProvider(max_workers=4, client=mock_bunny_client, api_key="k")
        assert provider.max_workers == 4

    def test_account_id_is_none(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.account_id is None

    def test_account_name_is_none(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.account_name is None

    def test_zone_plans_empty_without_plan_kwarg(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.zone_plans == {}

    @pytest.mark.parametrize(
        "plan_type,expected_tier",
        [(0, "basic"), (1, "advanced"), (2, "business"), (3, "enterprise")],
    )
    def test_zone_plans_auto_detected_from_api(
        self, mock_bunny_client, sample_pull_zones, plan_type, expected_tier
    ):
        """planType in the Shield Zone response auto-sets the zone tier."""
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = {
            "shieldZoneId": 999,
            "pullZoneId": 100,
            "planType": plan_type,
        }
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider.resolve_zone_id("my-cdn")
        assert provider.zone_plans == {"my-cdn": expected_tier}

    def test_zone_plans_api_tier_overrides_kwarg(self, mock_bunny_client, sample_pull_zones):
        """API-detected tier takes precedence over the plan kwarg."""
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = {
            "shieldZoneId": 999,
            "pullZoneId": 100,
            "planType": 1,
        }
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", plan="basic")
        provider.resolve_zone_id("my-cdn")
        assert provider.zone_plans == {"my-cdn": "advanced"}

    def test_zone_plans_kwarg_fallback_when_no_plantype(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        """plan kwarg is used when the API response has no planType."""
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", plan="advanced")
        provider.resolve_zone_id("my-cdn")
        assert provider.zone_plans == {"my-cdn": "advanced"}

    def test_zone_plans_plan_kwarg_lowercased(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", plan="Advanced")
        provider.resolve_zone_id("my-cdn")
        assert provider.zone_plans == {"my-cdn": "advanced"}

    def test_zone_plans_defensive_copy(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", plan="basic")
        provider.resolve_zone_id("my-cdn")
        copy = provider.zone_plans
        copy["injected"] = "bad"
        assert "injected" not in provider.zone_plans


class TestInit:
    def test_missing_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("BUNNY_API_KEY", raising=False)
        with pytest.raises(ConfigError, match="Bunny API key not specified"):
            BunnyShieldProvider()

    def test_env_var_fallback(self, monkeypatch):
        monkeypatch.setenv("BUNNY_API_KEY", "from-env")
        with unittest.mock.patch("octorules_bunny.provider.BunnyShieldClient") as mock_cls:
            mock_cls.return_value = unittest.mock.MagicMock()
            provider = BunnyShieldProvider()
            mock_cls.assert_called_once_with("from-env", timeout=30.0, max_retries=2)
            assert provider is not None


class TestResolveZoneId:
    def test_found(self, mock_bunny_client, sample_pull_zones, sample_shield_zone):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        result = provider.resolve_zone_id("my-cdn")
        assert result == "999"

    def test_not_found(self, mock_bunny_client):
        mock_bunny_client.list_pull_zones.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(Exception, match="No pull zone found"):
            provider.resolve_zone_id("missing")

    def test_multiple_matches(self, mock_bunny_client):
        mock_bunny_client.list_pull_zones.return_value = [
            {"Id": 1, "Name": "dup"},
            {"Id": 2, "Name": "dup"},
        ]
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(Exception, match="Multiple pull zones found"):
            provider.resolve_zone_id("dup")

    def test_shield_not_enabled(self, mock_bunny_client, sample_pull_zones):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = {}
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(Exception, match="Shield Zone not found"):
            provider.resolve_zone_id("my-cdn")

    def test_data_envelope_unwrapping(self, mock_bunny_client, sample_pull_zones):
        """Shield API wraps response in {"data": {...}} — resolve_zone_id unwraps it."""
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = {
            "data": {"shieldZoneId": 12345, "pullZoneId": 100},
            "error": None,
        }
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        result = provider.resolve_zone_id("my-cdn")
        assert result == "12345"

    def test_pull_zones_cached(self, mock_bunny_client, sample_pull_zones, sample_shield_zone):
        """list_pull_zones is called once and cached across resolve_zone_id calls."""
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider.resolve_zone_id("my-cdn")
        provider.resolve_zone_id("staging-cdn")
        assert mock_bunny_client.list_pull_zones.call_count == 1


class TestListZones:
    def test_returns_names(self, mock_bunny_client, sample_pull_zones):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.list_zones() == ["my-cdn", "staging-cdn"]


class TestGetPhaseRules:
    def test_custom_rules(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        rules = provider.get_phase_rules(_zs(), "bunny_waf_custom")
        assert len(rules) == 2
        assert rules[0]["ref"] == "Block SQLi"
        assert rules[0]["action"] == "block"
        assert rules[0]["_api_id"] == 101
        assert len(rules[0]["conditions"]) == 1
        assert rules[0]["conditions"][0]["operator"] == "detect_sqli"

    def test_rate_limit_rules(self, mock_bunny_client, sample_rate_limits):
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        rules = provider.get_phase_rules(_zs(), "bunny_waf_rate_limit")
        assert len(rules) == 1
        assert rules[0]["ref"] == "API rate limit"
        assert rules[0]["request_count"] == 100
        assert rules[0]["timeframe"] == "1m"
        assert rules[0]["block_time"] == "5m"
        assert rules[0]["counter_key_type"] == "ip"

    def test_access_list_rules(self, mock_bunny_client, sample_access_lists):
        mock_bunny_client.list_access_lists.return_value = sample_access_lists
        # Individual fetch returns content (list endpoint doesn't include it)
        mock_bunny_client.get_access_list.side_effect = [
            {
                "data": {"id": 301, "name": "block countries", "type": 3, "content": "CN\nRU"},
            },
            {
                "data": {
                    "id": 302,
                    "name": "allow ips",
                    "type": 0,
                    "content": "10.0.0.1\n192.168.1.1",
                },
            },
        ]
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        rules = provider.get_phase_rules(_zs(), "bunny_waf_access_list")
        assert len(rules) == 2
        assert rules[0]["ref"] == "block countries"
        assert rules[0]["type"] == "country"
        assert rules[0]["action"] == "block"
        assert rules[0]["content"] == "CN\nRU"
        assert rules[0]["_config_id"] == 42

    def test_unknown_phase_returns_empty(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.get_phase_rules(_zs(), "unknown_phase") == []


class TestPutPhaseRules:
    def _setup(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        return BunnyShieldProvider(client=mock_bunny_client, api_key="k")

    def test_add_new_rule(self, mock_bunny_client, sample_custom_rules):
        # Start with existing rules
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        new_rules = [
            {
                "ref": "Block SQLi",
                "action": "block",
                "severity": "error",
                "conditions": [{"variable": "request_body", "operator": "detect_sqli"}],
            },
            {
                "ref": "Block bad bots",
                "action": "challenge",
                "severity": "warning",
                "conditions": [
                    {
                        "variable": "request_headers",
                        "variable_value": "User-Agent",
                        "operator": "rx",
                        "value": "(curl|wget)",
                    }
                ],
            },
            {
                "ref": "New rule",
                "action": "block",
                "severity": "info",
                "conditions": [
                    {"variable": "request_uri", "operator": "contains", "value": "/admin"}
                ],
            },
        ]
        count = provider.put_phase_rules(_zs(), "bunny_waf_custom", new_rules)
        assert count == 3
        # Existing rules patched, new rule created
        assert mock_bunny_client.update_custom_waf_rule.call_count == 2
        assert mock_bunny_client.create_custom_waf_rule.call_count == 1

    def test_remove_rule(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        # Keep only the first rule
        new_rules = [
            {
                "ref": "Block SQLi",
                "action": "block",
                "severity": "error",
                "conditions": [{"variable": "request_body", "operator": "detect_sqli"}],
            },
        ]
        count = provider.put_phase_rules(_zs(), "bunny_waf_custom", new_rules)
        assert count == 1
        assert mock_bunny_client.delete_custom_waf_rule.call_count == 1
        mock_bunny_client.delete_custom_waf_rule.assert_called_with(102)

    def test_empty_rules_removes_all(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        count = provider.put_phase_rules(_zs(), "bunny_waf_custom", [])
        assert count == 0
        assert mock_bunny_client.delete_custom_waf_rule.call_count == 2


class TestPutRateLimitRules:
    def test_add_rate_limit(self, mock_bunny_client, sample_rate_limits):
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        new_rules = [
            {
                "ref": "API rate limit",
                "action": "block",
                "request_count": 200,
                "timeframe": "5m",
                "block_time": "15m",
                "counter_key_type": "ip",
                "conditions": [
                    {"variable": "request_uri", "operator": "begins_with", "value": "/api/"}
                ],
            },
            {
                "ref": "New rate limit",
                "action": "block",
                "request_count": 50,
                "timeframe": "1m",
                "block_time": "5m",
                "counter_key_type": "ip",
                "conditions": [
                    {"variable": "request_uri", "operator": "begins_with", "value": "/login"}
                ],
            },
        ]
        count = provider.put_phase_rules(_zs(), "bunny_waf_rate_limit", new_rules)
        assert count == 2
        assert mock_bunny_client.update_rate_limit.call_count == 1
        assert mock_bunny_client.create_rate_limit.call_count == 1

    def test_remove_rate_limit(self, mock_bunny_client, sample_rate_limits):
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider.put_phase_rules(_zs(), "bunny_waf_rate_limit", [])
        assert mock_bunny_client.delete_rate_limit.call_count == 1
        mock_bunny_client.delete_rate_limit.assert_called_with(201)


class TestPutAccessListRules:
    def _mock_get_access_list(self, mock_bunny_client):
        """Mock individual access list fetches (get_phase_rules fetches each)."""
        mock_bunny_client.get_access_list.side_effect = [
            {
                "data": {
                    "id": 301,
                    "name": "block countries",
                    "type": 3,
                    "content": "CN\nRU",
                },
            },
            {
                "data": {
                    "id": 302,
                    "name": "allow ips",
                    "type": 0,
                    "content": "10.0.0.1\n192.168.1.1",
                },
            },
        ]

    def test_add_access_list(self, mock_bunny_client, sample_access_lists):
        self._mock_get_access_list(mock_bunny_client)
        # create_access_list returns response with the new list id
        mock_bunny_client.create_access_list.return_value = {
            "data": {"id": 400, "name": "new list", "type": 2},
        }
        # After create, _create_rule re-fetches summaries to find configurationId
        new_summary = {
            "listId": 400,
            "configurationId": 99,
            "name": "new list",
            "type": 2,
            "action": 1,
            "isEnabled": True,
            "entryCount": 0,
        }
        mock_bunny_client.list_access_lists.side_effect = [
            sample_access_lists,  # first call: from get_phase_rules
            [*sample_access_lists, new_summary],  # second: from _create_rule
        ]
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        # Refs must match the name field from sample_access_lists
        new_rules = [
            {
                "ref": "block countries",
                "type": "country",
                "action": "block",
                "enabled": True,
                "content": "CN",
            },
            {
                "ref": "allow ips",
                "type": "ip",
                "action": "allow",
                "enabled": True,
                "content": "1.2.3.4",
            },
            {
                "ref": "new list",
                "type": "asn",
                "action": "block",
                "enabled": True,
                "content": "AS1234",
            },
        ]
        count = provider.put_phase_rules(
            _zs(),
            "bunny_waf_access_list",
            new_rules,
        )
        assert count == 3
        # Two existing lists updated (content + config for each)
        assert mock_bunny_client.update_access_list.call_count == 2
        # 2 update configs + 1 create config
        assert mock_bunny_client.update_access_list_config.call_count == 3
        assert mock_bunny_client.create_access_list.call_count == 1

    def test_remove_access_list(self, mock_bunny_client, sample_access_lists):
        mock_bunny_client.list_access_lists.return_value = sample_access_lists
        self._mock_get_access_list(mock_bunny_client)
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider.put_phase_rules(_zs(), "bunny_waf_access_list", [])
        assert mock_bunny_client.delete_access_list.call_count == 2


class TestPutPartialFailure:
    def test_partial_failure_logs_and_raises(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        # Make create fail after patch succeeds
        mock_bunny_client.create_custom_waf_rule.side_effect = Exception("API error")
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        new_rules = [
            {
                "ref": "Block SQLi",
                "action": "block",
                "severity": "error",
                "conditions": [{"variable": "request_body", "operator": "detect_sqli"}],
            },
            {
                "ref": "New rule",
                "action": "block",
                "severity": "info",
                "conditions": [
                    {"variable": "request_uri", "operator": "contains", "value": "/test"}
                ],
            },
        ]
        with pytest.raises(Exception, match="API error"):
            provider.put_phase_rules(_zs(), "bunny_waf_custom", new_rules)
        # Patch of existing "Block SQLi" should have succeeded
        assert mock_bunny_client.update_custom_waf_rule.call_count == 1


class TestPutIdempotent:
    def test_put_same_rules_twice(self, mock_bunny_client, sample_custom_rules):
        """Second put with same rules should only patch, not create/delete."""
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        # Normalize current rules and put them back unchanged
        current = provider.get_phase_rules(_zs(), "bunny_waf_custom")
        provider.put_phase_rules(_zs(), "bunny_waf_custom", current)
        # All rules existed already, so only patches (no creates, no deletes)
        assert mock_bunny_client.update_custom_waf_rule.call_count == 2
        assert mock_bunny_client.create_custom_waf_rule.call_count == 0
        assert mock_bunny_client.delete_custom_waf_rule.call_count == 0


class TestGetAllPhaseRules:
    def test_fetches_all_phases(
        self, mock_bunny_client, sample_custom_rules, sample_rate_limits, sample_access_lists
    ):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        mock_bunny_client.list_access_lists.return_value = sample_access_lists
        mock_bunny_client.get_pull_zone.return_value = {"Id": 100, "EdgeRules": []}
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        result = provider.get_all_phase_rules(_zs())
        assert "bunny_waf_custom" in result
        assert "bunny_waf_rate_limit" in result
        assert "bunny_waf_access_list" in result

    def test_filter_by_provider_ids(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["bunny_waf_custom"])
        assert "bunny_waf_custom" in result
        assert "bunny_waf_rate_limit" not in result

    def test_unknown_provider_ids_ignored(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["unknown"])
        assert dict(result) == {}


class TestErrorWrapping:
    def test_auth_error(self, mock_bunny_client):
        mock_bunny_client.list_pull_zones.side_effect = BunnyAuthError("forbidden")
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderAuthError):
            provider.list_zones()

    def test_connection_error(self, mock_bunny_client):
        import httpx

        mock_bunny_client.list_pull_zones.side_effect = httpx.ConnectError("timeout")
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderConnectionError):
            provider.list_zones()

    def test_api_error(self, mock_bunny_client):
        mock_bunny_client.list_pull_zones.side_effect = BunnyAPIError("bad request")
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderError):
            provider.list_zones()


class TestUnsupportedMethods:
    def test_list_custom_rulesets_empty(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.list_custom_rulesets(_zs()) == []

    def test_put_custom_ruleset_raises(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError):
            provider.put_custom_ruleset(_zs(), "id", [])

    def test_list_lists_empty(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.list_lists(_zs()) == []

    def test_create_list_raises(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError):
            provider.create_list(_zs(), "name", "ip")

    def test_poll_bulk_operation_completed(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.poll_bulk_operation(_zs(), "op-1") == "completed"


class TestShieldZoneIdValidation:
    def test_non_numeric_zone_id_raises_config_error(self, mock_bunny_client):
        """Non-numeric zone_id raises ConfigError, not raw ValueError."""
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError, match="must be numeric"):
            provider.get_phase_rules(Scope(zone_id="abc"), "bunny_waf_custom")

    def test_empty_zone_id_raises_config_error(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError, match="must be numeric"):
            provider.get_phase_rules(Scope(zone_id=""), "bunny_waf_custom")

    def test_none_zone_id_raises_config_error(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError, match="must be numeric"):
            provider.get_phase_rules(Scope(zone_id=None), "bunny_waf_custom")

    def test_valid_numeric_zone_id_works(self, mock_bunny_client):
        mock_bunny_client.list_custom_waf_rules.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        result = provider.get_phase_rules(Scope(zone_id="999"), "bunny_waf_custom")
        assert result == []


class TestConcurrentWorkers:
    """Tests for concurrent/parallel usage with max_workers > 1."""

    def _setup_provider(self, mock_bunny_client, sample_pull_zones, sample_shield_zone):
        """Create a provider with multiple zones resolved."""
        # Each pull zone gets its own shield zone ID
        zones = [
            {"Id": 100, "Name": "cdn-a"},
            {"Id": 200, "Name": "cdn-b"},
            {"Id": 300, "Name": "cdn-c"},
        ]
        mock_bunny_client.list_pull_zones.return_value = zones

        shield_ids = {100: 901, 200: 902, 300: 903}

        def get_shield(pull_zone_id):
            return {"shieldZoneId": shield_ids[pull_zone_id]}

        mock_bunny_client.get_shield_zone_by_pullzone.side_effect = get_shield

        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=4)
        for name in ("cdn-a", "cdn-b", "cdn-c"):
            mock_bunny_client.list_pull_zones.return_value = zones
            provider.resolve_zone_id(name)
        return provider

    def test_concurrent_get_phase_rules_success(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone, sample_custom_rules
    ):
        """Multiple concurrent get_phase_rules calls all return correct results."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_bunny_client, sample_pull_zones, sample_shield_zone)
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules

        zone_ids = ["901", "902", "903"]
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "bunny_waf_custom",
                ): zid
                for zid in zone_ids
            }
            results = {}
            for future in as_completed(futures):
                zid = futures[future]
                results[zid] = future.result()

        assert len(results) == 3
        for zid in zone_ids:
            assert len(results[zid]) == 2
            assert results[zid][0]["ref"] == "Block SQLi"

    def test_concurrent_partial_failure(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone, sample_custom_rules
    ):
        """Some zones succeed while others raise ProviderError."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_bunny_client, sample_pull_zones, sample_shield_zone)

        call_count = 0

        def mock_list_rules(shield_zone_id):
            nonlocal call_count
            call_count += 1
            if shield_zone_id == 902:
                raise BunnyAPIError("server error")
            return sample_custom_rules

        mock_bunny_client.list_custom_waf_rules.side_effect = mock_list_rules

        zone_ids = ["901", "902", "903"]
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "bunny_waf_custom",
                ): zid
                for zid in zone_ids
            }
            results = {}
            errors = {}
            for future in as_completed(futures):
                zid = futures[future]
                try:
                    results[zid] = future.result()
                except ProviderError as e:
                    errors[zid] = e

        assert "901" in results
        assert "903" in results
        assert "902" in errors
        assert len(results) == 2
        assert len(errors) == 1

    def test_concurrent_auth_error_propagates(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        """ProviderAuthError propagates from concurrent execution."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_bunny_client, sample_pull_zones, sample_shield_zone)

        def mock_list_rules(shield_zone_id):
            if shield_zone_id == 901:
                raise BunnyAuthError("forbidden")
            return []

        mock_bunny_client.list_custom_waf_rules.side_effect = mock_list_rules

        zone_ids = ["901", "902", "903"]
        auth_errors = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "bunny_waf_custom",
                ): zid
                for zid in zone_ids
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except ProviderAuthError as e:
                    auth_errors.append(e)

        assert len(auth_errors) >= 1

    def test_concurrent_resolve_zone_id_populates_all_metadata(self, mock_bunny_client):
        """Concurrent resolve_zone_id calls populate _zone_meta for all zones."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        zones = [{"Id": i, "Name": f"cdn-{i}"} for i in range(10)]
        shield_ids = {i: 900 + i for i in range(10)}

        def get_shield(pull_zone_id):
            return {"shieldZoneId": shield_ids[pull_zone_id]}

        mock_bunny_client.get_shield_zone_by_pullzone.side_effect = get_shield

        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=4)

        zone_names = [f"cdn-{i}" for i in range(10)]
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for name in zone_names:
                # Each call needs its own pull zone list
                mock_bunny_client.list_pull_zones.return_value = zones
                futures[executor.submit(provider.resolve_zone_id, name)] = name

            results = {}
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

        # All 10 zones resolved
        assert len(results) == 10
        # All zone metadata populated (thread-safe via lock)
        assert len(provider._zone_meta) == 10
        for i in range(10):
            assert str(900 + i) in provider._zone_meta


class TestGetAllPhaseRulesResilience:
    def test_one_phase_fails_others_succeed(self, mock_bunny_client, sample_rate_limits):
        """If one phase fails, other phases are still returned."""
        mock_bunny_client.list_custom_waf_rules.side_effect = BunnyAPIError("timeout")
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        mock_bunny_client.list_access_lists.return_value = []
        mock_bunny_client.get_pull_zone.return_value = {"Id": 100, "EdgeRules": []}
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        result = provider.get_all_phase_rules(_zs())
        # Rate limit succeeded despite custom WAF failure
        assert "bunny_waf_rate_limit" in result
        assert "bunny_waf_custom" not in result
        assert "bunny_waf_custom" in result.failed_phases


class TestUnknownProviderIdRaises:
    def test_create_unknown_raises(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderError, match="unknown provider_id"):
            provider._create_rule("bogus_phase", 999, {})

    def test_update_unknown_raises(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderError, match="unknown provider_id"):
            provider._update_rule("bogus_phase", 999, 1, {})

    def test_delete_unknown_raises(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ProviderError, match="unknown provider_id"):
            provider._delete_rule("bogus_phase", 999, 1)


class TestThreadSafety:
    def test_lock_exists(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert hasattr(provider._lock, "acquire")
        assert hasattr(provider._lock, "release")


class TestClientContextManager:
    def test_context_manager(self):
        from octorules_bunny._client import BunnyShieldClient

        with BunnyShieldClient("test-key") as client:
            assert client._http is not None
        # After exit, client is closed (no assertion needed — just verify no exception)


class TestGetZoneMetadata:
    def test_returns_none_for_unknown_zone(self, mock_bunny_client):
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        assert provider.get_zone_metadata("unknown") is None

    def test_returns_metadata_after_resolve(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        zone_id = provider.resolve_zone_id("my-cdn")
        meta = provider.get_zone_metadata(zone_id)
        assert meta is not None
        assert meta["pull_zone_id"] == 100
        assert meta["name"] == "my-cdn"

    def test_returns_none_for_other_zone_after_resolve(
        self, mock_bunny_client, sample_pull_zones, sample_shield_zone
    ):
        mock_bunny_client.list_pull_zones.return_value = sample_pull_zones
        mock_bunny_client.get_shield_zone_by_pullzone.return_value = sample_shield_zone
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider.resolve_zone_id("my-cdn")
        assert provider.get_zone_metadata("0") is None


class TestConnectionPoolScaling:
    def test_default_no_pool_override(self, monkeypatch):
        """max_workers=1 (default) does not pass max_connections."""
        monkeypatch.setenv("BUNNY_API_KEY", "from-env")
        with unittest.mock.patch("octorules_bunny.provider.BunnyShieldClient") as mock_cls:
            mock_cls.return_value = unittest.mock.MagicMock()
            BunnyShieldProvider()
            mock_cls.assert_called_once_with("from-env", timeout=30.0, max_retries=2)

    def test_max_workers_sets_pool(self, monkeypatch):
        """max_workers > 1 passes max_connections = 10 * max_workers."""
        monkeypatch.setenv("BUNNY_API_KEY", "from-env")
        with unittest.mock.patch("octorules_bunny.provider.BunnyShieldClient") as mock_cls:
            mock_cls.return_value = unittest.mock.MagicMock()
            BunnyShieldProvider(max_workers=4)
            mock_cls.assert_called_once_with(
                "from-env", timeout=30.0, max_retries=2, max_connections=40
            )

    def test_client_accepts_max_connections(self):
        """BunnyShieldClient configures httpx.Limits when max_connections is set."""
        from octorules_bunny._client import BunnyShieldClient

        client = BunnyShieldClient("test-key", max_connections=40)
        # Verify the limits were applied (the pool has connection limits)
        assert client._http._transport._pool._max_connections == 40
        client.close()

    def test_client_default_no_limits(self):
        """BunnyShieldClient without max_connections uses httpx defaults."""
        from octorules_bunny._client import BunnyShieldClient

        client = BunnyShieldClient("test-key")
        assert client._http is not None
        client.close()


class TestFetchParallelIntegration:
    """Tests that get_all_phase_rules uses fetch_parallel correctly."""

    def _with_edge_meta(self, mock_bunny_client, provider):
        """Add zone metadata and edge rule mock so get_all_phase_rules works."""
        mock_bunny_client.get_pull_zone.return_value = {"Id": 100, "EdgeRules": []}
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        return provider

    def test_auth_error_propagates_from_parallel(self, mock_bunny_client):
        """ProviderAuthError from one phase cancels others and propagates."""
        mock_bunny_client.list_custom_waf_rules.side_effect = BunnyAuthError("forbidden")
        mock_bunny_client.list_rate_limits.return_value = []
        mock_bunny_client.list_access_lists.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=3)
        self._with_edge_meta(mock_bunny_client, provider)
        with pytest.raises(ProviderAuthError):
            provider.get_all_phase_rules(_zs())

    def test_parallel_all_phases_succeed(
        self, mock_bunny_client, sample_custom_rules, sample_rate_limits, sample_access_lists
    ):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        mock_bunny_client.list_access_lists.return_value = sample_access_lists
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=3)
        self._with_edge_meta(mock_bunny_client, provider)
        result = provider.get_all_phase_rules(_zs())
        assert "bunny_waf_custom" in result
        assert "bunny_waf_rate_limit" in result
        assert "bunny_waf_access_list" in result
        assert result.failed_phases == []

    def test_parallel_one_phase_fails(self, mock_bunny_client, sample_rate_limits):
        """One phase failure doesn't break other phases (parallel resilience)."""
        mock_bunny_client.list_custom_waf_rules.side_effect = BunnyAPIError("timeout")
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        mock_bunny_client.list_access_lists.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=3)
        self._with_edge_meta(mock_bunny_client, provider)
        result = provider.get_all_phase_rules(_zs())
        assert "bunny_waf_rate_limit" in result
        assert "bunny_waf_custom" not in result
        assert "bunny_waf_custom" in result.failed_phases

    def test_parallel_empty_phases_skipped(self, mock_bunny_client):
        """Phases with empty rules are excluded from the result dict."""
        mock_bunny_client.list_custom_waf_rules.return_value = []
        mock_bunny_client.list_rate_limits.return_value = []
        mock_bunny_client.list_access_lists.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=3)
        self._with_edge_meta(mock_bunny_client, provider)
        result = provider.get_all_phase_rules(_zs())
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_parallel_filter_by_provider_ids(self, mock_bunny_client, sample_custom_rules):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k", max_workers=3)
        result = provider.get_all_phase_rules(_zs(), provider_ids=["bunny_waf_custom"])
        assert "bunny_waf_custom" in result
        assert "bunny_waf_rate_limit" not in result
        # rate_limit and access_list should NOT have been called
        mock_bunny_client.list_rate_limits.assert_not_called()
        mock_bunny_client.list_access_lists.assert_not_called()


class TestDenormalizeEdgeCases:
    def test_empty_condition_returns_empty_dict(self):
        from octorules_bunny.provider import _denormalize_condition

        assert _denormalize_condition({}) == {}

    def test_empty_condition_in_rule(self):
        """Custom rule with empty conditions list produces valid API payload."""
        from octorules_bunny.provider import _denormalize_custom_rule

        rule = {"ref": "Test", "action": "block", "severity": "info", "conditions": []}
        result = _denormalize_custom_rule(rule, 999)
        config = result["ruleConfiguration"]
        # No primary condition → no variableTypes
        assert config.get("variableTypes") is None or config.get("variableTypes") == {}


class TestDuplicateRefDetection:
    """Regression tests for duplicate ref guard in put_phase_rules (H4)."""

    def test_duplicate_ref_in_current_rules(self, mock_bunny_client):
        """Duplicate refs in the current (API-returned) rules raises ConfigError."""
        # Two rules with the same ruleName → same ref after normalization
        duplicate_current = [
            {
                "id": 101,
                "shieldZoneId": 999,
                "ruleName": "Block SQLi",
                "ruleDescription": "",
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
                "ruleName": "Block SQLi",
                "ruleDescription": "",
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
        ]
        mock_bunny_client.list_custom_waf_rules.return_value = duplicate_current
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        desired = [
            {
                "ref": "New rule",
                "action": "block",
                "severity": "info",
                "conditions": [
                    {"variable": "request_uri", "operator": "contains", "value": "/admin"}
                ],
            },
        ]
        with pytest.raises(ConfigError, match="Duplicate refs"):
            provider.put_phase_rules(_zs(), "bunny_waf_custom", desired)

    def test_duplicate_ref_in_desired_rules(self, mock_bunny_client):
        """Duplicate refs in the desired (input) rules raises ConfigError."""
        mock_bunny_client.list_custom_waf_rules.return_value = []
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")

        desired = [
            {
                "ref": "Same name",
                "action": "block",
                "severity": "info",
                "conditions": [{"variable": "request_uri", "operator": "contains", "value": "/a"}],
            },
            {
                "ref": "Same name",
                "action": "challenge",
                "severity": "warning",
                "conditions": [{"variable": "request_uri", "operator": "contains", "value": "/b"}],
            },
        ]
        with pytest.raises(ConfigError, match="Duplicate refs"):
            provider.put_phase_rules(_zs(), "bunny_waf_custom", desired)
