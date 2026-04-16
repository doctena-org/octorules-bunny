"""Tests for Bunny CDN Edge Rules phase.

Covers normalization round-trips, provider get/put, enum mapping, and
validation (BN7xx rule IDs).
"""

import pytest
from octorules.config import ConfigError
from octorules.linter.engine import LintResult
from octorules.provider.base import Scope

from octorules_bunny._enums import (
    EDGE_ACTION,
    EDGE_PATTERN_MATCH,
    EDGE_TRIGGER,
    EDGE_TRIGGER_MATCH,
)
from octorules_bunny.provider import (
    BunnyShieldProvider,
    _denormalize_edge_rule,
    _normalize_edge_rule,
)
from octorules_bunny.validate import validate_rules

_E = "bunny_edge_rules"


def _zs(zone_id: str = "999", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


def _edge_rule(**overrides):
    """Build a minimal valid edge rule with overrides."""
    base = {
        "ref": "Force HTTPS",
        "enabled": True,
        "description": "Force HTTPS",
        "action_type": "force_ssl",
        "action_parameter_1": "",
        "action_parameter_2": "",
        "trigger_matching_type": "all",
        "triggers": [
            {
                "type": "url",
                "pattern_matching_type": "any",
                "pattern_matches": ["http://*"],
            },
        ],
    }
    base.update(overrides)
    return base


def _ids(results: list[LintResult]) -> list[str]:
    return [r.rule_id for r in results]


# ---------------------------------------------------------------------------
# Enum maps
# ---------------------------------------------------------------------------
class TestEdgeEnumRoundTrip:
    def test_action_round_trip(self):
        for int_val, str_val in EDGE_ACTION.items():
            assert EDGE_ACTION.unresolve(str_val) == int_val

    def test_trigger_round_trip(self):
        for int_val, str_val in EDGE_TRIGGER.items():
            assert EDGE_TRIGGER.unresolve(str_val) == int_val

    def test_pattern_match_round_trip(self):
        for int_val, str_val in EDGE_PATTERN_MATCH.items():
            assert EDGE_PATTERN_MATCH.unresolve(str_val) == int_val

    def test_trigger_match_round_trip(self):
        for int_val, str_val in EDGE_TRIGGER_MATCH.items():
            assert EDGE_TRIGGER_MATCH.unresolve(str_val) == int_val

    def test_action_count(self):
        assert len(EDGE_ACTION) == 35

    def test_trigger_count(self):
        assert len(EDGE_TRIGGER) == 14

    def test_pattern_match_count(self):
        assert len(EDGE_PATTERN_MATCH) == 3

    def test_trigger_match_count(self):
        assert len(EDGE_TRIGGER_MATCH) == 3

    def test_no_duplicate_values(self):
        # Bijection enforced by EnumMap constructor; verify counts match
        for em in (EDGE_ACTION, EDGE_TRIGGER):
            strs = [s for _, s in em.items()]
            assert len(set(strs)) == len(strs)


# ---------------------------------------------------------------------------
# Normalization round-trip
# ---------------------------------------------------------------------------
class TestEdgeRuleNormalization:
    def test_force_ssl_rule(self):
        api_rule = {
            "Guid": "abc-def-123",
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
        }
        normalized = _normalize_edge_rule(api_rule)
        assert normalized["ref"] == "Force HTTPS"
        assert normalized["_api_id"] == "abc-def-123"
        assert normalized["action_type"] == "force_ssl"
        assert normalized["trigger_matching_type"] == "any"
        assert normalized["enabled"] is True
        assert len(normalized["triggers"]) == 1
        assert normalized["triggers"][0]["type"] == "url"
        assert normalized["triggers"][0]["pattern_matching_type"] == "any"
        assert normalized["triggers"][0]["pattern_matches"] == ["http://*"]

    def test_block_request_rule(self):
        api_rule = {
            "Guid": "block-guid",
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
        }
        normalized = _normalize_edge_rule(api_rule)
        assert normalized["action_type"] == "block_request"
        assert normalized["triggers"][0]["type"] == "country_code"
        assert normalized["triggers"][0]["pattern_matches"] == ["CN", "RU"]

    def test_redirect_rule_with_parameters(self):
        api_rule = {
            "Guid": "redir-guid",
            "ActionType": 1,
            "ActionParameter1": "https://example.com/new",
            "ActionParameter2": "301",
            "Triggers": [
                {
                    "Type": 0,
                    "PatternMatchingType": 0,
                    "PatternMatches": ["/old-path*"],
                    "Parameter1": "",
                },
            ],
            "TriggerMatchingType": 0,
            "Description": "Redirect old path",
            "Enabled": False,
        }
        normalized = _normalize_edge_rule(api_rule)
        assert normalized["action_type"] == "redirect"
        assert normalized["action_parameter_1"] == "https://example.com/new"
        assert normalized["action_parameter_2"] == "301"
        assert normalized["enabled"] is False

    def test_round_trip(self):
        """normalize -> denormalize produces structurally equivalent API payload."""
        api_rule = {
            "Guid": "rt-guid",
            "ActionType": 5,
            "ActionParameter1": "X-Custom",
            "ActionParameter2": "my-value",
            "Triggers": [
                {
                    "Type": 0,
                    "PatternMatchingType": 0,
                    "PatternMatches": ["/api/*"],
                    "Parameter1": "",
                },
                {
                    "Type": 9,
                    "PatternMatchingType": 0,
                    "PatternMatches": ["GET"],
                    "Parameter1": "",
                },
            ],
            "TriggerMatchingType": 1,
            "Description": "Set header on API",
            "Enabled": True,
        }
        normalized = _normalize_edge_rule(api_rule)
        denormalized = _denormalize_edge_rule(normalized)

        assert denormalized["ActionType"] == 5
        assert denormalized["ActionParameter1"] == "X-Custom"
        assert denormalized["ActionParameter2"] == "my-value"
        assert denormalized["TriggerMatchingType"] == 1
        assert denormalized["Enabled"] is True
        assert denormalized["Guid"] == "rt-guid"
        assert denormalized["Description"] == "Set header on API"
        assert len(denormalized["Triggers"]) == 2
        assert denormalized["Triggers"][0]["Type"] == 0
        assert denormalized["Triggers"][0]["PatternMatches"] == ["/api/*"]
        assert denormalized["Triggers"][1]["Type"] == 9

    def test_denormalize_new_rule_no_guid(self):
        """New rule (no _api_id) should not include Guid in payload."""
        rule = _edge_rule()
        denormalized = _denormalize_edge_rule(rule)
        assert "Guid" not in denormalized
        assert denormalized["ActionType"] == 0
        assert denormalized["Enabled"] is True

    def test_trigger_parameter_1_optional(self):
        """Parameter1 is omitted when empty in normalized form."""
        api_trigger = {
            "Type": 1,
            "PatternMatchingType": 0,
            "PatternMatches": ["x-bot: true"],
            "Parameter1": "X-Bot",
        }
        from octorules_bunny.provider import _normalize_edge_trigger

        normalized = _normalize_edge_trigger(api_trigger)
        assert normalized["parameter_1"] == "X-Bot"

    def test_trigger_parameter_1_absent_when_empty(self):
        """Empty Parameter1 is omitted from normalized form."""
        api_trigger = {
            "Type": 0,
            "PatternMatchingType": 0,
            "PatternMatches": ["/test"],
            "Parameter1": "",
        }
        from octorules_bunny.provider import _normalize_edge_trigger

        normalized = _normalize_edge_trigger(api_trigger)
        assert "parameter_1" not in normalized

    def test_unknown_enum_values_preserved(self):
        """Unknown enum ints should pass through as strings, not crash."""
        api_rule = {
            "Guid": "unknown-guid",
            "ActionType": 99,
            "ActionParameter1": "",
            "ActionParameter2": "",
            "Triggers": [
                {
                    "Type": 99,
                    "PatternMatchingType": 99,
                    "PatternMatches": ["*"],
                    "Parameter1": "",
                },
            ],
            "TriggerMatchingType": 99,
            "Description": "Unknown enums",
            "Enabled": True,
        }
        normalized = _normalize_edge_rule(api_rule)
        assert normalized["action_type"] == "99"
        assert normalized["triggers"][0]["type"] == "99"
        assert normalized["trigger_matching_type"] == "99"


# ---------------------------------------------------------------------------
# Provider get/put
# ---------------------------------------------------------------------------
class TestGetEdgeRules:
    def _provider_with_meta(self, mock_bunny_client):
        """Create a provider with zone metadata pre-populated."""
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        return provider

    def test_get_edge_rules(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        mock_bunny_client.get_pull_zone.return_value = sample_pull_zone_with_edge_rules
        provider = self._provider_with_meta(mock_bunny_client)
        rules = provider.get_phase_rules(_zs(), "bunny_edge_rule")
        assert len(rules) == 2
        assert rules[0]["ref"] == "Force HTTPS"
        assert rules[0]["action_type"] == "force_ssl"
        assert rules[0]["_api_id"] == "aaa-bbb-111"
        assert rules[1]["ref"] == "Block countries"
        assert rules[1]["action_type"] == "block_request"
        mock_bunny_client.get_pull_zone.assert_called_once_with(100)

    def test_get_edge_rules_empty(self, mock_bunny_client):
        mock_bunny_client.get_pull_zone.return_value = {"Id": 100, "Name": "my-cdn"}
        provider = self._provider_with_meta(mock_bunny_client)
        rules = provider.get_phase_rules(_zs(), "bunny_edge_rule")
        assert rules == []

    def test_get_edge_rules_no_metadata_raises(self, mock_bunny_client):
        """Without zone metadata, edge rules should raise ConfigError."""
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        with pytest.raises(ConfigError, match="No pull zone metadata"):
            provider.get_phase_rules(_zs(), "bunny_edge_rule")


class TestPutEdgeRules:
    def _provider_with_meta(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        mock_bunny_client.get_pull_zone.return_value = sample_pull_zone_with_edge_rules
        mock_bunny_client.create_or_update_edge_rule.return_value = {}
        mock_bunny_client.delete_edge_rule.return_value = None
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        return provider

    def test_add_new_edge_rule(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        provider = self._provider_with_meta(mock_bunny_client, sample_pull_zone_with_edge_rules)
        new_rules = [
            _edge_rule(ref="Force HTTPS"),
            _edge_rule(ref="Block countries", action_type="block_request"),
            _edge_rule(ref="New redirect", action_type="redirect"),
        ]
        count = provider.put_phase_rules(_zs(), "bunny_edge_rule", new_rules)
        assert count == 3
        # 2 existing rules updated + 1 new rule created
        assert mock_bunny_client.create_or_update_edge_rule.call_count == 3
        assert mock_bunny_client.delete_edge_rule.call_count == 0

    def test_remove_edge_rule(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        provider = self._provider_with_meta(mock_bunny_client, sample_pull_zone_with_edge_rules)
        # Keep only first rule
        new_rules = [_edge_rule(ref="Force HTTPS")]
        count = provider.put_phase_rules(_zs(), "bunny_edge_rule", new_rules)
        assert count == 1
        assert mock_bunny_client.delete_edge_rule.call_count == 1
        mock_bunny_client.delete_edge_rule.assert_called_with(100, "ccc-ddd-222")

    def test_empty_rules_removes_all(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        provider = self._provider_with_meta(mock_bunny_client, sample_pull_zone_with_edge_rules)
        count = provider.put_phase_rules(_zs(), "bunny_edge_rule", [])
        assert count == 0
        assert mock_bunny_client.delete_edge_rule.call_count == 2

    def test_idempotent_put(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        """Put the same rules back — only updates, no creates/deletes."""
        provider = self._provider_with_meta(mock_bunny_client, sample_pull_zone_with_edge_rules)
        current = provider.get_phase_rules(_zs(), "bunny_edge_rule")
        provider.put_phase_rules(_zs(), "bunny_edge_rule", current)
        # Both existing rules updated via create_or_update
        assert mock_bunny_client.create_or_update_edge_rule.call_count == 2
        assert mock_bunny_client.delete_edge_rule.call_count == 0


class TestGetAllPhaseRulesIncludesEdge:
    def test_includes_edge_rules(
        self,
        mock_bunny_client,
        sample_custom_rules,
        sample_rate_limits,
        sample_access_lists,
        sample_pull_zone_with_edge_rules,
    ):
        mock_bunny_client.list_custom_waf_rules.return_value = sample_custom_rules
        mock_bunny_client.list_rate_limits.return_value = sample_rate_limits
        mock_bunny_client.list_access_lists.return_value = sample_access_lists
        mock_bunny_client.get_pull_zone.return_value = sample_pull_zone_with_edge_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        result = provider.get_all_phase_rules(_zs())
        assert "bunny_waf_custom" in result
        assert "bunny_waf_rate_limit" in result
        assert "bunny_waf_access_list" in result
        assert "bunny_edge_rule" in result
        assert len(result["bunny_edge_rule"]) == 2

    def test_filter_edge_rules_only(self, mock_bunny_client, sample_pull_zone_with_edge_rules):
        mock_bunny_client.get_pull_zone.return_value = sample_pull_zone_with_edge_rules
        provider = BunnyShieldProvider(client=mock_bunny_client, api_key="k")
        provider._zone_meta["999"] = {"pull_zone_id": 100, "name": "my-cdn"}
        result = provider.get_all_phase_rules(_zs(), provider_ids=["bunny_edge_rule"])
        assert "bunny_edge_rule" in result
        assert "bunny_waf_custom" not in result
        mock_bunny_client.list_custom_waf_rules.assert_not_called()


# ---------------------------------------------------------------------------
# Validation (BN7xx)
# ---------------------------------------------------------------------------
class TestEdgeRuleValidation:
    def test_valid_rule_no_errors(self):
        assert validate_rules([_edge_rule()], phase=_E) == []

    def test_empty_list(self):
        assert validate_rules([], phase=_E) == []


class TestBN001EdgeMissingRef:
    def test_missing_ref(self):
        r = _edge_rule()
        del r["ref"]
        assert "BN001" in _ids(validate_rules([r], phase=_E))

    def test_empty_ref(self):
        assert "BN001" in _ids(validate_rules([_edge_rule(ref="")], phase=_E))


class TestBN002EdgeDuplicateRef:
    def test_duplicate_ref(self):
        rules = [_edge_rule(ref="dup"), _edge_rule(ref="dup")]
        assert "BN002" in _ids(validate_rules(rules, phase=_E))


class TestBN004EdgeUnknownFields:
    def test_unknown_field(self):
        r = _edge_rule(unknown_field="x")
        assert "BN004" in _ids(validate_rules([r], phase=_E))

    def test_api_id_not_flagged(self):
        r = _edge_rule(_api_id="guid-123")
        assert "BN004" not in _ids(validate_rules([r], phase=_E))


class TestBN700InvalidActionType:
    def test_missing_action_type(self):
        r = _edge_rule()
        del r["action_type"]
        assert "BN700" in _ids(validate_rules([r], phase=_E))

    def test_invalid_action_type(self):
        assert "BN700" in _ids(validate_rules([_edge_rule(action_type="nope")], phase=_E))

    def test_all_valid_action_types(self):
        for action in EDGE_ACTION:
            ids = _ids(validate_rules([_edge_rule(action_type=action)], phase=_E))
            assert "BN700" not in ids, f"{action} incorrectly flagged"


class TestBN701InvalidTriggerType:
    def test_missing_trigger_type(self):
        r = _edge_rule(triggers=[{"pattern_matching_type": "any", "pattern_matches": ["*"]}])
        assert "BN701" in _ids(validate_rules([r], phase=_E))

    def test_invalid_trigger_type(self):
        r = _edge_rule(
            triggers=[{"type": "bogus", "pattern_matching_type": "any", "pattern_matches": ["*"]}]
        )
        assert "BN701" in _ids(validate_rules([r], phase=_E))

    def test_all_valid_trigger_types(self):
        for ttype in EDGE_TRIGGER:
            trigger = {"type": ttype, "pattern_matching_type": "any", "pattern_matches": ["*"]}
            ids = _ids(validate_rules([_edge_rule(triggers=[trigger])], phase=_E))
            assert "BN701" not in ids, f"{ttype} incorrectly flagged"


class TestBN702NoTriggers:
    def test_empty_triggers(self):
        assert "BN702" in _ids(validate_rules([_edge_rule(triggers=[])], phase=_E))

    def test_missing_triggers(self):
        r = _edge_rule()
        del r["triggers"]
        assert "BN702" in _ids(validate_rules([r], phase=_E))


class TestBN703InvalidTriggerMatchingType:
    def test_invalid(self):
        r = _edge_rule(trigger_matching_type="bogus")
        assert "BN703" in _ids(validate_rules([r], phase=_E))

    def test_valid_all(self):
        assert "BN703" not in _ids(
            validate_rules([_edge_rule(trigger_matching_type="all")], phase=_E)
        )

    def test_valid_any(self):
        assert "BN703" not in _ids(
            validate_rules([_edge_rule(trigger_matching_type="any")], phase=_E)
        )


class TestBN704EmptyPatternMatches:
    def test_empty_patterns(self):
        r = _edge_rule(
            triggers=[{"type": "url", "pattern_matching_type": "any", "pattern_matches": []}]
        )
        assert "BN704" in _ids(validate_rules([r], phase=_E))

    def test_non_empty_patterns_ok(self):
        assert "BN704" not in _ids(validate_rules([_edge_rule()], phase=_E))


class TestBN706ActionParameterRequirements:
    def test_bn706_redirect_missing_param1(self):
        r = _edge_rule(action_type="redirect", action_parameter_1="", action_parameter_2="301")
        assert "BN706" in _ids(validate_rules([r], phase=_E))

    def test_bn706_redirect_missing_param2(self):
        r = _edge_rule(
            action_type="redirect",
            action_parameter_1="https://example.com/new",
            action_parameter_2="",
        )
        assert "BN706" in _ids(validate_rules([r], phase=_E))

    def test_bn706_force_ssl_no_params_ok(self):
        r = _edge_rule(action_type="force_ssl", action_parameter_1="", action_parameter_2="")
        assert "BN706" not in _ids(validate_rules([r], phase=_E))

    def test_bn706_set_status_code_missing_param1(self):
        r = _edge_rule(action_type="set_status_code", action_parameter_1="")
        assert "BN706" in _ids(validate_rules([r], phase=_E))

    def test_bn706_set_status_code_with_param1_ok(self):
        r = _edge_rule(action_type="set_status_code", action_parameter_1="404")
        assert "BN706" not in _ids(validate_rules([r], phase=_E))

    def test_bn706_set_response_header_missing_both(self):
        r = _edge_rule(
            action_type="set_response_header", action_parameter_1="", action_parameter_2=""
        )
        results = [res for res in validate_rules([r], phase=_E) if res.rule_id == "BN706"]
        assert len(results) == 2  # both param1 and param2 missing

    def test_bn706_block_request_no_params_ok(self):
        r = _edge_rule(action_type="block_request", action_parameter_1="", action_parameter_2="")
        assert "BN706" not in _ids(validate_rules([r], phase=_E))


class TestBN705InvalidPatternMatchingType:
    def test_invalid(self):
        r = _edge_rule(
            triggers=[{"type": "url", "pattern_matching_type": "bogus", "pattern_matches": ["*"]}]
        )
        assert "BN705" in _ids(validate_rules([r], phase=_E))

    def test_valid(self):
        for pmt in ("any", "all", "none"):
            trigger = {"type": "url", "pattern_matching_type": pmt, "pattern_matches": ["*"]}
            ids = _ids(validate_rules([_edge_rule(triggers=[trigger])], phase=_E))
            assert "BN705" not in ids


class TestBN005EdgeTypeMismatch:
    def test_enabled_not_bool(self):
        assert "BN005" in _ids(validate_rules([_edge_rule(enabled="yes")], phase=_E))

    def test_triggers_not_list(self):
        assert "BN005" in _ids(validate_rules([_edge_rule(triggers="bad")], phase=_E))

    def test_pattern_matches_not_list(self):
        r = _edge_rule(
            triggers=[{"type": "url", "pattern_matching_type": "any", "pattern_matches": "bad"}]
        )
        assert "BN005" in _ids(validate_rules([r], phase=_E))


class TestEdgeRuleBestPractice:
    def test_bn601_no_description(self):
        r = _edge_rule(description="")
        assert "BN601" in _ids(validate_rules([r], phase=_E))

    def test_bn601_with_description_ok(self):
        assert "BN601" not in _ids(validate_rules([_edge_rule()], phase=_E))

    def test_bn011_description_too_long(self):
        r = _edge_rule(description="x" * 256)
        assert "BN011" in _ids(validate_rules([r], phase=_E))


class TestEdgeRuleEdgeCases:
    def test_none_action_type(self):
        """None values should not crash validation."""
        r = _edge_rule(action_type=None)
        validate_rules([r], phase=_E)

    def test_rule_with_only_ref(self):
        """Minimal invalid rule — should produce errors, not crash."""
        results = validate_rules([{"ref": "Bare rule"}], phase=_E)
        assert len(results) > 0

    def test_multiple_triggers(self):
        """Rule with multiple triggers validates each."""
        triggers = [
            {"type": "url", "pattern_matching_type": "any", "pattern_matches": ["/api/*"]},
            {"type": "request_method", "pattern_matching_type": "any", "pattern_matches": ["GET"]},
        ]
        assert validate_rules([_edge_rule(triggers=triggers)], phase=_E) == []
