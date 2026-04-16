"""Tests for remaining missing Shield fields (wafEnabled, wafExecutionMode, etc.)."""

from octorules_bunny._enums import EXECUTION_MODE
from octorules_bunny._shield_config import (
    denormalize_bot_config,
    denormalize_waf_settings,
    normalize_shield_config,
)


class TestWafGlobalFields:
    """wafEnabled, wafExecutionMode, wafRealtimeThreatIntelligenceEnabled, wafProfileId."""

    def test_normalize_includes_global_waf_fields(self):
        shield_zone = {
            "wafEnabled": True,
            "wafExecutionMode": 1,
            "wafRealtimeThreatIntelligenceEnabled": True,
            "wafProfileId": 2,
            "wafEngineConfig": [
                {"name": "allowed_methods", "valueEncoded": "GET POST"},
            ],
        }
        result = normalize_shield_config(shield_zone, {})
        waf = result["waf"]
        assert waf["enabled"] is True
        assert waf["execution_mode"] == "block"  # 1 = block
        assert waf["realtime_threat_intelligence_enabled"] is True
        assert waf["profile_id"] == 2
        assert waf["engine_config"] == [
            {"name": "allowed_methods", "valueEncoded": "GET POST"},
        ]

    def test_normalize_waf_defaults(self):
        result = normalize_shield_config({}, {})
        waf = result["waf"]
        assert waf["enabled"] is False
        assert waf["execution_mode"] == "log"  # 0 = log
        assert waf["realtime_threat_intelligence_enabled"] is False
        assert waf["profile_id"] is None
        assert waf["engine_config"] == []

    def test_denormalize_global_waf_fields(self):
        config = {
            "enabled": False,
            "execution_mode": "block",
            "realtime_threat_intelligence_enabled": True,
            "profile_id": 2,
            "engine_config": [
                {"name": "allowed_methods", "valueEncoded": "GET POST PUT"},
            ],
        }
        result = denormalize_waf_settings(config)
        assert result["wafEnabled"] is False
        assert result["wafExecutionMode"] == 1
        assert result["wafRealtimeThreatIntelligenceEnabled"] is True
        assert result["wafProfileId"] == 2
        assert result["wafEngineConfig"] == [
            {"name": "allowed_methods", "valueEncoded": "GET POST PUT"},
        ]

    def test_denormalize_partial_only_enabled(self):
        config = {"enabled": True}
        result = denormalize_waf_settings(config)
        assert result == {"wafEnabled": True}
        assert "wafExecutionMode" not in result

    def test_execution_mode_enum_values(self):
        """WAFExecutionMode: 0=Log, 1=Block."""
        assert EXECUTION_MODE.resolve(0) == "off"
        # The WAF execution mode uses the same EXECUTION_MODE enum
        # but note: WAFExecutionMode has 0=Log, 1=Block
        # which is different from the general EXECUTION_MODE (0=off, 1=log, 2=block)
        # We need a separate enum for this.


class TestBotDetectionAggression:
    """browserFingerprint.aggression field."""

    def test_normalize_includes_aggression(self):
        bot_config = {
            "executionMode": 1,
            "browserFingerprint": {"sensitivity": 2, "aggression": 3, "complexEnabled": True},
            "requestIntegrity": {"sensitivity": 0},
            "ipAddress": {"sensitivity": 0},
        }
        result = normalize_shield_config({}, bot_config)
        bd = result["bot_detection"]
        assert bd["fingerprint_aggression"] == 3

    def test_normalize_aggression_default(self):
        bot_config = {
            "executionMode": 0,
            "browserFingerprint": {"sensitivity": 0},
            "requestIntegrity": {"sensitivity": 0},
            "ipAddress": {"sensitivity": 0},
        }
        result = normalize_shield_config({}, bot_config)
        assert result["bot_detection"]["fingerprint_aggression"] == 1

    def test_denormalize_includes_aggression(self):
        config = {
            "fingerprint_sensitivity": "high",
            "fingerprint_aggression": 3,
            "complex_fingerprinting": True,
        }
        result = denormalize_bot_config(config)
        bf = result["browserFingerprint"]
        assert bf["aggression"] == 3
        assert bf["sensitivity"] == 3  # high
        assert bf["complexEnabled"] is True

    def test_denormalize_without_aggression(self):
        config = {"fingerprint_sensitivity": "low"}
        result = denormalize_bot_config(config)
        bf = result["browserFingerprint"]
        assert bf["sensitivity"] == 1
        assert "aggression" not in bf


class TestValidateNewFields:
    def test_valid_waf_global_fields(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {
            "bunny_shield_config": {
                "waf": {
                    "enabled": True,
                    "execution_mode": "block",
                    "realtime_threat_intelligence_enabled": False,
                    "profile_id": 2,
                }
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_waf_execution_mode(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"execution_mode": "nuke"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "execution_mode" in errors[0]

    def test_invalid_profile_id_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"profile_id": "general"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "profile_id" in errors[0]

    def test_invalid_engine_config_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"engine_config": "bad"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "engine_config" in errors[0]

    def test_valid_aggression(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"bot_detection": {"fingerprint_aggression": 2}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_aggression_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"bot_detection": {"fingerprint_aggression": "high"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "fingerprint_aggression" in errors[0]
