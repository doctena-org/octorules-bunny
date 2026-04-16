"""Tests for new Shield config features: upload scanning, WAF settings, whitelabel."""

from octorules.provider.base import Scope

from octorules_bunny._shield_config import (
    denormalize_upload_scanning,
    denormalize_waf_settings,
    diff_shield_config,
    normalize_shield_config,
)


def _scope(zone_id="42"):
    return Scope(zone_id=zone_id, label="test-zone")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalizeWafSettings:
    def test_waf_settings_from_shield_zone(self):
        shield_zone = {
            "learningMode": True,
            "learningModeUntil": "2026-04-22T14:26:16",
            "wafRequestBodyLimitAction": 1,
            "wafResponseBodyLimitAction": 2,
            "whitelabelResponsePages": True,
            "wafRequestHeaderLoggingEnabled": True,
            "wafRequestIgnoredHeaders": ["Authorization", "Cookie"],
            # DDoS fields also present — should not leak into waf section
            "dDoSShieldSensitivity": 2,
        }
        result = normalize_shield_config(shield_zone, {})
        waf = result["waf"]
        assert waf["learning_mode"] is True
        assert waf["learning_mode_until"] == "2026-04-22T14:26:16"
        assert waf["request_body_limit_action"] == 1
        assert waf["response_body_limit_action"] == 2
        assert waf["whitelabel_response_pages"] is True
        assert waf["request_header_logging_enabled"] is True
        assert waf["request_ignored_headers"] == ["Authorization", "Cookie"]

    def test_waf_settings_defaults(self):
        """Shield zone with no WAF-specific fields still produces waf section."""
        result = normalize_shield_config({}, {})
        waf = result.get("waf", {})
        assert waf.get("learning_mode") is False
        assert waf.get("request_body_limit_action") == 0
        assert waf.get("whitelabel_response_pages") is False

    def test_learning_mode_false(self):
        shield_zone = {"learningMode": False, "learningModeUntil": "2026-04-15T00:00:00"}
        result = normalize_shield_config(shield_zone, {})
        assert result["waf"]["learning_mode"] is False


class TestNormalizeUploadScanning:
    def test_upload_scanning_from_api(self):
        shield_zone = {}
        upload_config = {
            "shieldZoneId": 123,
            "isEnabled": True,
            "csamScanningMode": 1,
            "antivirusScanningMode": 1,
        }
        result = normalize_shield_config(shield_zone, {}, upload_config=upload_config)
        us = result["upload_scanning"]
        assert us["enabled"] is True
        assert us["csam_scanning_mode"] == 1
        assert us["antivirus_scanning_mode"] == 1

    def test_upload_scanning_disabled(self):
        upload_config = {
            "isEnabled": False,
            "csamScanningMode": 0,
            "antivirusScanningMode": 0,
        }
        result = normalize_shield_config({}, {}, upload_config=upload_config)
        us = result["upload_scanning"]
        assert us["enabled"] is False
        assert us["csam_scanning_mode"] == 0

    def test_upload_scanning_absent(self):
        """When no upload config is provided, no upload_scanning section."""
        result = normalize_shield_config({}, {})
        assert "upload_scanning" not in result


# ---------------------------------------------------------------------------
# Denormalization
# ---------------------------------------------------------------------------
class TestDenormalizeWafSettings:
    def test_round_trip_fields(self):
        config = {
            "learning_mode": False,
            "request_body_limit_action": 2,
            "response_body_limit_action": 1,
            "whitelabel_response_pages": True,
            "request_header_logging_enabled": False,
            "request_ignored_headers": ["Authorization"],
        }
        result = denormalize_waf_settings(config)
        assert result["learningMode"] is False
        assert result["wafRequestBodyLimitAction"] == 2
        assert result["wafResponseBodyLimitAction"] == 1
        assert result["whitelabelResponsePages"] is True
        assert result["wafRequestHeaderLoggingEnabled"] is False
        assert result["wafRequestIgnoredHeaders"] == ["Authorization"]

    def test_partial_config(self):
        """Only present keys are denormalized."""
        config = {"whitelabel_response_pages": True}
        result = denormalize_waf_settings(config)
        assert result == {"whitelabelResponsePages": True}
        assert "learningMode" not in result

    def test_learning_mode_until_excluded(self):
        """learning_mode_until is read-only — should not be denormalized."""
        config = {"learning_mode": True, "learning_mode_until": "2026-04-22T00:00:00"}
        result = denormalize_waf_settings(config)
        assert "learningMode" in result
        assert "learningModeUntil" not in result


class TestDenormalizeUploadScanning:
    def test_round_trip(self):
        config = {
            "enabled": True,
            "csam_scanning_mode": 1,
            "antivirus_scanning_mode": 1,
        }
        result = denormalize_upload_scanning(config)
        assert result["isEnabled"] is True
        assert result["csamScanningMode"] == 1
        assert result["antivirusScanningMode"] == 1

    def test_partial(self):
        config = {"enabled": False}
        result = denormalize_upload_scanning(config)
        assert result == {"isEnabled": False}


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiffNewSections:
    def test_waf_diff_detects_changes(self):
        current = {
            "waf": {
                "learning_mode": True,
                "request_body_limit_action": 1,
                "whitelabel_response_pages": False,
            }
        }
        desired = {
            "waf": {
                "learning_mode": False,
                "request_body_limit_action": 2,
                "whitelabel_response_pages": True,
            }
        }
        plan = diff_shield_config(current, desired)
        assert plan.has_changes
        waf_changes = [c for c in plan.changes if c.section == "waf"]
        assert len(waf_changes) == 3

    def test_upload_scanning_diff(self):
        current = {"upload_scanning": {"enabled": False, "csam_scanning_mode": 0}}
        desired = {"upload_scanning": {"enabled": True, "csam_scanning_mode": 1}}
        plan = diff_shield_config(current, desired)
        assert plan.has_changes
        us_changes = [c for c in plan.changes if c.section == "upload_scanning"]
        assert len(us_changes) == 2

    def test_no_changes(self):
        config = {"waf": {"learning_mode": True}, "upload_scanning": {"enabled": False}}
        plan = diff_shield_config(config, config)
        assert not plan.has_changes


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
class TestValidateNewSections:
    def test_valid_waf_config(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {
            "bunny_shield_config": {
                "waf": {
                    "learning_mode": True,
                    "request_body_limit_action": 1,
                    "response_body_limit_action": 2,
                    "whitelabel_response_pages": False,
                    "request_header_logging_enabled": True,
                    "request_ignored_headers": ["Authorization"],
                }
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_waf_learning_mode_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"learning_mode": "yes"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "learning_mode" in errors[0]

    def test_invalid_body_limit_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"request_body_limit_action": "big"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "request_body_limit_action" in errors[0]

    def test_invalid_ignored_headers_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"waf": {"request_ignored_headers": "Authorization"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "request_ignored_headers" in errors[0]

    def test_valid_upload_scanning(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {
            "bunny_shield_config": {
                "upload_scanning": {
                    "enabled": True,
                    "csam_scanning_mode": 1,
                    "antivirus_scanning_mode": 0,
                }
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_upload_scanning_mode_type(self):
        from octorules_bunny._shield_config import _validate_shield_config

        desired = {"bunny_shield_config": {"upload_scanning": {"csam_scanning_mode": "on"}}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "csam_scanning_mode" in errors[0]
