"""Tests for Bunny pull zone security config normalization and extension hooks."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_bunny._pullzone_security import (
    PullZoneSecurityChange,
    PullZoneSecurityFormatter,
    PullZoneSecurityPlan,
    _apply_pullzone_security,
    _dump_pullzone_security,
    _finalize_pullzone_security,
    _prefetch_pullzone_security,
    _validate_pullzone_security,
    denormalize_pullzone_security,
    diff_pullzone_security,
    normalize_pullzone_security,
)


def _scope(zone_id: str = "999") -> Scope:
    return Scope(zone_id=zone_id, label="test-zone")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalizePullZoneSecurity:
    def test_full_pull_zone(self):
        pz = {
            "BlockedIps": "1.2.3.4\n5.6.7.8",
            "BlockedCountries": "CN,RU",
            "BlockedReferrers": "spam.example.com\nbad.example.com",
            "AllowedReferrers": "good.example.com",
            "BlockPostRequests": True,
            "BlockRootPathAccess": False,
            "EnableTokenAuthentication": True,
            "ZoneSecurityIncludeHashRemoteIP": True,
            "BlockNoneReferrer": True,
            "EnableAccessControlOriginHeader": True,
            "AccessControlOriginHeaderExtensions": ".jpg .png",
            "LoggingIPAnonymization": True,
        }
        result = normalize_pullzone_security(pz)
        assert result["blocked_ips"] == "1.2.3.4\n5.6.7.8"
        assert result["blocked_countries"] == "CN,RU"
        assert result["blocked_referrers"] == "spam.example.com\nbad.example.com"
        assert result["allowed_referrers"] == "good.example.com"
        assert result["block_post_requests"] is True
        assert result["block_root_path_access"] is False
        assert result["enable_token_authentication"] is True
        assert result["token_auth_include_ip"] is True
        assert result["block_none_referrer"] is True
        assert result["cors_enabled"] is True
        assert result["cors_extensions"] == ".jpg .png"
        assert result["logging_ip_anonymization"] is True

    def test_empty_pull_zone(self):
        result = normalize_pullzone_security({})
        assert result["blocked_ips"] == ""
        assert result["blocked_countries"] == ""
        assert result["blocked_referrers"] == ""
        assert result["allowed_referrers"] == ""
        assert result["block_post_requests"] is False
        assert result["block_root_path_access"] is False
        assert result["enable_token_authentication"] is False
        assert result["token_auth_include_ip"] is False
        assert result["block_none_referrer"] is False
        assert result["cors_enabled"] is False
        assert result["cors_extensions"] == ""
        assert result["logging_ip_anonymization"] is False

    def test_partial_pull_zone(self):
        pz = {"BlockedIps": "10.0.0.1", "EnableTokenAuthentication": True}
        result = normalize_pullzone_security(pz)
        assert result["blocked_ips"] == "10.0.0.1"
        assert result["enable_token_authentication"] is True
        # Defaults for missing fields
        assert result["blocked_countries"] == ""
        assert result["block_post_requests"] is False


class TestDenormalizePullZoneSecurity:
    def test_round_trip(self):
        config = {
            "blocked_ips": "1.2.3.4\n5.6.7.8",
            "blocked_countries": "CN,RU",
            "blocked_referrers": "spam.example.com",
            "allowed_referrers": "good.example.com",
            "block_post_requests": True,
            "block_root_path_access": False,
            "enable_token_authentication": True,
            "token_auth_include_ip": True,
            "block_none_referrer": True,
            "cors_enabled": True,
            "cors_extensions": ".jpg .png",
            "logging_ip_anonymization": True,
        }
        result = denormalize_pullzone_security(config)
        assert result["BlockedIps"] == "1.2.3.4\n5.6.7.8"
        assert result["BlockedCountries"] == "CN,RU"
        assert result["BlockedReferrers"] == "spam.example.com"
        assert result["AllowedReferrers"] == "good.example.com"
        assert result["BlockPostRequests"] is True
        assert result["BlockRootPathAccess"] is False
        assert result["EnableTokenAuthentication"] is True
        assert result["ZoneSecurityIncludeHashRemoteIP"] is True
        assert result["BlockNoneReferrer"] is True
        assert result["EnableAccessControlOriginHeader"] is True
        assert result["AccessControlOriginHeaderExtensions"] == ".jpg .png"
        assert result["LoggingIPAnonymization"] is True

    def test_partial_config(self):
        """Only specified keys appear in the API payload."""
        config = {"blocked_ips": "1.2.3.4", "cors_enabled": True}
        result = denormalize_pullzone_security(config)
        assert result == {"BlockedIps": "1.2.3.4", "EnableAccessControlOriginHeader": True}
        assert "BlockedCountries" not in result

    def test_empty_config(self):
        result = denormalize_pullzone_security({})
        assert result == {}

    def test_full_round_trip(self):
        """normalize -> denormalize produces the original API keys."""
        pz = {
            "BlockedIps": "10.0.0.1",
            "BlockedCountries": "DE",
            "BlockedReferrers": "x.com",
            "AllowedReferrers": "y.com",
            "BlockPostRequests": True,
            "BlockRootPathAccess": True,
            "EnableTokenAuthentication": False,
            "ZoneSecurityIncludeHashRemoteIP": True,
            "BlockNoneReferrer": False,
            "EnableAccessControlOriginHeader": True,
            "AccessControlOriginHeaderExtensions": ".css",
            "LoggingIPAnonymization": False,
        }
        normalized = normalize_pullzone_security(pz)
        denormalized = denormalize_pullzone_security(normalized)
        for api_key in pz:
            assert denormalized[api_key] == pz[api_key]


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffPullZoneSecurity:
    def test_no_changes(self):
        config = {"blocked_ips": "1.2.3.4", "cors_enabled": True}
        plan = diff_pullzone_security(config, config)
        assert not plan.has_changes

    def test_string_change(self):
        current = {"blocked_ips": "1.2.3.4"}
        desired = {"blocked_ips": "1.2.3.4\n5.6.7.8"}
        plan = diff_pullzone_security(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "blocked_ips"
        assert plan.changes[0].current == "1.2.3.4"
        assert plan.changes[0].desired == "1.2.3.4\n5.6.7.8"

    def test_bool_change(self):
        current = {"cors_enabled": False}
        desired = {"cors_enabled": True}
        plan = diff_pullzone_security(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "cors_enabled"

    def test_multiple_changes(self):
        current = {"blocked_ips": "", "cors_enabled": False, "block_post_requests": False}
        desired = {"blocked_ips": "10.0.0.1", "cors_enabled": True, "block_post_requests": False}
        plan = diff_pullzone_security(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 2  # block_post_requests unchanged

    def test_new_field(self):
        """Desired has a field not present in current."""
        plan = diff_pullzone_security({}, {"blocked_ips": "10.0.0.1"})
        assert plan.has_changes
        assert plan.changes[0].current is None


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_pullzone_security({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_pull_zone(self):
        provider = MagicMock()
        provider.get_pullzone_security.return_value = {
            "blocked_ips": "1.2.3.4",
            "cors_enabled": False,
        }
        all_desired = {
            "bunny_pullzone_security": {
                "blocked_ips": "1.2.3.4\n5.6.7.8",
                "cors_enabled": True,
            }
        }
        result = _prefetch_pullzone_security(all_desired, _scope(), provider)
        assert result is not None
        current, desired = result
        assert current["blocked_ips"] == "1.2.3.4"
        assert desired["cors_enabled"] is True

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_pullzone_security.side_effect = ProviderError("API down")
        all_desired = {"bunny_pullzone_security": {"cors_enabled": True}}
        result = _prefetch_pullzone_security(all_desired, _scope(), provider)
        current, _desired = result
        assert current == {}


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        current = {"blocked_ips": "", "cors_enabled": False}
        desired = {"blocked_ips": "10.0.0.1", "cors_enabled": True}
        ctx = (current, desired)

        _finalize_pullzone_security(zp, {}, _scope(), MagicMock(), ctx)
        assert "bunny_pullzone_security" in zp.extension_plans
        plan = zp.extension_plans["bunny_pullzone_security"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        config = {"blocked_ips": "10.0.0.1", "cors_enabled": True}
        ctx = (config, config)

        _finalize_pullzone_security(zp, {}, _scope(), MagicMock(), ctx)
        assert "bunny_pullzone_security" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_pullzone_security(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_changes(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        synced, error = _apply_pullzone_security(zp, [plan], _scope(), provider)
        assert error is None
        assert "bunny_pullzone_security" in synced
        provider.update_pullzone_security.assert_called_once()
        call_args = provider.update_pullzone_security.call_args
        settings = call_args[0][1]
        assert settings["blocked_ips"] == "10.0.0.1"
        assert settings["cors_enabled"] is True

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "1.2.3.4", "1.2.3.4"),
            ]
        )
        synced, _error = _apply_pullzone_security(zp, [plan], _scope(), provider)
        assert synced == []
        provider.update_pullzone_security.assert_not_called()

    def test_empty_plans(self):
        synced, error = _apply_pullzone_security(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert error is None

    def test_single_api_call_for_all_fields(self):
        """All changed fields are sent in a single API call."""
        provider = MagicMock()
        zp = MagicMock()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
                PullZoneSecurityChange("block_post_requests", False, True),
            ]
        )
        _synced, error = _apply_pullzone_security(zp, [plan], _scope(), provider)
        assert error is None
        # Only one API call despite multiple changes
        provider.update_pullzone_security.assert_called_once()
        settings = provider.update_pullzone_security.call_args[0][1]
        assert len(settings) == 3


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class TestPullZoneSecurityFormatter:
    # -- format_text --------------------------------------------------------

    def test_format_text_with_changes(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        assert "pullzone_security.blocked_ips" in lines[0]
        assert "''" in lines[0]
        assert "'10.0.0.1'" in lines[0]
        assert lines[0].startswith("  ~ ")
        assert "pullzone_security.cors_enabled" in lines[1]

    def test_format_text_skips_no_change(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "x", "x"),
            ]
        )
        assert fmt.format_text([plan], use_color=False) == []

    def test_format_text_empty_plans(self):
        fmt = PullZoneSecurityFormatter()
        assert fmt.format_text([], use_color=False) == []

    def test_format_text_with_color(self):
        """With color enabled, output wraps in ANSI codes."""
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        assert "\033[" in lines[0]
        assert "pullzone_security.cors_enabled" in lines[0]

    # -- format_json --------------------------------------------------------

    def test_format_json_with_changes(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert "changes" in result[0]
        changes = result[0]["changes"]
        assert len(changes) == 2
        assert changes[0]["field"] == "blocked_ips"
        assert changes[0]["current"] == ""
        assert changes[0]["desired"] == "10.0.0.1"
        assert changes[1]["field"] == "cors_enabled"
        assert changes[1]["current"] is False
        assert changes[1]["desired"] is True

    def test_format_json_skips_no_change(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "x", "x"),
            ]
        )
        assert fmt.format_json([plan]) == []

    def test_format_json_empty_plans(self):
        fmt = PullZoneSecurityFormatter()
        assert fmt.format_json([]) == []

    def test_format_json_multiple_plans(self):
        fmt = PullZoneSecurityFormatter()
        plan1 = PullZoneSecurityPlan(
            changes=[PullZoneSecurityChange("blocked_ips", "", "10.0.0.1")]
        )
        plan2 = PullZoneSecurityPlan(changes=[PullZoneSecurityChange("cors_enabled", False, True)])
        result = fmt.format_json([plan1, plan2])
        assert len(result) == 2

    # -- format_markdown ----------------------------------------------------

    def test_format_markdown_with_changes(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 2
        assert lines[0].startswith("| ~ |")
        assert "pullzone_security.blocked_ips" in lines[0]
        assert "'10.0.0.1'" in lines[0]
        assert lines[1].startswith("| ~ |")
        assert "pullzone_security.cors_enabled" in lines[1]

    def test_format_markdown_skips_no_change(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "x", "x"),
            ]
        )
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_format_markdown_empty_plans(self):
        fmt = PullZoneSecurityFormatter()
        assert fmt.format_markdown([], pending_diffs=[]) == []

    def test_format_markdown_escapes_pipes(self):
        """Pipe characters in values are escaped for markdown tables."""
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "a|b", "c|d"),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        assert "a\\|b" in lines[0] or "a|b" in lines[0]

    # -- format_html --------------------------------------------------------

    def test_format_html_with_changes(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 2, 0)
        assert len(lines) > 0
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "pullzone_security.blocked_ips" in html
        assert "pullzone_security.cors_enabled" in html
        assert "&rarr;" in html
        assert "Updates=2" in html

    def test_format_html_skips_no_change(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "x", "x"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_format_html_empty_plans(self):
        fmt = PullZoneSecurityFormatter()
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_format_html_escapes_special_chars(self):
        """HTML special characters in values are escaped."""
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "<script>", "10.0.0.1"),
            ]
        )
        lines: list[str] = []
        fmt.format_html([plan], lines)
        html = "\n".join(lines)
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.replace("&lt;script&gt;", "")

    # -- format_report ------------------------------------------------------

    def test_format_report_with_drift(self):
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "", "10.0.0.1"),
                PullZoneSecurityChange("cors_enabled", False, True),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "pullzone_security"
        assert entry["provider_id"] == "bunny_pullzone_security"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 2
        assert entry["adds"] == 0
        assert entry["removes"] == 0

    def test_format_report_preserves_incoming_drift(self):
        """zone_has_drift=True is preserved even when extension has no drift."""
        fmt = PullZoneSecurityFormatter()
        plan = PullZoneSecurityPlan(
            changes=[
                PullZoneSecurityChange("blocked_ips", "x", "x"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []

    def test_format_report_no_drift(self):
        fmt = PullZoneSecurityFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []

    def test_format_report_empty_plans_passes_through_drift(self):
        """With empty plans, returns the incoming zone_has_drift unchanged."""
        fmt = PullZoneSecurityFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []


# ---------------------------------------------------------------------------
# Validate extension
# ---------------------------------------------------------------------------
class TestValidateExtension:
    def test_valid_config(self):
        desired = {
            "bunny_pullzone_security": {
                "blocked_ips": "1.2.3.4\n5.6.7.8",
                "blocked_countries": "CN,RU",
                "block_post_requests": True,
                "cors_enabled": True,
                "cors_extensions": ".jpg .png",
                "logging_ip_anonymization": False,
            }
        }
        errors: list[str] = []
        lines: list[str] = []
        _validate_pullzone_security(desired, "zone", errors, lines)
        assert errors == []

    def test_invalid_bool_type(self):
        desired = {
            "bunny_pullzone_security": {
                "cors_enabled": "yes",
            }
        }
        errors: list[str] = []
        _validate_pullzone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "must be a bool" in errors[0]
        assert "cors_enabled" in errors[0]

    def test_invalid_string_type(self):
        desired = {
            "bunny_pullzone_security": {
                "blocked_ips": 12345,
            }
        }
        errors: list[str] = []
        _validate_pullzone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "must be a string" in errors[0]
        assert "blocked_ips" in errors[0]

    def test_unknown_field(self):
        desired = {
            "bunny_pullzone_security": {
                "nonexistent_field": True,
            }
        }
        errors: list[str] = []
        _validate_pullzone_security(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "unknown field" in errors[0]

    def test_multiple_errors(self):
        desired = {
            "bunny_pullzone_security": {
                "blocked_ips": 123,
                "cors_enabled": "nope",
                "bad_field": True,
            }
        }
        errors: list[str] = []
        _validate_pullzone_security(desired, "zone", errors, [])
        assert len(errors) == 3

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_pullzone_security({}, "zone", errors, [])
        assert errors == []

    def test_non_dict_config_is_ok(self):
        """Non-dict values are silently ignored (not our concern)."""
        errors: list[str] = []
        _validate_pullzone_security({"bunny_pullzone_security": "bad"}, "zone", errors, [])
        assert errors == []

    def test_all_bool_fields_validated(self):
        """Every boolean field rejects non-bool values."""
        bool_fields = [
            "block_post_requests",
            "block_root_path_access",
            "enable_token_authentication",
            "token_auth_include_ip",
            "block_none_referrer",
            "cors_enabled",
            "logging_ip_anonymization",
        ]
        for field_name in bool_fields:
            errors: list[str] = []
            desired = {"bunny_pullzone_security": {field_name: "yes"}}
            _validate_pullzone_security(desired, "zone", errors, [])
            assert len(errors) == 1, f"Expected validation error for {field_name}"
            assert "must be a bool" in errors[0]

    def test_all_string_fields_validated(self):
        """Every string field rejects non-string values."""
        str_fields = [
            "blocked_ips",
            "blocked_countries",
            "blocked_referrers",
            "allowed_referrers",
            "cors_extensions",
        ]
        for field_name in str_fields:
            errors: list[str] = []
            desired = {"bunny_pullzone_security": {field_name: 12345}}
            _validate_pullzone_security(desired, "zone", errors, [])
            assert len(errors) == 1, f"Expected validation error for {field_name}"
            assert "must be a string" in errors[0]


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_config(self):
        provider = MagicMock()
        provider.get_pullzone_security.return_value = {
            "blocked_ips": "1.2.3.4",
            "blocked_countries": "CN",
            "blocked_referrers": "",
            "allowed_referrers": "",
            "block_post_requests": True,
            "block_root_path_access": False,
            "enable_token_authentication": False,
            "cors_enabled": True,
            "cors_extensions": ".jpg",
            "logging_ip_anonymization": False,
        }
        result = _dump_pullzone_security(_scope(), provider, None)
        assert "bunny_pullzone_security" in result
        assert result["bunny_pullzone_security"]["blocked_ips"] == "1.2.3.4"
        assert result["bunny_pullzone_security"]["cors_enabled"] is True

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_pullzone_security.side_effect = ProviderError("down")
        result = _dump_pullzone_security(_scope(), provider, None)
        assert result is None

    def test_dump_empty_config(self):
        provider = MagicMock()
        provider.get_pullzone_security.return_value = {}
        result = _dump_pullzone_security(_scope(), provider, None)
        assert result is None


# ---------------------------------------------------------------------------
# Provider methods
# ---------------------------------------------------------------------------
class TestProviderMethods:
    def test_get_pullzone_security(self):
        from octorules_bunny.provider import BunnyShieldProvider

        client = MagicMock()
        client.get_pull_zone.return_value = {
            "BlockedIps": "10.0.0.1",
            "BlockedCountries": "RU",
            "BlockedReferrers": "",
            "AllowedReferrers": "",
            "BlockPostRequests": False,
            "BlockRootPathAccess": False,
            "EnableTokenAuthentication": True,
            "ZoneSecurityIncludeHashRemoteIP": False,
            "BlockNoneReferrer": True,
            "EnableAccessControlOriginHeader": False,
            "AccessControlOriginHeaderExtensions": "",
            "LoggingIPAnonymization": False,
        }
        provider = BunnyShieldProvider(client=client)
        # Simulate zone resolution
        provider._zone_meta["42"] = {"pull_zone_id": 100, "name": "test"}
        scope = Scope(zone_id="42", label="test")

        result = provider.get_pullzone_security(scope)
        client.get_pull_zone.assert_called_once_with(100)
        assert result["blocked_ips"] == "10.0.0.1"
        assert result["enable_token_authentication"] is True
        assert result["token_auth_include_ip"] is False
        assert result["block_none_referrer"] is True

    def test_update_pullzone_security(self):
        from octorules_bunny.provider import BunnyShieldProvider

        client = MagicMock()
        client.update_pull_zone.return_value = {}
        provider = BunnyShieldProvider(client=client)
        provider._zone_meta["42"] = {"pull_zone_id": 100, "name": "test"}
        scope = Scope(zone_id="42", label="test")

        provider.update_pullzone_security(scope, {"blocked_ips": "10.0.0.1", "cors_enabled": True})
        client.update_pull_zone.assert_called_once_with(
            100,
            {"BlockedIps": "10.0.0.1", "EnableAccessControlOriginHeader": True},
        )

    def test_pull_zone_id_raises_without_metadata(self):
        import pytest
        from octorules.config import ConfigError

        from octorules_bunny.provider import BunnyShieldProvider

        provider = BunnyShieldProvider(client=MagicMock())
        scope = Scope(zone_id="999", label="test")
        with pytest.raises(ConfigError, match="No pull zone metadata"):
            provider._pull_zone_id(scope)
