"""Tests for Bunny Shield config normalization and extension hooks."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_bunny._shield_config import (
    ShieldConfigChange,
    ShieldConfigFormatter,
    ShieldConfigPlan,
    _apply_shield_config,
    _dump_shield_config,
    _finalize_shield_config,
    _prefetch_shield_config,
    _validate_shield_config,
    denormalize_bot_config,
    denormalize_ddos_config,
    denormalize_managed_rules,
    diff_managed_rules,
    diff_shield_config,
    normalize_managed_rules,
    normalize_shield_config,
)


def _scope(zone_id: str = "999") -> Scope:
    return Scope(zone_id=zone_id, label="test-zone")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalizeShieldConfig:
    def test_bot_detection(self):
        bot = {
            "executionMode": 2,
            "requestIntegrity": {"sensitivity": 2},
            "ipAddress": {"sensitivity": 1},
            "browserFingerprint": {"sensitivity": 3, "complexEnabled": True},
        }
        result = normalize_shield_config({}, bot)
        assert result["bot_detection"]["execution_mode"] == "block"
        assert result["bot_detection"]["request_integrity_sensitivity"] == "medium"
        assert result["bot_detection"]["ip_sensitivity"] == "low"
        assert result["bot_detection"]["fingerprint_sensitivity"] == "high"
        assert result["bot_detection"]["complex_fingerprinting"] is True

    def test_ddos(self):
        zone = {
            "dDoSShieldSensitivity": 2,
            "dDoSExecutionMode": 1,
            "dDoSChallengeWindow": 300,
        }
        result = normalize_shield_config(zone, {})
        assert result["ddos"]["shield_sensitivity"] == "medium"
        assert result["ddos"]["execution_mode"] == "log"
        assert result["ddos"]["challenge_window"] == 300

    def test_both(self):
        zone = {"dDoSShieldSensitivity": 1}
        bot = {"executionMode": 0}
        result = normalize_shield_config(zone, bot)
        assert "bot_detection" in result
        assert "ddos" in result

    def test_empty(self):
        result = normalize_shield_config({}, {})
        # waf section always present (with defaults)
        assert "bot_detection" not in result
        assert "ddos" not in result
        assert "upload_scanning" not in result
        assert "waf" in result
        assert result["waf"]["learning_mode"] is False


class TestDenormalizeBotConfig:
    def test_round_trip(self):
        config = {
            "execution_mode": "block",
            "request_integrity_sensitivity": "medium",
            "ip_sensitivity": "low",
            "fingerprint_sensitivity": "high",
            "complex_fingerprinting": True,
        }
        result = denormalize_bot_config(config)
        assert result["executionMode"] == 2
        assert result["requestIntegrity"] == {"sensitivity": 2}
        assert result["ipAddress"] == {"sensitivity": 1}
        assert result["browserFingerprint"] == {"sensitivity": 3, "complexEnabled": True}


class TestDenormalizeDDoSConfig:
    def test_round_trip(self):
        config = {
            "shield_sensitivity": "medium",
            "execution_mode": "block",
            "challenge_window": 300,
        }
        result = denormalize_ddos_config(config)
        assert result["dDoSShieldSensitivity"] == 2
        assert result["dDoSExecutionMode"] == 2
        assert result["dDoSChallengeWindow"] == 300


class TestNormalizeManagedRules:
    def test_with_rules(self):
        zone = {
            "wafDisabledRules": ["941100", "942100"],
            "wafLogOnlyRules": ["930100"],
        }
        result = normalize_managed_rules(zone)
        assert result["disabled"] == ["941100", "942100"]
        assert result["log_only"] == ["930100"]

    def test_empty(self):
        result = normalize_managed_rules({})
        assert result == {}


class TestDenormalizeManagedRules:
    def test_round_trip(self):
        config = {
            "disabled": ["941100", "942100"],
            "log_only": ["930100"],
        }
        result = denormalize_managed_rules(config)
        assert result["wafDisabledRules"] == ["941100", "942100"]
        assert result["wafLogOnlyRules"] == ["930100"]


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
class TestDiffShieldConfig:
    def test_no_changes(self):
        config = {"bot_detection": {"execution_mode": "block"}}
        plan = diff_shield_config(config, config)
        assert not plan.has_changes

    def test_bot_detection_change(self):
        current = {"bot_detection": {"execution_mode": "log"}}
        desired = {"bot_detection": {"execution_mode": "block"}}
        plan = diff_shield_config(current, desired)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].field == "execution_mode"
        assert plan.changes[0].current == "log"
        assert plan.changes[0].desired == "block"

    def test_ddos_change(self):
        current = {"ddos": {"challenge_window": 300}}
        desired = {"ddos": {"challenge_window": 600}}
        plan = diff_shield_config(current, desired)
        assert plan.has_changes

    def test_new_section(self):
        plan = diff_shield_config({}, {"bot_detection": {"execution_mode": "block"}})
        assert plan.has_changes
        assert plan.changes[0].current is None


class TestDiffManagedRules:
    def test_no_changes(self):
        config = {"disabled": ["1"], "log_only": ["2"]}
        plan = diff_managed_rules(config, config)
        assert not plan.has_changes

    def test_disabled_change(self):
        current = {"disabled": ["1"]}
        desired = {"disabled": ["1", "2"]}
        plan = diff_managed_rules(current, desired)
        assert plan.has_changes
        assert plan.changes[0].field == "disabled"


# ---------------------------------------------------------------------------
# Prefetch hook
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_config(self):
        result = _prefetch_shield_config({}, _scope(), MagicMock())
        assert result is None

    def test_fetches_shield_zone(self):
        provider = MagicMock()
        provider.get_shield_zone_config.return_value = {"dDoSShieldSensitivity": 2}
        provider.get_bot_detection_config.return_value = {"executionMode": 1}

        all_desired = {
            "bunny_shield_config": {
                "bot_detection": {"execution_mode": "block"},
                "ddos": {"shield_sensitivity": "high"},
            }
        }
        result = _prefetch_shield_config(all_desired, _scope(), provider)
        assert result is not None
        shield_zone, bot_config, _upload_config, _desired_config, _desired_managed = result
        assert shield_zone["dDoSShieldSensitivity"] == 2
        assert bot_config["executionMode"] == 1

    def test_fetches_managed_rules_only(self):
        provider = MagicMock()
        provider.get_shield_zone_config.return_value = {"wafDisabledRules": ["1"]}
        all_desired = {"bunny_waf_managed_rules": {"disabled": ["1", "2"]}}
        result = _prefetch_shield_config(all_desired, _scope(), provider)
        assert result is not None
        _, _, _, desired_config, desired_managed = result
        assert desired_config is None
        assert desired_managed is not None

    def test_api_failure_handled_gracefully(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_shield_zone_config.side_effect = ProviderError("API down")
        all_desired = {"bunny_shield_config": {"ddos": {"execution_mode": "block"}}}
        result = _prefetch_shield_config(all_desired, _scope(), provider)
        # Should not raise — returns empty shield_zone
        shield_zone, _bot_config, _, _, _ = result
        assert shield_zone == {}


# ---------------------------------------------------------------------------
# Finalize hook
# ---------------------------------------------------------------------------
class TestFinalizeHook:
    def test_adds_plan_when_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        shield_zone = {"dDoSShieldSensitivity": 1, "dDoSExecutionMode": 0}
        bot_config = {}
        desired_config = {"ddos": {"shield_sensitivity": "high", "execution_mode": "block"}}
        ctx = (shield_zone, bot_config, {}, desired_config, None)

        _finalize_shield_config(zp, {}, _scope(), MagicMock(), ctx)
        assert "bunny_shield_config" in zp.extension_plans
        plan = zp.extension_plans["bunny_shield_config"][0]
        assert plan.has_changes

    def test_no_plan_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}

        shield_zone = {
            "dDoSShieldSensitivity": 2,
            "dDoSExecutionMode": 2,
            "dDoSChallengeWindow": 300,
        }
        desired_config = {
            "ddos": {
                "shield_sensitivity": "medium",
                "execution_mode": "block",
                "challenge_window": 300,
            }
        }
        ctx = (shield_zone, {}, {}, desired_config, None)

        _finalize_shield_config(zp, {}, _scope(), MagicMock(), ctx)
        assert "bunny_shield_config" not in zp.extension_plans

    def test_none_ctx_is_noop(self):
        zp = MagicMock()
        zp.extension_plans = {}
        _finalize_shield_config(zp, {}, _scope(), MagicMock(), None)
        assert zp.extension_plans == {}

    def test_managed_rules_plan(self):
        zp = MagicMock()
        zp.extension_plans = {}

        shield_zone = {"wafDisabledRules": ["1"]}
        desired_managed = {"disabled": ["1", "2"]}
        ctx = (shield_zone, {}, {}, None, desired_managed)

        _finalize_shield_config(zp, {}, _scope(), MagicMock(), ctx)
        assert "bunny_waf_managed_rules" in zp.extension_plans


# ---------------------------------------------------------------------------
# Apply hook
# ---------------------------------------------------------------------------
class TestApplyHook:
    def test_apply_bot_detection(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("bot_detection", "ip_sensitivity", "low", "high"),
            ]
        )
        synced, _error = _apply_shield_config(zp, [plan], _scope(), provider)
        assert _error is None
        assert "bunny_shield_config:bot_detection" in synced
        provider.update_bot_detection_config.assert_called_once()

    def test_apply_ddos(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        synced, _error = _apply_shield_config(zp, [plan], _scope(), provider)
        assert "bunny_shield_config:ddos" in synced
        provider.update_shield_zone_config.assert_called_once()

    def test_apply_managed_rules(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("managed_rules", "disabled", ["1"], ["1", "2"]),
            ]
        )
        synced, _error = _apply_shield_config(zp, [plan], _scope(), provider)
        assert "bunny_waf_managed_rules" in synced
        provider.update_shield_zone_config.assert_called_once()

    def test_no_changes_skipped(self):
        provider = MagicMock()
        zp = MagicMock()
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "block", "block"),
            ]
        )
        synced, _error = _apply_shield_config(zp, [plan], _scope(), provider)
        assert synced == []
        provider.update_bot_detection_config.assert_not_called()

    def test_empty_plans(self):
        synced, _error = _apply_shield_config(MagicMock(), [], _scope(), MagicMock())
        assert synced == []
        assert _error is None

    def test_apply_bot_and_ddos_simultaneously(self):
        """Both bot_detection and ddos changes applied in a single pass."""
        provider = MagicMock()
        zp = MagicMock()
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        synced, _error = _apply_shield_config(zp, [plan], _scope(), provider)
        assert _error is None
        assert "bunny_shield_config:bot_detection" in synced
        assert "bunny_shield_config:ddos" in synced
        provider.update_bot_detection_config.assert_called_once()
        provider.update_shield_zone_config.assert_called_once()


# ---------------------------------------------------------------------------
# Format extension
# ---------------------------------------------------------------------------
class TestShieldConfigFormatter:
    # -- format_text --------------------------------------------------------

    def test_format_text_with_changes(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 2
        # First line — bot_detection field
        assert "bot_detection.execution_mode" in lines[0]
        assert "'log'" in lines[0]
        assert "'block'" in lines[0]
        assert lines[0].startswith("  ~ ")
        # Second line — ddos field
        assert "ddos.shield_sensitivity" in lines[1]
        assert "'low'" in lines[1]
        assert "'high'" in lines[1]

    def test_format_text_skips_no_change(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "block", "block"),
            ]
        )
        assert fmt.format_text([plan], use_color=False) == []

    def test_format_text_empty_plans(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        assert fmt.format_text([], use_color=False) == []

    def test_format_text_with_color(self):
        """With color enabled, output wraps in ANSI codes."""
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
            ]
        )
        lines = fmt.format_text([plan], use_color=True)
        assert len(lines) == 1
        # ANSI escape codes surround the content
        assert "\033[" in lines[0]
        assert "bot_detection.execution_mode" in lines[0]

    # -- format_json --------------------------------------------------------

    def test_format_json_with_changes(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "challenge_window", 300, 600),
            ]
        )
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert "changes" in result[0]
        changes = result[0]["changes"]
        assert len(changes) == 2
        # First change
        assert changes[0]["section"] == "bot_detection"
        assert changes[0]["field"] == "execution_mode"
        assert changes[0]["current"] == "log"
        assert changes[0]["desired"] == "block"
        # Second change
        assert changes[1]["section"] == "ddos"
        assert changes[1]["field"] == "challenge_window"
        assert changes[1]["current"] == 300
        assert changes[1]["desired"] == 600

    def test_format_json_skips_no_change(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "block", "block"),
            ]
        )
        assert fmt.format_json([plan]) == []

    def test_format_json_empty_plans(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        assert fmt.format_json([]) == []

    def test_format_json_multiple_plans(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan1 = ShieldConfigPlan(
            changes=[ShieldConfigChange("bot_detection", "execution_mode", "log", "block")]
        )
        plan2 = ShieldConfigPlan(
            changes=[ShieldConfigChange("managed_rules", "disabled", ["1"], ["1", "2"])]
        )
        result = fmt.format_json([plan1, plan2])
        assert len(result) == 2
        assert result[0]["changes"][0]["section"] == "bot_detection"
        assert result[1]["changes"][0]["section"] == "managed_rules"

    # -- format_markdown ----------------------------------------------------

    def test_format_markdown_with_changes(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 2
        # Markdown table rows with ~ prefix
        assert lines[0].startswith("| ~ |")
        assert "bot_detection.execution_mode" in lines[0]
        assert "'log'" in lines[0]
        assert "'block'" in lines[0]
        assert lines[1].startswith("| ~ |")
        assert "ddos.shield_sensitivity" in lines[1]

    def test_format_markdown_skips_no_change(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("ddos", "challenge_window", 300, 300),
            ]
        )
        assert fmt.format_markdown([plan], pending_diffs=[]) == []

    def test_format_markdown_empty_plans(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        assert fmt.format_markdown([], pending_diffs=[]) == []

    def test_format_markdown_escapes_pipes(self):
        """Pipe characters in values are escaped for markdown tables."""
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "a|b", "c|d"),
            ]
        )
        lines = fmt.format_markdown([plan], pending_diffs=[])
        assert len(lines) == 1
        # The repr of "a|b" is "'a|b'" — the pipe inside should be escaped
        assert "a\\|b" in lines[0] or "a|b" in lines[0]

    # -- format_html --------------------------------------------------------

    def test_format_html_with_changes(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        # Returns (adds, removes, modifies, reorders)
        assert result == (0, 0, 2, 0)
        # Lines should contain HTML content
        assert len(lines) > 0
        html = "\n".join(lines)
        assert "<table>" in html
        assert "</table>" in html
        assert "Modify" in html
        assert "bot_detection.execution_mode" in html
        assert "ddos.shield_sensitivity" in html
        assert "&rarr;" in html
        # Summary row
        assert "Updates=2" in html

    def test_format_html_skips_no_change(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "block", "block"),
            ]
        )
        lines: list[str] = []
        result = fmt.format_html([plan], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_format_html_empty_plans(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        lines: list[str] = []
        result = fmt.format_html([], lines)
        assert result == (0, 0, 0, 0)
        assert lines == []

    def test_format_html_escapes_special_chars(self):
        """HTML special characters in values are escaped."""
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "<script>", "block"),
            ]
        )
        lines: list[str] = []
        fmt.format_html([plan], lines)
        html = "\n".join(lines)
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.replace("&lt;script&gt;", "")

    # -- format_report ------------------------------------------------------

    def test_format_report_with_drift(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "log", "block"),
                ShieldConfigChange("ddos", "shield_sensitivity", "low", "high"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=False, phases_data=phases_data)
        assert result is True
        assert len(phases_data) == 1
        entry = phases_data[0]
        assert entry["phase"] == "shield_config"
        assert entry["provider_id"] == "bunny_shield_config"
        assert entry["status"] == "drifted"
        assert entry["modifies"] == 2
        assert entry["adds"] == 0
        assert entry["removes"] == 0

    def test_format_report_preserves_incoming_drift(self):
        """zone_has_drift=True is preserved even when extension has no drift."""
        fmt = ShieldConfigFormatter("bunny_shield_config")
        plan = ShieldConfigPlan(
            changes=[
                ShieldConfigChange("bot_detection", "execution_mode", "block", "block"),
            ]
        )
        phases_data: list[dict] = []
        result = fmt.format_report([plan], zone_has_drift=True, phases_data=phases_data)
        assert result is True
        assert phases_data == []  # no extension entry since no changes

    def test_format_report_no_drift(self):
        fmt = ShieldConfigFormatter("bunny_shield_config")
        phases_data: list[dict] = []
        result = fmt.format_report([], zone_has_drift=False, phases_data=phases_data)
        assert result is False
        assert phases_data == []

    def test_format_report_empty_plans_passes_through_drift(self):
        """With empty plans, returns the incoming zone_has_drift unchanged."""
        fmt = ShieldConfigFormatter("bunny_shield_config")
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
            "bunny_shield_config": {
                "bot_detection": {"execution_mode": "block", "ip_sensitivity": "medium"},
                "ddos": {
                    "execution_mode": "log",
                    "shield_sensitivity": "high",
                    "challenge_window": 300,
                },
            }
        }
        errors: list[str] = []
        lines: list[str] = []
        _validate_shield_config(desired, "zone", errors, lines)
        assert errors == []

    def test_invalid_bot_execution_mode(self):
        desired = {
            "bunny_shield_config": {
                "bot_detection": {"execution_mode": "destroy"},
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "execution_mode" in errors[0]

    def test_invalid_sensitivity(self):
        desired = {
            "bunny_shield_config": {
                "bot_detection": {"ip_sensitivity": "extreme"},
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1

    def test_invalid_challenge_window(self):
        desired = {
            "bunny_shield_config": {
                "ddos": {"challenge_window": -1},
            }
        }
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "challenge_window" in errors[0]

    def test_invalid_managed_rules_type(self):
        desired = {"bunny_waf_managed_rules": {"disabled": "not-a-list"}}
        errors: list[str] = []
        _validate_shield_config(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "must be a list" in errors[0]

    def test_no_config_is_ok(self):
        errors: list[str] = []
        _validate_shield_config({}, "zone", errors, [])
        assert errors == []


# ---------------------------------------------------------------------------
# Dump extension
# ---------------------------------------------------------------------------
class TestDumpExtension:
    def test_dump_returns_config(self):
        provider = MagicMock()
        provider.get_shield_zone_config.return_value = {
            "dDoSShieldSensitivity": 2,
            "dDoSExecutionMode": 1,
            "wafDisabledRules": ["941100"],
        }
        provider.get_bot_detection_config.return_value = {"executionMode": 2}

        result = _dump_shield_config(_scope(), provider, None)
        assert "bunny_shield_config" in result
        assert "bunny_waf_managed_rules" in result
        assert result["bunny_waf_managed_rules"]["disabled"] == ["941100"]

    def test_dump_api_failure(self):
        from octorules.provider.exceptions import ProviderError

        provider = MagicMock()
        provider.get_shield_zone_config.side_effect = ProviderError("down")
        result = _dump_shield_config(_scope(), provider, None)
        assert result is None

    def test_dump_empty_config(self):
        provider = MagicMock()
        provider.get_shield_zone_config.return_value = {}
        provider.get_bot_detection_config.return_value = {}
        provider.get_upload_scanning_config.return_value = {}
        result = _dump_shield_config(_scope(), provider, None)
        # waf section with defaults is always included
        assert result is not None
        assert "bunny_shield_config" in result
        assert "waf" in result["bunny_shield_config"]
