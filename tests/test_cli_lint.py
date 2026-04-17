"""Tests for the 'octorules lint' CLI command against Bunny rules."""

from pathlib import Path

import pytest
from octorules.commands import cmd_lint
from octorules.config import Config

# Importing the package registers the Bunny lint plugin.
import octorules_bunny  # noqa: F401


@pytest.fixture
def lint_config(tmp_path):
    """Create a minimal config + two rules files (valid + invalid) for lint testing."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "my-cdn.yaml").write_text(
        "bunny_waf_custom_rules:\n"
        "  - ref: Block admin\n"
        "    action: block\n"
        "    severity: info\n"
        "    description: Admin path guard\n"
        "    conditions:\n"
        "      - variable: request_uri\n"
        "        operator: contains\n"
        "        value: /admin\n"
    )

    # Missing ref (BN001) + missing operator (BN401).
    (rules_dir / "bad-cdn.yaml").write_text(
        "bunny_waf_custom_rules:\n"
        "  - action: block\n"
        "    conditions:\n"
        "      - variable: request_uri\n"
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  bunny:\n"
        "    api_key: test-key\n"
        "    plan: advanced\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  my-cdn:\n"
        "    sources:\n"
        "      - rules\n"
        "  bad-cdn:\n"
        "    sources:\n"
        "      - rules\n"
    )

    return Config.from_file(config_file)


class TestCmdLint:
    def test_valid_rules_exit_0(self, lint_config):
        rc = cmd_lint(lint_config, ["my-cdn"])
        assert rc == 0

    def test_invalid_rules_exit_1(self, lint_config):
        rc = cmd_lint(lint_config, ["bad-cdn"])
        assert rc == 1

    def test_severity_filter_errors_only(self, lint_config):
        rc = cmd_lint(lint_config, ["bad-cdn"], lint_severity="error")
        assert rc == 1

    def test_rule_filter_bn001(self, lint_config):
        rc = cmd_lint(lint_config, ["bad-cdn"], lint_rules=["BN001"])
        assert rc == 1

    def test_rule_filter_unrelated_rule_passes(self, lint_config):
        # Filter to a rule ID not triggered by the fixture → exit 0.
        rc = cmd_lint(lint_config, ["bad-cdn"], lint_rules=["BN600"])
        assert rc == 0

    def test_json_format_emits_rule_ids(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-cdn"], lint_format="json")
        out = capsys.readouterr().out
        assert '"rule_id"' in out
        assert "BN001" in out

    def test_sarif_format_emits_version(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-cdn"], lint_format="sarif")
        out = capsys.readouterr().out
        assert '"version": "2.1.0"' in out

    def test_output_file_written(self, lint_config, tmp_path):
        out_file = tmp_path / "lint-report.txt"
        cmd_lint(lint_config, ["bad-cdn"], output_file=str(out_file))
        assert out_file.exists()
        assert "BN001" in out_file.read_text()

    def test_phase_filter_skips_unrelated_phase(self, lint_config):
        rc = cmd_lint(
            lint_config,
            ["bad-cdn"],
            phase_filter=["bunny_waf_rate_limit_rules"],
        )
        # bad-cdn.yaml has no rate-limit rules, so nothing to lint → 0.
        assert rc == 0

    def test_plan_tier_basic_does_not_crash(self, lint_config):
        rc = cmd_lint(lint_config, ["my-cdn"], lint_plan="basic")
        assert rc == 0

    def test_plan_tier_enterprise_does_not_crash(self, lint_config):
        rc = cmd_lint(lint_config, ["my-cdn"], lint_plan="enterprise")
        assert rc == 0


class TestZonePlanResolution:
    def test_explicit_plan_overrides_zone_plans(self, lint_config):
        rc = cmd_lint(
            lint_config,
            ["my-cdn"],
            lint_plan="basic",
            zone_plans={"my-cdn": "enterprise"},
        )
        assert rc == 0

    def test_zone_plans_used_when_lint_plan_none(self, lint_config):
        rc = cmd_lint(
            lint_config,
            ["my-cdn"],
            lint_plan=None,
            zone_plans={"my-cdn": "business"},
        )
        assert rc == 0

    def test_fallback_when_no_plan_info(self, lint_config):
        rc = cmd_lint(lint_config, ["my-cdn"], lint_plan=None, zone_plans={})
        assert rc == 0


class TestBunnyRulesRegistered:
    """Lint plugin must be registered once the package is imported."""

    def test_bn_rules_known(self):
        from octorules.linter.engine import get_known_rule_ids

        known = get_known_rule_ids()
        assert "BN001" in known
        assert "BN501" in known
        assert "BN712" in known

    def test_known_rule_count_matches_metas(self):
        from octorules.linter.engine import get_known_rule_ids

        from octorules_bunny.linter._rules import BN_RULE_METAS

        known = get_known_rule_ids()
        bn_known = {r for r in known if r.startswith("BN")}
        assert bn_known == {m.rule_id for m in BN_RULE_METAS}


def _write_config(tmp_path: Path, rules_body: str) -> Config:
    """Build a one-zone Config pointing at an ephemeral rules file."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "zone.yaml").write_text(rules_body)
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  bunny:\n"
        "    api_key: test-key\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  zone:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return Config.from_file(config_file)


class TestSuppressionsHonored:
    def test_octorules_disable_suppresses_bn001(self, tmp_path):
        cfg = _write_config(
            tmp_path,
            "bunny_waf_custom_rules:\n"
            "  # octorules:disable=BN001\n"
            "  - action: block\n"
            "    conditions:\n"
            "      - variable: request_uri\n"
            "        operator: contains\n"
            "        value: /x\n",
        )
        rc = cmd_lint(cfg, ["zone"])
        # BN001 is suppressed; remaining findings (if any) are not errors here.
        assert rc == 0
