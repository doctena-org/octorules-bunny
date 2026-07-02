"""Tests for iter_provider_phases in linter plugin."""

from unittest.mock import MagicMock

from octorules.linter.helpers import iter_provider_phases

from octorules_bunny._phases import BUNNY_PHASE_NAMES


def _ctx(phase_filter=None):
    ctx = MagicMock()
    ctx.phase_filter = phase_filter
    return ctx


class TestIterPhases:
    def test_yields_bunny_phases(self):
        data = {
            "bunny_waf_custom_rules": [{"ref": "a"}],
            "bunny_waf_rate_limit_rules": [{"ref": "b"}],
        }
        results = list(iter_provider_phases(data, _ctx(), BUNNY_PHASE_NAMES))
        names = [name for name, _ in results]
        assert "bunny_waf_custom_rules" in names
        assert "bunny_waf_rate_limit_rules" in names

    def test_skips_non_bunny_phases(self):
        data = {
            "cf_waf_custom_rules": [{"ref": "a"}],
            "bunny_waf_custom_rules": [{"ref": "b"}],
        }
        results = list(iter_provider_phases(data, _ctx(), BUNNY_PHASE_NAMES))
        names = [name for name, _ in results]
        assert "cf_waf_custom_rules" not in names

    def test_skips_non_list_values(self):
        data = {
            "bunny_waf_custom_rules": "not-a-list",
        }
        results = list(iter_provider_phases(data, _ctx(), BUNNY_PHASE_NAMES))
        assert len(results) == 0

    def test_respects_phase_filter(self):
        data = {
            "bunny_waf_custom_rules": [{"ref": "a"}],
            "bunny_waf_rate_limit_rules": [{"ref": "b"}],
        }
        results = list(
            iter_provider_phases(
                data, _ctx(phase_filter={"bunny_waf_custom_rules"}), BUNNY_PHASE_NAMES
            )
        )
        names = [name for name, _ in results]
        assert "bunny_waf_custom_rules" in names
        assert "bunny_waf_rate_limit_rules" not in names

    def test_skip_suffixes(self):
        data = {
            "bunny_waf_custom_rules": [{"ref": "a"}],
            "bunny_waf_access_list_rules": [{"ref": "b"}],
            "bunny_edge_rules": [{"ref": "c"}],
        }
        results = list(
            iter_provider_phases(
                data, _ctx(), BUNNY_PHASE_NAMES, skip_suffixes=("access_list_rules", "edge_rules")
            )
        )
        names = [name for name, _ in results]
        assert "bunny_waf_custom_rules" in names
        assert "bunny_waf_access_list_rules" not in names
        assert "bunny_edge_rules" not in names

    def test_empty_data(self):
        assert list(iter_provider_phases({}, _ctx(), BUNNY_PHASE_NAMES)) == []
