"""Tests for Bunny lint rule registration (BN_RULE_METAS / BN_RULE_IDS sync)."""

from octorules.linter.plugin import get_registered_plugins

from octorules_bunny.linter import register_bunny_linter
from octorules_bunny.linter._plugin import BN_RULE_IDS
from octorules_bunny.linter._rules import BN_RULE_METAS


class TestIdempotentRegistration:
    def test_idempotent_registration(self):
        """Calling register_bunny_linter() again should be a no-op."""
        count_before = len(get_registered_plugins())
        register_bunny_linter()
        assert len(get_registered_plugins()) == count_before


class TestRuleRegistration:
    def test_all_rule_ids_start_with_bn(self):
        for meta in BN_RULE_METAS:
            assert meta.rule_id.startswith("BN"), f"{meta.rule_id} should start with BN"

    def test_rule_ids_are_unique(self):
        ids = [m.rule_id for m in BN_RULE_METAS]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {ids}"

    def test_exact_rule_count(self):
        assert len(BN_RULE_METAS) == 69, (
            f"Expected 69 rule metas, got {len(BN_RULE_METAS)}. "
            f"Update this count when adding/removing rules."
        )

    def test_metas_is_tuple(self):
        """BN_RULE_METAS must be an explicit tuple, not a globals() scan."""
        assert isinstance(BN_RULE_METAS, tuple)

    def test_plugin_rule_ids_match_metas(self):
        meta_ids = frozenset(r.rule_id for r in BN_RULE_METAS)
        assert BN_RULE_IDS == meta_ids, (
            f"BN_RULE_IDS and BN_RULE_METAS are out of sync: "
            f"missing from metas: {BN_RULE_IDS - meta_ids}, "
            f"missing from plugin: {meta_ids - BN_RULE_IDS}"
        )
