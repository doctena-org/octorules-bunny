"""Tests for curated threat lists (managed access lists)."""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_bunny._config_base import ConfigPlan
from octorules_bunny._curated_lists import (
    diff_curated_lists,
    normalize_curated_lists,
)


def _scope(zone_id="42"):
    return Scope(zone_id=zone_id, label="test-zone")


SAMPLE_MANAGED = [
    {
        "listId": 1,
        "configurationId": 100,
        "name": "VPN Providers",
        "isEnabled": False,
        "action": 4,
        "requiredPlan": 1,
        "entryCount": 10000,
    },
    {
        "listId": 3,
        "configurationId": 102,
        "name": "TOR Exit Nodes",
        "isEnabled": True,
        "action": 2,
        "requiredPlan": 1,
        "entryCount": 2000,
    },
    {
        "listId": 2,
        "configurationId": 101,
        "name": "Common Datacenters",
        "isEnabled": False,
        "action": 4,
        "requiredPlan": 1,
        "entryCount": 900,
    },
]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
class TestNormalize:
    def test_produces_dict_keyed_by_name(self):
        result = normalize_curated_lists(SAMPLE_MANAGED)
        assert "VPN Providers" in result
        assert "TOR Exit Nodes" in result
        assert "Common Datacenters" in result

    def test_normalizes_action_to_string(self):
        result = normalize_curated_lists(SAMPLE_MANAGED)
        assert result["VPN Providers"]["action"] == "log"  # 4 = log
        assert result["TOR Exit Nodes"]["action"] == "block"  # 2 = block

    def test_normalizes_enabled(self):
        result = normalize_curated_lists(SAMPLE_MANAGED)
        assert result["VPN Providers"]["enabled"] is False
        assert result["TOR Exit Nodes"]["enabled"] is True

    def test_preserves_config_id(self):
        result = normalize_curated_lists(SAMPLE_MANAGED)
        assert result["VPN Providers"]["_config_id"] == 100

    def test_empty_input(self):
        assert normalize_curated_lists([]) == {}


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_detects_enable_change(self):
        current = normalize_curated_lists(SAMPLE_MANAGED)
        desired = {"VPN Providers": {"enabled": True, "action": "block"}}
        plan = diff_curated_lists(current, desired)
        assert plan.has_changes
        names = {c.field for c in plan.changes if c.has_changes}
        assert "VPN Providers" in names

    def test_detects_action_change(self):
        current = normalize_curated_lists(SAMPLE_MANAGED)
        desired = {"TOR Exit Nodes": {"enabled": True, "action": "challenge"}}
        plan = diff_curated_lists(current, desired)
        assert plan.has_changes

    def test_no_changes(self):
        current = normalize_curated_lists(SAMPLE_MANAGED)
        desired = {
            "TOR Exit Nodes": {"enabled": True, "action": "block"},
        }
        plan = diff_curated_lists(current, desired)
        assert not plan.has_changes

    def test_unknown_list_ignored(self):
        """Desired list not in managed lists produces no crash."""
        current = normalize_curated_lists(SAMPLE_MANAGED)
        desired = {"Nonexistent List": {"enabled": True, "action": "block"}}
        plan = diff_curated_lists(current, desired)
        # No changes since the list doesn't exist on the API side
        assert not plan.has_changes

    def test_only_desired_lists_diffed(self):
        """Lists not in desired YAML are not included in the diff."""
        current = normalize_curated_lists(SAMPLE_MANAGED)
        desired = {"VPN Providers": {"enabled": True, "action": "log"}}
        plan = diff_curated_lists(current, desired)
        # VPN Providers: enabled changed False->True, action unchanged (log)
        assert plan.has_changes
        fields = {c.field for c in plan.changes}
        assert "TOR Exit Nodes" not in fields
        assert "Common Datacenters" not in fields


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
class TestValidate:
    def test_valid_config(self):
        from octorules_bunny._curated_lists import _validate_curated_lists

        desired = {
            "bunny_curated_threat_lists": {
                "VPN Providers": {"enabled": True, "action": "block"},
                "TOR Exit Nodes": {"enabled": False, "action": "log"},
            }
        }
        errors: list[str] = []
        _validate_curated_lists(desired, "zone", errors, [])
        assert errors == []

    def test_invalid_action(self):
        from octorules_bunny._curated_lists import _validate_curated_lists

        desired = {
            "bunny_curated_threat_lists": {
                "VPN Providers": {"enabled": True, "action": "nuke"},
            }
        }
        errors: list[str] = []
        _validate_curated_lists(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "action" in errors[0]

    def test_invalid_enabled_type(self):
        from octorules_bunny._curated_lists import _validate_curated_lists

        desired = {
            "bunny_curated_threat_lists": {
                "VPN Providers": {"enabled": "yes", "action": "block"},
            }
        }
        errors: list[str] = []
        _validate_curated_lists(desired, "zone", errors, [])
        assert len(errors) == 1
        assert "enabled" in errors[0]

    def test_non_dict_entry(self):
        from octorules_bunny._curated_lists import _validate_curated_lists

        desired = {"bunny_curated_threat_lists": {"VPN Providers": "block"}}
        errors: list[str] = []
        _validate_curated_lists(desired, "zone", errors, [])
        assert len(errors) == 1


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------
class TestApply:
    def test_applies_config_changes(self):
        from octorules_bunny._config_base import ConfigChange
        from octorules_bunny._curated_lists import _apply_curated_lists

        plan = ConfigPlan(
            changes=[
                ConfigChange(
                    section="curated_threat_lists",
                    field="VPN Providers",
                    current={"enabled": False, "action": "log", "_config_id": 100},
                    desired={"enabled": True, "action": "block"},
                ),
            ]
        )
        provider = MagicMock()
        zp = MagicMock()
        synced, error = _apply_curated_lists(zp, [plan], _scope(), provider)
        assert error is None
        assert len(synced) > 0
        # Should call update_access_list_config with the right config_id
        provider.update_curated_list_config.assert_called_once()
        call_args = provider.update_curated_list_config.call_args
        assert call_args[0][1] == 100  # config_id
        payload = call_args[0][2]
        assert payload["isEnabled"] is True
        assert payload["action"] == 2  # block

    def test_skips_no_changes(self):
        from octorules_bunny._curated_lists import _apply_curated_lists

        plan = ConfigPlan(changes=[])
        provider = MagicMock()
        synced, _error = _apply_curated_lists(MagicMock(), [plan], _scope(), provider)
        assert synced == []
