"""Performance regression tests for access list sync.

Locks in the fix that batches ``list_access_lists`` calls after creates.
Without the fix, creating N new access lists triggers N extra lookups;
with the fix, it's exactly one additional lookup regardless of N.
"""

from unittest.mock import MagicMock

from octorules.provider.base import Scope

from octorules_bunny.provider import BunnyShieldProvider


def _setup(n_existing: int):
    """Build a provider with a mock client returning *n_existing* access lists."""
    client = MagicMock()
    existing = [
        {
            "listId": i,
            "name": f"existing-{i}",
            "type": 0,
            "action": 1,
            "isEnabled": True,
            "configurationId": 1000 + i,
        }
        for i in range(n_existing)
    ]
    created_lists: list[int] = []

    def _list_side(*args, **kwargs):
        return existing + [
            {
                "listId": cl,
                "name": f"new-{idx}",
                "type": 0,
                "action": 1,
                "isEnabled": True,
                "configurationId": 5000 + cl,
            }
            for idx, cl in enumerate(created_lists)
        ]

    client.list_access_lists.side_effect = _list_side
    client.get_access_list.return_value = {"content": "1.2.3.4"}

    counter = [2000]

    def _create(*args, **kwargs):
        counter[0] += 1
        created_lists.append(counter[0])
        return {"data": {"id": counter[0]}}

    client.create_access_list.side_effect = _create

    provider = BunnyShieldProvider(client=client, max_workers=1)
    provider._zone_meta["42"] = {"pull_zone_id": 100, "name": "test"}
    return provider, client


def _run_sync(provider, n_existing: int, n_new: int):
    scope = Scope(zone_id="42", label="test")
    desired = [
        {
            "ref": f"existing-{i}",
            "type": "ip",
            "action": "block",
            "enabled": True,
            "content": f"1.2.3.{i}",
        }
        for i in range(n_existing)
    ] + [
        {
            "ref": f"new-{i}",
            "type": "ip",
            "action": "block",
            "enabled": True,
            "content": f"2.3.4.{i}",
        }
        for i in range(n_new)
    ]
    provider.put_phase_rules(scope, "bunny_waf_access_list", desired)


class TestAccessListCreateBatching:
    """``list_access_lists`` must be called at most twice regardless of new-list count."""

    def test_create_1_list_2_lookups(self):
        provider, client = _setup(n_existing=0)
        _run_sync(provider, n_existing=0, n_new=1)
        assert client.list_access_lists.call_count == 2

    def test_create_5_lists_2_lookups(self):
        provider, client = _setup(n_existing=0)
        _run_sync(provider, n_existing=0, n_new=5)
        # Before fix: 6 calls.  After fix: 2 (initial get_phase_rules + batched flush).
        assert client.list_access_lists.call_count == 2

    def test_create_10_lists_2_lookups(self):
        provider, client = _setup(n_existing=0)
        _run_sync(provider, n_existing=0, n_new=10)
        assert client.list_access_lists.call_count == 2

    def test_mixed_update_and_create_2_lookups(self):
        provider, client = _setup(n_existing=5)
        _run_sync(provider, n_existing=5, n_new=5)
        assert client.list_access_lists.call_count == 2

    def test_only_updates_1_lookup(self):
        """With zero creates, the batch-flush lookup is skipped entirely."""
        provider, client = _setup(n_existing=5)
        _run_sync(provider, n_existing=5, n_new=0)
        assert client.list_access_lists.call_count == 1

    def test_configs_applied_for_all_new_lists(self):
        """Every new list gets its action/enabled configured exactly once."""
        provider, client = _setup(n_existing=0)
        _run_sync(provider, n_existing=0, n_new=5)
        assert client.update_access_list_config.call_count == 5
