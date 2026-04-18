"""Tests for error resilience improvements."""

import logging
from unittest.mock import MagicMock, patch

from octorules_bunny._client import (
    BunnyAPIError,
    BunnyShieldClient,
    _sleep_for_retry_after,
)


class TestRetryAfterLogging:
    """Non-integer Retry-After values should be logged, not silently ignored."""

    def test_date_format_retry_after_logs_debug(self, caplog):
        """HTTP-date Retry-After should log a debug message."""
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"Retry-After": "Fri, 31 Dec 1999 23:59:59 GMT"}

        with caplog.at_level(logging.DEBUG, logger="octorules_bunny._client"):
            _sleep_for_retry_after(resp, 0)

        assert any("Retry-After" in r.message for r in caplog.records)

    def test_garbage_retry_after_logs_debug(self, caplog):
        """Completely invalid Retry-After should log a debug message."""
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"Retry-After": "not-a-number"}

        with caplog.at_level(logging.DEBUG, logger="octorules_bunny._client"):
            _sleep_for_retry_after(resp, 0)

        assert any("Retry-After" in r.message for r in caplog.records)

    def test_valid_int_retry_after_does_not_log_parse_warning(self, caplog):
        """Valid integer Retry-After should NOT log a parse warning."""
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"Retry-After": "5"}

        with caplog.at_level(logging.DEBUG, logger="octorules_bunny._client"):
            with patch("octorules_bunny._client.time.sleep"):
                _sleep_for_retry_after(resp, 0)

        # Should not have any "non-integer" or "unparseable" messages
        parse_msgs = [r for r in caplog.records if "non-integer" in r.message.lower()]
        assert len(parse_msgs) == 0


class TestNonlocalAttempt:
    """The retry closure should use nonlocal, not a mutable list."""

    def test_attempt_counter_not_list(self):
        """Verify _request doesn't use [0] list pattern (implementation detail)."""
        import inspect

        source = inspect.getsource(BunnyShieldClient._request)
        assert "attempt_num = [0]" not in source
        assert "nonlocal attempt" in source


class TestAccessListCreateResilience:
    """Access list create should log when config update step fails."""

    def test_config_update_failure_logs_warning(self, caplog):
        """When config update fails in the batched flush, a warning should appear."""
        from octorules_bunny.provider import BunnyShieldProvider

        mock_client = MagicMock(spec=BunnyShieldClient)
        mock_client.list_access_lists.return_value = [{"listId": 42, "configurationId": 99}]
        mock_client.update_access_list_config.side_effect = BunnyAPIError("Config failed")

        provider = BunnyShieldProvider(client=mock_client)
        provider._zone_meta["10"] = {"pull_zone_id": 100, "name": "test-zone"}

        with caplog.at_level(logging.WARNING, logger="octorules_bunny.provider"):
            try:
                provider._flush_access_list_configs(
                    10, [(42, {"ref": "test", "action": "block", "type": "ip"})]
                )
            except BunnyAPIError:
                pass  # expected — re-raised after logging

        assert any(
            "partial" in r.message.lower() or "config" in r.message.lower() for r in caplog.records
        )

    def test_missing_config_id_logs_warning(self, caplog):
        """When list_access_lists doesn't find the new listId, warn and skip."""
        from octorules_bunny.provider import BunnyShieldProvider

        mock_client = MagicMock(spec=BunnyShieldClient)
        # listId 42 not in the returned summaries
        mock_client.list_access_lists.return_value = [{"listId": 99, "configurationId": 123}]

        provider = BunnyShieldProvider(client=mock_client)
        provider._zone_meta["10"] = {"pull_zone_id": 100, "name": "test-zone"}

        with caplog.at_level(logging.WARNING, logger="octorules_bunny.provider"):
            provider._flush_access_list_configs(
                10, [(42, {"ref": "test", "action": "block", "type": "ip"})]
            )

        # update_access_list_config should NOT have been called
        mock_client.update_access_list_config.assert_not_called()
        assert any("configurationId" in r.message for r in caplog.records)


class TestAccessListFetchResilience:
    """Access list detail fetch should narrow exceptions and log failures."""

    def _make_provider(self, mock_client, *, max_workers=1):
        from octorules_bunny.provider import BunnyShieldProvider

        provider = BunnyShieldProvider(client=mock_client, max_workers=max_workers)
        provider._zone_meta["42"] = {"pull_zone_id": 100, "name": "test-zone"}
        return provider

    def test_access_list_fetch_failure_logs_warning(self, caplog):
        """When individual access list fetch fails, a warning should be logged."""
        from octorules.provider.base import Scope

        mock_client = MagicMock(spec=BunnyShieldClient)
        mock_client.list_custom_waf_rules.return_value = []
        mock_client.list_rate_limits.return_value = []

        # list_access_lists returns summaries, but get_access_list fails
        mock_client.list_access_lists.return_value = [
            {"listId": 1, "name": "test", "type": 0, "action": 1, "isEnabled": True}
        ]
        mock_client.get_access_list.side_effect = BunnyAPIError("Not found")

        provider = self._make_provider(mock_client)
        scope = Scope(zone_id="42", label="test-zone")

        with caplog.at_level(logging.WARNING, logger="octorules_bunny.provider"):
            result = provider.get_phase_rules(scope, "bunny_waf_access_list")

        # Should still return the summary-only fallback
        assert len(result) == 1
        # Should have logged the failure
        assert any("access list" in r.message.lower() for r in caplog.records)

    def test_parallel_fetch_returns_all(self):
        """With max_workers>1, multiple access lists are fetched concurrently."""
        from octorules.provider.base import Scope

        mock_client = MagicMock(spec=BunnyShieldClient)
        mock_client.list_access_lists.return_value = [
            {
                "listId": 1,
                "name": "list-a",
                "type": 0,
                "action": 1,
                "isEnabled": True,
                "configurationId": 10,
            },
            {
                "listId": 2,
                "name": "list-b",
                "type": 3,
                "action": 2,
                "isEnabled": True,
                "configurationId": 20,
            },
            {
                "listId": 3,
                "name": "list-c",
                "type": 1,
                "action": 1,
                "isEnabled": False,
                "configurationId": 30,
            },
        ]
        mock_client.get_access_list.side_effect = [
            {"id": 1, "name": "list-a", "type": 0, "content": "1.2.3.4"},
            {"id": 2, "name": "list-b", "type": 3, "content": "US"},
            {"id": 3, "name": "list-c", "type": 1, "content": "10.0.0.0/8"},
        ]

        provider = self._make_provider(mock_client, max_workers=4)
        scope = Scope(zone_id="42", label="test-zone")

        result = provider.get_phase_rules(scope, "bunny_waf_access_list")
        assert len(result) == 3
        refs = {r["ref"] for r in result}
        assert refs == {"list-a", "list-b", "list-c"}
        # All should have content (fetched from detail endpoint)
        assert all(r.get("content") for r in result)

    def test_parallel_fetch_graceful_on_failure(self):
        """Parallel fetch falls back to summary-only on individual failures."""
        from octorules.provider.base import Scope

        mock_client = MagicMock(spec=BunnyShieldClient)
        mock_client.list_access_lists.return_value = [
            {
                "listId": 1,
                "name": "ok",
                "type": 0,
                "action": 1,
                "isEnabled": True,
                "configurationId": 10,
            },
            {
                "listId": 2,
                "name": "fail",
                "type": 0,
                "action": 1,
                "isEnabled": True,
                "configurationId": 20,
            },
        ]
        mock_client.get_access_list.side_effect = [
            {"id": 1, "name": "ok", "type": 0, "content": "1.2.3.4"},
            BunnyAPIError("Not found"),
        ]

        provider = self._make_provider(mock_client, max_workers=4)
        scope = Scope(zone_id="42", label="test-zone")

        result = provider.get_phase_rules(scope, "bunny_waf_access_list")
        assert len(result) == 2
        # The successful one should have content
        ok_rule = next(r for r in result if r["ref"] == "ok")
        assert ok_rule["content"] == "1.2.3.4"
