"""Tests for the Bunny Shield HTTP client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from octorules_bunny._client import (
    BunnyAPIError,
    BunnyAuthError,
    BunnyShieldClient,
    _classify_http_error,
    _TransientHTTPError,
)


def _http_error(status: int) -> httpx.HTTPStatusError:
    """Build a mock HTTPStatusError with the given status code."""
    response = MagicMock()
    response.status_code = status
    return httpx.HTTPStatusError("error", request=MagicMock(), response=response)


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------
class TestClassifyHTTPError:
    def test_401_raises_auth_error(self):
        with pytest.raises(BunnyAuthError):
            _classify_http_error(_http_error(401))

    def test_403_raises_auth_error(self):
        with pytest.raises(BunnyAuthError):
            _classify_http_error(_http_error(403))

    def test_429_raises_transient(self):
        with pytest.raises(_TransientHTTPError):
            _classify_http_error(_http_error(429))

    def test_500_raises_transient(self):
        with pytest.raises(_TransientHTTPError):
            _classify_http_error(_http_error(500))

    def test_502_raises_transient(self):
        with pytest.raises(_TransientHTTPError):
            _classify_http_error(_http_error(502))

    def test_503_raises_transient(self):
        with pytest.raises(_TransientHTTPError):
            _classify_http_error(_http_error(503))

    def test_504_raises_transient(self):
        with pytest.raises(_TransientHTTPError):
            _classify_http_error(_http_error(504))

    def test_400_raises_api_error(self):
        with pytest.raises(BunnyAPIError):
            _classify_http_error(_http_error(400))

    def test_404_raises_api_error(self):
        with pytest.raises(BunnyAPIError):
            _classify_http_error(_http_error(404))

    def test_422_raises_api_error(self):
        with pytest.raises(BunnyAPIError):
            _classify_http_error(_http_error(422))


# ---------------------------------------------------------------------------
# Client construction
# ---------------------------------------------------------------------------
class TestClientInit:
    def test_creates_httpx_client(self):
        client = BunnyShieldClient("test-key")
        assert client._http is not None
        client.close()

    def test_close_closes_http(self):
        client = BunnyShieldClient("test-key")
        client.close()
        # Closing again should not raise
        client.close()

    def test_max_connections_sets_limits(self):
        """max_connections configures httpx.Limits on the HTTP client."""
        client = BunnyShieldClient("test-key", max_connections=40)
        limits = client._http._transport._pool._max_connections
        assert limits == 40
        client.close()

    def test_max_connections_keepalive(self):
        """max_keepalive_connections is half of max_connections (min 20)."""
        client = BunnyShieldClient("test-key", max_connections=40)
        keepalive = client._http._transport._pool._max_keepalive_connections
        assert keepalive == 20
        client.close()

    def test_max_connections_keepalive_small(self):
        """For small max_connections, keepalive floor is 20."""
        client = BunnyShieldClient("test-key", max_connections=20)
        keepalive = client._http._transport._pool._max_keepalive_connections
        assert keepalive == 20
        client.close()

    def test_no_max_connections_uses_defaults(self):
        """Without max_connections, httpx defaults are used."""
        client = BunnyShieldClient("test-key")
        # httpx default is 100 max connections
        assert client._http is not None
        client.close()


# ---------------------------------------------------------------------------
# Retry exhaustion
# ---------------------------------------------------------------------------
class TestRetryExhaustion:
    @patch("octorules.retry.time.sleep")
    def test_all_retries_fail(self, _mock_sleep):
        """When all retries fail, the final exception propagates."""
        client = BunnyShieldClient("key", max_retries=2)
        response = MagicMock()
        response.status_code = 429
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=response
        )
        client._http = MagicMock()
        client._http.request.return_value = response
        with pytest.raises(_TransientHTTPError):
            client._request("GET", "/test")
        assert client._http.request.call_count == 3
        client.close()


# ---------------------------------------------------------------------------
# Retry-After header support
# ---------------------------------------------------------------------------
class TestRetryAfter:
    @patch("octorules.retry.time.sleep")
    def test_retry_after_header_respected(self, mock_sleep):
        """429 with Retry-After header sleeps the extra time before backoff."""
        client = BunnyShieldClient("key", max_retries=1)

        # First response: 429 with Retry-After
        rate_response = MagicMock()
        rate_response.status_code = 429
        rate_response.headers = {"Retry-After": "5"}
        rate_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=rate_response
        )

        # Second response: success
        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.raise_for_status.return_value = None
        ok_response.json.return_value = {"ok": True}

        client._http = MagicMock()
        client._http.request.side_effect = [rate_response, ok_response]
        result = client._request("GET", "/test")
        assert result == {"ok": True}

        # First sleep: Retry-After extra (5 - 1.0 = 4.0)
        # Second sleep: normal backoff from retry_with_backoff (1.0 + jitter)
        assert mock_sleep.call_count == 2
        extra_sleep = mock_sleep.call_args_list[0][0][0]
        assert extra_sleep == 4.0
        client.close()

    @patch("octorules.retry.time.sleep")
    def test_retry_after_below_backoff_no_extra_sleep(self, mock_sleep):
        """When Retry-After is below normal backoff, no extra sleep is added."""
        client = BunnyShieldClient("key", max_retries=1)

        rate_response = MagicMock()
        rate_response.status_code = 429
        rate_response.headers = {"Retry-After": "0"}
        rate_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=rate_response
        )

        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.raise_for_status.return_value = None
        ok_response.json.return_value = {"ok": True}

        client._http = MagicMock()
        client._http.request.side_effect = [rate_response, ok_response]
        client._request("GET", "/test")
        # Only the normal backoff sleep, no extra Retry-After sleep
        assert mock_sleep.call_count == 1
        client.close()

    @patch("octorules.retry.time.sleep")
    def test_retry_after_malformed_ignored(self, mock_sleep):
        """Malformed Retry-After header is safely ignored."""
        client = BunnyShieldClient("key", max_retries=1)

        rate_response = MagicMock()
        rate_response.status_code = 429
        rate_response.headers = {"Retry-After": "not-a-number"}
        rate_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=rate_response
        )

        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.raise_for_status.return_value = None
        ok_response.json.return_value = {"ok": True}

        client._http = MagicMock()
        client._http.request.side_effect = [rate_response, ok_response]
        client._request("GET", "/test")
        # Only the normal backoff sleep, no extra Retry-After sleep
        assert mock_sleep.call_count == 1
        client.close()

    @patch("octorules.retry.time.sleep")
    def test_retry_after_capped_at_120(self, mock_sleep):
        """Huge Retry-After values are capped to 120 seconds."""
        client = BunnyShieldClient("key", max_retries=1)

        rate_response = MagicMock()
        rate_response.status_code = 429
        rate_response.headers = {"Retry-After": "9999"}
        rate_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=rate_response
        )

        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.raise_for_status.return_value = None
        ok_response.json.return_value = {"ok": True}

        client._http = MagicMock()
        client._http.request.side_effect = [rate_response, ok_response]
        client._request("GET", "/test")
        # First sleep: Retry-After extra capped: min(9999, 120) - 1.0 = 119.0
        # Second sleep: normal backoff from retry_with_backoff
        assert mock_sleep.call_count == 2
        extra_sleep = mock_sleep.call_args_list[0][0][0]
        assert extra_sleep == pytest.approx(119.0)
        client.close()


class TestJSONDecodeError:
    @patch("octorules.retry.time.sleep")
    def test_non_json_response_retried_then_wrapped(self, _mock_sleep):
        """Non-JSON 200 is retried; exhausted retries raise BunnyAPIError."""
        client = BunnyShieldClient("key", max_retries=1)
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("Expecting value")
        client._http = MagicMock()
        client._http.request.return_value = response
        with pytest.raises(BunnyAPIError, match="Non-JSON response"):
            client._request("GET", "/test")
        # 1 attempt + 1 retry = 2
        assert client._http.request.call_count == 2
        client.close()

    @patch("octorules.retry.time.sleep")
    def test_json_recovers_on_retry(self, _mock_sleep):
        """Non-JSON first response, valid JSON on retry."""
        client = BunnyShieldClient("key", max_retries=1)

        bad_response = MagicMock()
        bad_response.status_code = 200
        bad_response.raise_for_status.return_value = None
        bad_response.json.side_effect = ValueError("Expecting value")

        good_response = MagicMock()
        good_response.status_code = 200
        good_response.raise_for_status.return_value = None
        good_response.json.return_value = {"ok": True}

        client._http = MagicMock()
        client._http.request.side_effect = [bad_response, good_response]
        result = client._request("GET", "/test")
        assert result == {"ok": True}
        assert client._http.request.call_count == 2
        client.close()


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------
class TestPagination:
    @patch.object(BunnyShieldClient, "_request")
    def test_single_page(self, mock_request):
        mock_request.return_value = {
            "data": [{"id": 1}, {"id": 2}],
            "page": {"totalPages": 1, "currentPage": 1},
        }
        client = BunnyShieldClient("key")
        result = client._paginate("/test")
        assert len(result) == 2
        assert result[0]["id"] == 1
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_multi_page(self, mock_request):
        mock_request.side_effect = [
            {
                "data": [{"id": 1}],
                "page": {"totalPages": 2, "currentPage": 1},
            },
            {
                "data": [{"id": 2}],
                "page": {"totalPages": 2, "currentPage": 2},
            },
        ]
        client = BunnyShieldClient("key")
        result = client._paginate("/test")
        assert len(result) == 2
        assert result[1]["id"] == 2
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_empty_response(self, mock_request):
        mock_request.return_value = {
            "data": [],
            "page": {"totalPages": 0, "currentPage": 1},
        }
        client = BunnyShieldClient("key")
        result = client._paginate("/test")
        assert result == []
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_list_response_format(self, mock_request):
        """Some endpoints return a plain list instead of paginated dict."""
        mock_request.return_value = [{"id": 1}, {"id": 2}]
        client = BunnyShieldClient("key")
        result = client._paginate("/test")
        assert len(result) == 2
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_pascalcase_items_key(self, mock_request):
        """Pull Zone API uses PascalCase: Items, HasMoreItems, TotalItems."""
        mock_request.return_value = {
            "Items": [{"Id": 1}, {"Id": 2}],
            "HasMoreItems": False,
            "TotalItems": 2,
        }
        client = BunnyShieldClient("key")
        result = client._paginate("/pullzone")
        assert len(result) == 2
        assert result[0]["Id"] == 1
        assert result[1]["Id"] == 2
        # Single page — _request called once
        assert mock_request.call_count == 1
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_pascalcase_has_more_items_true(self, mock_request):
        """HasMoreItems=True triggers a second page fetch."""
        mock_request.side_effect = [
            {
                "Items": [{"Id": 1}],
                "HasMoreItems": True,
                "TotalItems": 2,
            },
            {
                "Items": [{"Id": 2}],
                "HasMoreItems": False,
                "TotalItems": 2,
            },
        ]
        client = BunnyShieldClient("key")
        result = client._paginate("/pullzone")
        assert len(result) == 2
        assert result[0]["Id"] == 1
        assert result[1]["Id"] == 2
        assert mock_request.call_count == 2
        client.close()


# ---------------------------------------------------------------------------
# API method delegation
# ---------------------------------------------------------------------------
class TestAPIMethods:
    @patch.object(BunnyShieldClient, "_paginate")
    def test_list_pull_zones(self, mock_paginate):
        mock_paginate.return_value = [{"Name": "cdn-1"}]
        client = BunnyShieldClient("key")
        result = client.list_pull_zones()
        assert result == [{"Name": "cdn-1"}]
        mock_paginate.assert_called_once_with("/pullzone")
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_get_shield_zone_by_pullzone(self, mock_request):
        mock_request.return_value = {"shieldZoneId": 42}
        client = BunnyShieldClient("key")
        result = client.get_shield_zone_by_pullzone(100)
        assert result["shieldZoneId"] == 42
        client.close()

    @patch.object(BunnyShieldClient, "_paginate")
    def test_list_custom_waf_rules(self, mock_paginate):
        mock_paginate.return_value = [{"id": 1, "ruleName": "test"}]
        client = BunnyShieldClient("key")
        result = client.list_custom_waf_rules(42)
        assert len(result) == 1
        mock_paginate.assert_called_once_with("/shield/waf/custom-rules/42")
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_create_custom_waf_rule(self, mock_request):
        mock_request.return_value = {"id": 10}
        client = BunnyShieldClient("key")
        result = client.create_custom_waf_rule({"ruleName": "test"})
        assert result["id"] == 10
        mock_request.assert_called_once_with(
            "POST", "/shield/waf/custom-rule", json={"ruleName": "test"}
        )
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_delete_custom_waf_rule(self, mock_request):
        mock_request.return_value = {}
        client = BunnyShieldClient("key")
        client.delete_custom_waf_rule(10)
        mock_request.assert_called_once_with("DELETE", "/shield/waf/custom-rule/10")
        client.close()

    @patch.object(BunnyShieldClient, "_paginate")
    def test_list_rate_limits(self, mock_paginate):
        mock_paginate.return_value = []
        client = BunnyShieldClient("key")
        client.list_rate_limits(42)
        mock_paginate.assert_called_once_with("/shield/rate-limits/42")
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_list_access_lists_custom_lists(self, mock_request):
        """API returns {customLists: [...], managedLists: [...]}."""
        mock_request.return_value = {
            "customLists": [{"listId": 1, "name": "test"}],
            "managedLists": [{"listId": 99}],
        }
        client = BunnyShieldClient("key")
        result = client.list_access_lists(42)
        assert result == [{"listId": 1, "name": "test"}]
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_list_access_lists_empty(self, mock_request):
        """API returns no custom lists."""
        mock_request.return_value = {"customLists": [], "managedLists": []}
        client = BunnyShieldClient("key")
        result = client.list_access_lists(42)
        assert result == []
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_list_access_lists_fallback_list(self, mock_request):
        """Handle unexpected flat list response gracefully."""
        mock_request.return_value = [{"id": 1}]
        client = BunnyShieldClient("key")
        result = client.list_access_lists(42)
        assert result == [{"id": 1}]
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_get_bot_detection(self, mock_request):
        mock_request.return_value = {"executionMode": 2}
        client = BunnyShieldClient("key")
        result = client.get_bot_detection(42)
        assert result["executionMode"] == 2
        client.close()

    @patch.object(BunnyShieldClient, "_request")
    def test_update_bot_detection(self, mock_request):
        mock_request.return_value = {}
        client = BunnyShieldClient("key")
        client.update_bot_detection(42, {"executionMode": 1})
        mock_request.assert_called_once_with(
            "PATCH",
            "/shield/shield-zone/42/bot-detection",
            json={"executionMode": 1},
        )
        client.close()
