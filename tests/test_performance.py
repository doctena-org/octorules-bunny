"""Tests for performance improvements."""

from octorules_bunny._client import _extract_page
from octorules_bunny.validate import _PRIVATE_V4, _PRIVATE_V6, _is_private_ip


class TestPrivateRangePartitioning:
    """Private ranges should be partitioned by IP version for faster lookup."""

    def test_v4_ranges_exist(self):
        assert len(_PRIVATE_V4) > 0
        assert all(n.version == 4 for n, _ in _PRIVATE_V4)

    def test_v6_ranges_exist(self):
        assert len(_PRIVATE_V6) > 0
        assert all(n.version == 6 for n, _ in _PRIVATE_V6)

    def test_total_count_matches(self):
        """All private ranges should be in exactly one partition."""
        from octorules_bunny.validate import _PRIVATE_RANGES

        assert len(_PRIVATE_V4) + len(_PRIVATE_V6) == len(_PRIVATE_RANGES)

    def test_ipv4_lookup_uses_v4_pool(self):
        """IPv4 private check should work correctly."""
        assert _is_private_ip("10.0.0.1") is not None
        assert _is_private_ip("192.168.1.0/24") is not None

    def test_ipv6_lookup_uses_v6_pool(self):
        """IPv6 private check should work correctly."""
        assert _is_private_ip("::1") is not None
        assert _is_private_ip("fc00::1") is not None

    def test_public_ip_returns_none(self):
        assert _is_private_ip("8.8.8.8") is None
        assert _is_private_ip("2606:4700::") is None


class TestExtractPage:
    """_extract_page should cleanly separate pagination format detection."""

    def test_list_response(self):
        items, has_more = _extract_page([{"id": 1}, {"id": 2}])
        assert items == [{"id": 1}, {"id": 2}]
        assert has_more is False

    def test_shield_paginated_response(self):
        body = {
            "data": [{"id": 1}],
            "page": {"totalPages": 3, "currentPage": 1},
        }
        items, has_more = _extract_page(body, current_page=1)
        assert items == [{"id": 1}]
        assert has_more is True

    def test_shield_last_page(self):
        body = {
            "data": [{"id": 1}],
            "page": {"totalPages": 2, "currentPage": 2},
        }
        _items, has_more = _extract_page(body, current_page=2)
        assert has_more is False

    def test_pullzone_has_more_items(self):
        body = {"Items": [{"Id": 1}], "HasMoreItems": True, "TotalItems": 50}
        items, has_more = _extract_page(body, current_page=1)
        assert items == [{"Id": 1}]
        assert has_more is True

    def test_pullzone_no_more_items(self):
        body = {"Items": [{"Id": 1}], "HasMoreItems": False, "TotalItems": 1}
        _items, has_more = _extract_page(body, current_page=1)
        assert has_more is False

    def test_single_dict_response(self):
        """Dict with no pagination markers → single page."""
        body = {"items": [{"id": 1}]}
        items, has_more = _extract_page(body, current_page=1)
        assert items == [{"id": 1}]
        assert has_more is False

    def test_empty_response(self):
        items, has_more = _extract_page({}, current_page=1)
        assert items == []
        assert has_more is False

    def test_non_dict_non_list(self):
        items, has_more = _extract_page("unexpected", current_page=1)
        assert items == []
        assert has_more is False

    def test_dict_values_as_items(self):
        """When 'data' is a dict, its values become items."""
        body = {"data": {"a": {"id": 1}, "b": {"id": 2}}}
        items, has_more = _extract_page(body, current_page=1)
        assert len(items) == 2
        assert has_more is False
