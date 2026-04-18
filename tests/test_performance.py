"""Tests for performance improvements."""

from octorules_bunny._client import _extract_page

# Reserved/bogon range coverage migrated to octorules core v0.26.0
# (tests/test_reserved_ips.py).  Removed from Bunny in v0.3.2.


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
