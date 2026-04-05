"""Tests for Bunny Shield audit extension."""

from octorules_bunny.audit import _extract_ips


class TestAccessListExtraction:
    def test_ip_type(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": "42",
                    "type": "ip",
                    "action": "block",
                    "content": "10.0.0.1\n192.168.1.1",
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_access_list_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["10.0.0.1", "192.168.1.1"]
        assert results[0].action == "block"

    def test_cidr_type(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {
                    "ref": "43",
                    "type": "cidr",
                    "action": "allow",
                    "content": "10.0.0.0/8",
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_access_list_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["10.0.0.0/8"]

    def test_country_type_skipped(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {"ref": "44", "type": "country", "action": "block", "content": "CN\nRU"}
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_access_list_rules")
        assert results == []

    def test_empty_content_skipped(self):
        rules_data = {
            "bunny_waf_access_list_rules": [
                {"ref": "45", "type": "ip", "action": "block", "content": ""}
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_access_list_rules")
        assert results == []


class TestWAFRuleExtraction:
    def test_remote_addr_condition(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "Block IP",
                    "action": "block",
                    "conditions": [
                        {"variable": "remote_addr", "operator": "str_eq", "value": "1.2.3.4"}
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_custom_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["1.2.3.4"]

    def test_non_ip_condition_skipped(self):
        rules_data = {
            "bunny_waf_custom_rules": [
                {
                    "ref": "Block path",
                    "action": "block",
                    "conditions": [
                        {"variable": "request_uri", "operator": "contains", "value": "/admin"}
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_waf_custom_rules")
        assert results == []


class TestUnknownPhase:
    def test_returns_empty(self):
        assert _extract_ips({}, "unknown_phase") == []
