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


class TestEdgeRuleExtraction:
    """Edge rules with ``remote_ip`` triggers participate in audit.

    Closes the coverage gap where ``audit ip-overlap`` / ``cdn-ranges`` /
    ``zone-drift`` / ``ip-shadow`` silently dropped IPs that lived in
    edge-rule triggers (BN709 confirms the schema carries CIDR data).
    """

    def test_remote_ip_trigger_extracted(self):
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "Block private",
                    "action_type": "block",
                    "triggers": [
                        {
                            "type": "remote_ip",
                            "pattern_matching_type": "match_any",
                            "pattern_matches": ["10.0.0.0/8", "192.168.0.0/16"],
                        }
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_edge_rules")
        assert len(results) == 1
        assert results[0].ref == "Block private"
        assert results[0].action == "block"
        assert results[0].ip_ranges == ["10.0.0.0/8", "192.168.0.0/16"]
        assert results[0].phase_name == "bunny_edge_rules"

    def test_multiple_remote_ip_triggers_merged(self):
        """Multiple remote_ip triggers on the same rule produce one RuleIPInfo."""
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "multi",
                    "action_type": "redirect",
                    "triggers": [
                        {"type": "remote_ip", "pattern_matches": ["10.0.0.0/8"]},
                        {"type": "remote_ip", "pattern_matches": ["172.16.0.0/12"]},
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_edge_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_non_ip_triggers_skipped(self):
        """request_method, country_code, etc. triggers carry no IPs and are skipped."""
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "geo",
                    "action_type": "block",
                    "triggers": [
                        {"type": "country_code", "pattern_matches": ["CN", "RU"]},
                        {"type": "request_method", "pattern_matches": ["POST"]},
                    ],
                }
            ]
        }
        assert _extract_ips(rules_data, "bunny_edge_rules") == []

    def test_mixed_triggers_only_remote_ip_extracted(self):
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "mixed",
                    "action_type": "block",
                    "triggers": [
                        {"type": "country_code", "pattern_matches": ["CN"]},
                        {"type": "remote_ip", "pattern_matches": ["1.2.3.4/32"]},
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_edge_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["1.2.3.4/32"]

    def test_empty_pattern_matches_skipped(self):
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "empty",
                    "action_type": "block",
                    "triggers": [{"type": "remote_ip", "pattern_matches": []}],
                }
            ]
        }
        assert _extract_ips(rules_data, "bunny_edge_rules") == []

    def test_action_falls_back_to_action_field(self):
        """If action_type is absent (legacy YAML), fall back to action."""
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "legacy",
                    "action": "block",  # no action_type
                    "triggers": [{"type": "remote_ip", "pattern_matches": ["10.0.0.0/8"]}],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_edge_rules")
        assert len(results) == 1
        assert results[0].action == "block"

    def test_malformed_triggers_dont_crash(self):
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "weird",
                    "action_type": "block",
                    "triggers": "not-a-list",  # malformed
                }
            ]
        }
        assert _extract_ips(rules_data, "bunny_edge_rules") == []

    def test_non_string_pattern_matches_filtered(self):
        rules_data = {
            "bunny_edge_rules": [
                {
                    "ref": "junk",
                    "action_type": "block",
                    "triggers": [
                        {"type": "remote_ip", "pattern_matches": [None, 42, "10.0.0.0/8"]},
                    ],
                }
            ]
        }
        results = _extract_ips(rules_data, "bunny_edge_rules")
        assert len(results) == 1
        assert results[0].ip_ranges == ["10.0.0.0/8"]


class TestUnknownPhase:
    def test_returns_empty(self):
        assert _extract_ips({}, "unknown_phase") == []
