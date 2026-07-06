"""Tests for bunny namespace registration and zone-file normalization."""

from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES

import octorules_bunny  # noqa: F401 — triggers __init__.py registration


def test_bunny_namespace_registered():
    """Verify bunny namespace is registered with all 8 keys."""
    assert "bunny" in PROVIDER_NAMESPACES
    bunny_ns = PROVIDER_NAMESPACES["bunny"]
    assert isinstance(bunny_ns, dict)
    assert len(bunny_ns) == 8


def test_bunny_namespace_mapping():
    """Verify all nested keys map to correct flat keys."""
    expected = {
        "waf_custom_rules": "bunny_waf_custom_rules",
        "waf_rate_limit_rules": "bunny_waf_rate_limit_rules",
        "waf_access_list_rules": "bunny_waf_access_list_rules",
        "edge_rules": "bunny_edge_rules",
        "waf_managed_rules": "bunny_waf_managed_rules",
        "shield_config": "bunny_shield_config",
        "pullzone_security": "bunny_pullzone_security",
        "curated_threat_lists": "bunny_curated_threat_lists",
    }
    assert PROVIDER_NAMESPACES["bunny"] == expected


def test_normalize_nested_bunny_format():
    """Verify normalize_zone_format flattens nested bunny: block."""
    nested = {
        "bunny": {
            "waf_custom_rules": [
                {
                    "ref": "Block SQLi",
                    "action": "block",
                    "severity": "error",
                    "conditions": [
                        {
                            "variable": "request_body",
                            "operator": "detect_sqli",
                        }
                    ],
                }
            ],
            "shield_config": {
                "waf": {"enabled": True, "execution_mode": "block"}
            },
        }
    }

    result = normalize_zone_format(nested)

    # After normalization, nested keys should be flattened to canonical flat keys
    assert "bunny_waf_custom_rules" in result
    assert "bunny_shield_config" in result
    assert result["bunny_waf_custom_rules"] == nested["bunny"]["waf_custom_rules"]
    assert result["bunny_shield_config"] == nested["bunny"]["shield_config"]
    assert "bunny" not in result  # Original nested key should not be present


def test_normalize_mixed_flat_and_nested_logs_deprecation(caplog):
    """Verify that mixing flat and nested keys logs deprecation warning."""
    import logging

    mixed = {
        "bunny_waf_custom_rules": [
            {
                "ref": "Flat rule",
                "action": "block",
            }
        ],
        "bunny": {
            "waf_rate_limit_rules": [
                {
                    "ref": "Nested rule",
                    "action": "block",
                }
            ]
        },
    }

    with caplog.at_level(logging.WARNING):
        result = normalize_zone_format(mixed)

    # Both forms should be merged into the result with flat keys
    assert "bunny_waf_custom_rules" in result
    assert "bunny_waf_rate_limit_rules" in result
    # The nested key should be removed after normalization
    assert "bunny" not in result
    # Deprecation warning should be logged
    assert any("deprecated flat spelling" in record.message for record in caplog.records)
