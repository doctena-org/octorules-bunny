"""Bunny Shield WAF lint rule definitions — all BN-specific RuleMeta instances."""

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

# BN0xx — Structural
BN001 = RuleMeta("BN001", "structure", "Rule missing 'ref'", Severity.ERROR)
BN002 = RuleMeta("BN002", "structure", "Duplicate ref within phase", Severity.ERROR)
BN003 = RuleMeta("BN003", "structure", "Rule missing required field", Severity.ERROR)
BN004 = RuleMeta("BN004", "structure", "Unknown top-level rule field", Severity.WARNING)
BN005 = RuleMeta("BN005", "structure", "Rule field has wrong type", Severity.ERROR)
BN006 = RuleMeta("BN006", "structure", "Rule entry is not a dict", Severity.ERROR)
BN007 = RuleMeta("BN007", "structure", "Phase value is not a list", Severity.ERROR)
BN009 = RuleMeta("BN009", "structure", "Duplicate ref across different phases", Severity.INFO)
BN010 = RuleMeta("BN010", "structure", "Invalid ref format (must be [a-zA-Z0-9 ]+)", Severity.ERROR)
BN011 = RuleMeta("BN011", "structure", "Description exceeds 255 characters", Severity.WARNING)

# BN1xx — Enum validation
BN100 = RuleMeta("BN100", "action", "Invalid action value", Severity.ERROR)
BN101 = RuleMeta("BN101", "operator", "Invalid operator value", Severity.ERROR)
BN102 = RuleMeta("BN102", "variable", "Unknown variable value", Severity.WARNING)
BN103 = RuleMeta("BN103", "transformation", "Unknown transformation value", Severity.WARNING)
BN104 = RuleMeta("BN104", "severity", "Invalid severity value", Severity.ERROR)
BN105 = RuleMeta("BN105", "operator", "Invalid regex pattern in rx operator", Severity.ERROR)
BN106 = RuleMeta("BN106", "operator", "Operator requires 'value' but none provided", Severity.ERROR)
BN107 = RuleMeta(
    "BN107", "operator", "Numeric operator used with non-numeric variable", Severity.WARNING
)
BN108 = RuleMeta(
    "BN108", "condition", "Catch-all condition (matches all traffic)", Severity.WARNING
)
BN109 = RuleMeta("BN109", "variable", "variable_value on unsupported variable", Severity.WARNING)
BN119 = RuleMeta(
    "BN119", "operator", "Regex starts with '.*' or '.+' (performance footgun)", Severity.INFO
)
BN120 = RuleMeta(
    "BN120",
    "operator",
    "Overly permissive regex pattern (may match unintended input)",
    Severity.WARNING,
)
BN549 = RuleMeta(
    "BN549",
    "operator",
    "Fully-anchored literal regex can be simplified to eq operator",
    Severity.INFO,
)
BN520 = RuleMeta(
    "BN520",
    "operator",
    "HTTP method should be uppercase (case-sensitive operator used)",
    Severity.WARNING,
)
BN521 = RuleMeta(
    "BN521",
    "operator",
    "URI variables should start with / (normalizes path matching)",
    Severity.WARNING,
)

# BN526 is reserved but undocumented in Bunny docs (header case-sensitivity).
# Defer implementation until Bunny clarifies the API behavior per no-speculative-apis.md.

# BN1xx — Variable sub-value validation
BN115 = RuleMeta(
    "BN115", "variable", "Variable requires variable_value but none provided", Severity.WARNING
)
BN116 = RuleMeta("BN116", "variable", "Invalid GEO sub-value", Severity.ERROR)
BN117 = RuleMeta(
    "BN117",
    "variable",
    "REQUEST_HEADERS/REQUEST_COOKIES requires variable_value (header/cookie name)",
    Severity.WARNING,
)

# BN1xx — Transformation checks
BN122 = RuleMeta(
    "BN122",
    "transformation",
    "Redundant LOWERCASE transformation with str_eq operator",
    Severity.INFO,
)
BN123 = RuleMeta(
    "BN123", "value", "Percent-encoded literal on decoded URI variable", Severity.WARNING
)
BN124 = RuleMeta(
    "BN124", "value", "CONTAINSWORD with multi-word value cannot match", Severity.WARNING
)
BN125 = RuleMeta(
    "BN125", "transformation", "Duplicate transformation in same rule", Severity.WARNING
)

# BN2xx — Rate limit
BN200 = RuleMeta("BN200", "rate_limit", "request_count must be a positive integer", Severity.ERROR)
BN201 = RuleMeta("BN201", "rate_limit", "Invalid timeframe value", Severity.ERROR)
BN202 = RuleMeta("BN202", "rate_limit", "Invalid block_time value", Severity.ERROR)
BN203 = RuleMeta("BN203", "rate_limit", "Invalid counter_key_type value", Severity.ERROR)
BN210 = RuleMeta("BN210", "rate_limit", "Very short block_time (30s)", Severity.WARNING)

# BN3xx — Access list
BN300 = RuleMeta("BN300", "access_list", "Invalid access list type", Severity.ERROR)
BN301 = RuleMeta("BN301", "access_list", "Empty access list content", Severity.ERROR)
BN302 = RuleMeta("BN302", "access_list", "Invalid CIDR/IP notation", Severity.WARNING)
BN303 = RuleMeta("BN303", "access_list", "Invalid ASN format", Severity.WARNING)
BN304 = RuleMeta("BN304", "access_list", "Invalid country code", Severity.WARNING)
BN305 = RuleMeta(
    "BN305", "access_list", "Private/reserved IP range in access list", Severity.WARNING
)
BN306 = RuleMeta(
    "BN306", "access_list", "CIDR has host bits set (auto-correctable)", Severity.WARNING
)
BN307 = RuleMeta(
    "BN307", "access_list", "Overlapping CIDRs within same access list", Severity.WARNING
)
BN308 = RuleMeta("BN308", "access_list", "Invalid JA4 fingerprint format", Severity.WARNING)
BN309 = RuleMeta("BN309", "access_list", "Duplicate entry in access list", Severity.WARNING)
BN310 = RuleMeta(
    "BN310", "access_list", "Duplicate organization entry in access list", Severity.WARNING
)
BN311 = RuleMeta(
    "BN311",
    "access_list",
    "Catch-all CIDR (0.0.0.0/0 or ::/0) in access list",
    Severity.WARNING,
)

# BN4xx — Condition validation
BN400 = RuleMeta("BN400", "condition", "Condition missing 'variable'", Severity.ERROR)
BN401 = RuleMeta("BN401", "condition", "Condition missing 'operator'", Severity.ERROR)
BN402 = RuleMeta(
    "BN402",
    "condition",
    "detect_sqli/detect_xss operators ignore 'value' field",
    Severity.WARNING,
)
BN403 = RuleMeta(
    "BN403", "condition", "Duplicate condition in chained conditions", Severity.WARNING
)
BN404 = RuleMeta("BN404", "condition", "Chained conditions exceed 10", Severity.WARNING)

# BN5xx — Cross-rule
BN500 = RuleMeta(
    "BN500", "cross_rule", "Duplicate conditions across rules in phase", Severity.WARNING
)
BN501 = RuleMeta("BN501", "cross_rule", "Rule count may exceed plan tier limit", Severity.WARNING)
BN502 = RuleMeta(
    "BN502",
    "cross_rule",
    "Conflicting access lists (overlapping entries with different actions)",
    Severity.WARNING,
)

BN503 = RuleMeta(
    "BN503",
    "cross_rule",
    "Rule likely unreachable after catch-all terminating rule",
    Severity.WARNING,
)
BN504 = RuleMeta(
    "BN504",
    "cross_rule",
    "Overlapping CIDR ranges across multiple access lists with different actions",
    Severity.WARNING,
)

# BN7xx — Edge rules
BN700 = RuleMeta("BN700", "edge_rule", "Invalid or missing edge rule action_type", Severity.ERROR)
BN701 = RuleMeta("BN701", "edge_rule", "Invalid or missing edge rule trigger type", Severity.ERROR)
BN702 = RuleMeta("BN702", "edge_rule", "Edge rule has no triggers", Severity.ERROR)
BN703 = RuleMeta("BN703", "edge_rule", "Invalid edge rule trigger_matching_type", Severity.ERROR)
BN704 = RuleMeta(
    "BN704", "edge_rule", "Edge rule trigger has empty pattern_matches", Severity.WARNING
)
BN705 = RuleMeta("BN705", "edge_rule", "Invalid edge rule pattern_matching_type", Severity.ERROR)
BN706 = RuleMeta(
    "BN706", "edge_rule", "Edge rule action missing required parameter", Severity.ERROR
)
BN707 = RuleMeta(
    "BN707", "edge_rule", "Edge rule trigger has empty/whitespace pattern", Severity.ERROR
)
BN708 = RuleMeta(
    "BN708", "edge_rule", "Invalid country code in country_code trigger", Severity.ERROR
)
BN709 = RuleMeta("BN709", "edge_rule", "Invalid IP/CIDR in remote_ip trigger", Severity.ERROR)
BN710 = RuleMeta(
    "BN710", "edge_rule", "Invalid HTTP method in request_method trigger", Severity.ERROR
)
BN711 = RuleMeta(
    "BN711",
    "edge_rule",
    "Status code out of range (100-900) in status_code trigger",
    Severity.ERROR,
)
BN712 = RuleMeta("BN712", "edge_rule", "Malformed Lua pattern (pattern: prefix)", Severity.ERROR)
BN713 = RuleMeta(
    "BN713",
    "edge_rule",
    "URL trigger pattern must start with /, http, or *",
    Severity.WARNING,
)
BN715 = RuleMeta(
    "BN715",
    "edge_rule",
    "Redirect status code must be 300-399",
    Severity.ERROR,
)

# BN6xx — Best practice
BN600 = RuleMeta("BN600", "best_practice", "Very short rule name", Severity.INFO)
BN601 = RuleMeta("BN601", "best_practice", "Rule has no description", Severity.INFO)
BN602 = RuleMeta(
    "BN602", "best_practice", "Access list is disabled (enabled: false)", Severity.INFO
)

BN_RULE_METAS: tuple[RuleMeta, ...] = (
    # BN0xx — Structural
    BN001,
    BN002,
    BN003,
    BN004,
    BN005,
    BN006,
    BN007,
    BN009,
    BN010,
    BN011,
    # BN1xx — Enum validation
    BN100,
    BN101,
    BN102,
    BN103,
    BN104,
    BN105,
    BN106,
    BN107,
    BN108,
    BN109,
    BN119,
    BN120,
    BN520,
    BN521,
    BN549,
    # BN1xx — Variable sub-value
    BN115,
    BN116,
    BN117,
    # BN1xx — Transformation
    BN122,
    BN123,
    BN124,
    BN125,
    # BN2xx — Rate limit
    BN200,
    BN201,
    BN202,
    BN203,
    BN210,
    # BN3xx — Access list
    BN300,
    BN301,
    BN302,
    BN303,
    BN304,
    BN305,
    BN306,
    BN307,
    BN308,
    BN309,
    BN310,
    BN311,
    # BN4xx — Condition
    BN400,
    BN401,
    BN402,
    BN403,
    BN404,
    # BN5xx — Cross-rule
    BN500,
    BN501,
    BN502,
    BN503,
    BN504,
    # BN6xx — Best practice
    BN600,
    BN601,
    BN602,
    # BN7xx — Edge rules
    BN700,
    BN701,
    BN702,
    BN703,
    BN704,
    BN705,
    BN706,
    BN707,
    BN708,
    BN709,
    BN710,
    BN711,
    BN712,
    BN713,
    BN715,
)
