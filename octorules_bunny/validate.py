"""Offline validation for Bunny Shield WAF rules."""

import ipaddress
import re

from octorules.linter.engine import LintResult, Severity
from octorules.reserved_ips import is_reserved

from octorules_bunny._enums import (
    ACCESS_LIST_TYPE,
    ACTION,
    BLOCKTIME,
    COUNTER_KEY,
    EDGE_ACTION,
    EDGE_PATTERN_MATCH,
    EDGE_TRIGGER,
    EDGE_TRIGGER_MATCH,
    GEO_SUBVALUES,
    OPERATOR,
    SEVERITY,
    TIMEFRAME,
    TRANSFORMATION,
    VARIABLE,
    VARIABLES_WITH_SUBVALUE,
)

# Rule IDs emitted by validate_rules() — kept in sync with _rules.py by
# test_plugin_rule_ids_match_metas.
RULE_IDS: frozenset[str] = frozenset(
    {
        "BN001",
        "BN002",
        "BN003",
        "BN004",
        "BN005",
        "BN006",
        "BN010",
        "BN011",
        "BN100",
        "BN101",
        "BN102",
        "BN103",
        "BN104",
        "BN105",
        "BN106",
        "BN107",
        "BN108",
        "BN109",
        "BN119",
        "BN120",
        "BN520",
        "BN521",
        "BN549",
        "BN115",
        "BN116",
        "BN117",
        "BN122",
        "BN123",
        "BN124",
        "BN125",
        "BN200",
        "BN201",
        "BN202",
        "BN203",
        "BN210",
        "BN300",
        "BN301",
        "BN302",
        "BN303",
        "BN304",
        "BN305",
        "BN306",
        "BN307",
        "BN308",
        "BN309",
        "BN310",
        "BN311",
        "BN400",
        "BN401",
        "BN402",
        "BN403",
        "BN404",
        "BN500",
        "BN501",
        "BN502",
        "BN503",
        "BN504",
        "BN600",
        "BN601",
        "BN602",
        "BN700",
        "BN701",
        "BN702",
        "BN703",
        "BN704",
        "BN705",
        "BN706",
        "BN707",
        "BN708",
        "BN709",
        "BN710",
        "BN711",
        "BN712",
        "BN713",
        "BN715",
    }
)

_RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9 ]+$")
_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
# JA4 TLS fingerprint: 36 chars in format a_b_c (10 + 1 + 12 + 1 + 12).
# Section A: protocol(1) + TLS version(2) + SNI(1) + cipher count(2)
#            + extension count(2) + ALPN(2) = 10 chars
# Section B: truncated SHA-256 of cipher suites (12 hex chars)
# Section C: truncated SHA-256 of extensions (12 hex chars)
_JA4_RE = re.compile(
    r"^[tqd]"  # protocol: TLS/QUIC/DTLS
    r"(?:13|12|11|10|s[23]|d[123]|00)"  # TLS version
    r"[di]"  # SNI: domain or IP
    r"[0-9]{2}"  # cipher suite count
    r"[0-9]{2}"  # extension count
    r"[a-z0-9]{2}"  # ALPN abbreviation
    r"_[a-f0-9]{12}"  # cipher hash
    r"_[a-f0-9]{12}$"  # extension hash
)
# BN549: fully anchored literal regex (conservative — only basic alphanumerics + /, -, _)
_FULLY_ANCHORED_LITERAL_REGEX = re.compile(
    r"^\^"  # start anchor
    r"((?:[a-zA-Z0-9_/-]|\\\.|\\/)+)"  # literal-only payload (escaped . or / OK)
    r"\$$"  # end anchor
)
_DETECT_OPERATORS = frozenset({"detect_sqli", "detect_xss"})
_NUMERIC_OPERATORS = frozenset({"eq", "ge", "gt", "le", "lt"})
# Case-sensitive string operators (should be used with uppercase method names)
_CASE_SENSITIVE_OPERATORS = frozenset(
    {"str_match", "rx", "begins_with", "contains", "contains_word", "ends_with"}
)
# Literal-text operators where leading / in path matters
_LITERAL_TEXT_OPERATORS = frozenset({"eq", "str_eq", "str_match", "begins_with", "contains"})
_MAX_DESCRIPTION_LEN = 255
_MAX_CHAINED_CONDITIONS = 10

# Catch-all CIDR ranges (match everything) — flagged by BN311 and skipped
# by BN307 to avoid double-firing against every other entry in the list.
_CATCH_ALL_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# BN120: overly permissive regex patterns that match too broadly
_OVERLY_PERMISSIVE_PATTERNS = frozenset(
    {
        "",  # empty string
        ".",  # any single character
        ".*",  # any characters
        "^.*",  # any characters from start
        ".*$",  # any characters to end
        "^.*$",  # any characters anywhere
        ".+",  # one or more any character
        "^.+",  # one or more any character from start
        ".+$",  # one or more any character to end
        "^.+$",  # one or more any character anywhere
        "^",  # anchor only (matches start)
        "$",  # anchor only (matches end)
        "|",  # alternation with empty branch
    }
)

# Path-context patterns (URI/filename specific) for BN120 path context check
_OVERLY_PERMISSIVE_PATH_PATTERNS = frozenset(
    {
        "/",  # any root path
        "^/",  # root path from start
        "/.*",  # anything under root
        "^/.*",  # anything under root from start
        "/.*$",  # anything under root to end
        "^/.*$",  # anything under root anywhere
    }
)

# BN122: case-insensitive string operator (makes lowercase transformation redundant)
_CASE_INSENSITIVE_OPERATORS = frozenset({"str_eq", "contains_word"})

# BN123: decoded URI variables (percent-encoding doesn't apply)
_DECODED_URI_VARIABLES = frozenset({"request_uri", "request_filename", "request_basename"})

# BN123: percent-encoded literal operator scope
_PERCENT_ENCODED_LITERAL_OPERATORS = frozenset(
    {"eq", "str_eq", "str_match", "begins_with", "ends_with", "contains", "contains_word"}
)

# BN123: percent-encoded sequence pattern
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# Known top-level fields for each phase type.
_CUSTOM_WAF_FIELDS = frozenset(
    {"ref", "action", "severity", "description", "conditions", "transformations"}
)
_RATE_LIMIT_FIELDS = _CUSTOM_WAF_FIELDS | frozenset(
    {"request_count", "timeframe", "block_time", "counter_key_type"}
)
_ACCESS_LIST_FIELDS = frozenset({"ref", "type", "action", "enabled", "content", "description"})

# Variables that semantically require a sub-value.
_REQUIRES_SUBVALUE = frozenset({"request_headers", "request_cookies"})

# Reserved/bogon network detection is provided by octorules.reserved_ips
# (single source of truth across all providers; see core v0.26.0).


def _result(
    rule_id: str,
    severity: Severity,
    message: str,
    phase: str,
    ref: str = "",
    *,
    field: str = "",
    suggestion: str = "",
) -> LintResult:
    return LintResult(
        rule_id=rule_id,
        severity=severity,
        message=message,
        phase=phase,
        ref=ref,
        field=field,
        suggestion=suggestion,
    )


def _condition_key(cond: dict) -> tuple[str, str, str, str]:
    """Return a hashable key for a condition dict (faster than json.dumps)."""
    return (
        str(cond.get("variable", "")),
        str(cond.get("operator", "")),
        str(cond.get("value", "")),
        str(cond.get("variable_value", "")),
    )


# Standard HTTP methods accepted by edge rule request_method triggers.
_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
)


def _check_lua_pattern(pattern: str) -> str | None:
    """Validate a Lua pattern (without the 'pattern:' prefix).

    Returns an error message if malformed, else None.  Lua patterns use
    a simplified syntax (not PCRE): ``%a %d %w`` classes, ``[abc]``
    character sets, ``+ * -`` repeaters, and ``%`` as the escape
    character.
    """
    if not pattern:
        return "empty pattern body after 'pattern:' prefix"
    # Check for unclosed character sets
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "%":
            # Escape must be followed by a character
            if i == n - 1:
                return "trailing '%' escape with no following character"
            i += 2
            continue
        if ch == "[":
            # Find the closing bracket (Lua doesn't allow nested brackets)
            close = pattern.find("]", i + 1)
            if close == -1:
                return "unclosed '[' character set"
            i = close + 1
            continue
        i += 1
    return None


# ---------------------------------------------------------------------------
# Custom WAF / Rate Limit validation
# ---------------------------------------------------------------------------
def _validate_condition(
    cond: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    index: int,
) -> None:
    """Validate a single rule condition."""
    prefix = f"conditions[{index}]"

    var = cond.get("variable", "")
    if not var:
        results.append(
            _result("BN400", Severity.ERROR, f"{prefix}: missing 'variable'", phase, ref)
        )
    elif isinstance(var, str) and var not in VARIABLE:
        results.append(
            _result(
                "BN102",
                Severity.WARNING,
                f"{prefix}: unknown variable {var!r}",
                phase,
                ref,
                field="variable",
            )
        )

    op = cond.get("operator", "")
    if not op:
        results.append(
            _result("BN401", Severity.ERROR, f"{prefix}: missing 'operator'", phase, ref)
        )
    elif isinstance(op, str) and op not in OPERATOR:
        results.append(
            _result(
                "BN101",
                Severity.ERROR,
                f"{prefix}: unknown operator {op!r}",
                phase,
                ref,
                field="operator",
            )
        )

    # BN402: detect_sqli/xss operators ignore the value field
    if isinstance(op, str) and op in _DETECT_OPERATORS and cond.get("value"):
        results.append(
            _result(
                "BN402",
                Severity.WARNING,
                f"{prefix}: {op} ignores the 'value' field",
                phase,
                ref,
                field="value",
                suggestion="Remove the value field",
            )
        )

    # BN106: Non-detect operators require a value
    if isinstance(op, str) and op in OPERATOR and op not in _DETECT_OPERATORS:
        if cond.get("value") in (None, ""):
            results.append(
                _result(
                    "BN106",
                    Severity.ERROR,
                    f"{prefix}: operator {op!r} requires a 'value'",
                    phase,
                    ref,
                    field="value",
                )
            )

    # BN105: Validate regex pattern for RX operator
    if isinstance(op, str) and op == "rx":
        pattern = cond.get("value", "")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as e:
                results.append(
                    _result(
                        "BN105",
                        Severity.ERROR,
                        f"{prefix}: invalid regex pattern: {e}",
                        phase,
                        ref,
                        field="value",
                    )
                )
            # BN119: leading .* / .+ (performance footgun)
            # Skip if it's a known catch-all pattern (BN108 covers those).
            if isinstance(pattern, str) and pattern not in (".*", "^.*$", ".+"):
                if pattern.startswith((".*", ".+")):
                    results.append(
                        _result(
                            "BN119",
                            Severity.INFO,
                            f"{prefix}: regex starts with {pattern[:2]!r} — "
                            "unanchored regex already matches anywhere, this prefix is "
                            "redundant and hurts performance",
                            phase,
                            ref,
                            field="value",
                            suggestion="Remove the leading '.*' or '.+'",
                        )
                    )
            # BN120: overly permissive regex patterns
            if isinstance(pattern, str) and pattern in _OVERLY_PERMISSIVE_PATTERNS:
                results.append(
                    _result(
                        "BN120",
                        Severity.WARNING,
                        f"{prefix}: regex {pattern!r} is overly permissive and matches "
                        "almost everything",
                        phase,
                        ref,
                        field="value",
                        suggestion="Consider a more specific pattern",
                    )
                )
            # BN120 path context: additional patterns when var is request_uri/request_filename
            if (
                isinstance(pattern, str)
                and isinstance(var, str)
                and var in ("request_uri", "request_filename")
                and pattern in _OVERLY_PERMISSIVE_PATH_PATTERNS
            ):
                results.append(
                    _result(
                        "BN120",
                        Severity.WARNING,
                        f"{prefix}: regex {pattern!r} on path variable {var!r} matches "
                        "almost all paths",
                        phase,
                        ref,
                        field="value",
                        suggestion="Consider a more specific pattern",
                    )
                )
            # BN549: fully anchored literal regex (can simplify to eq)
            m = _FULLY_ANCHORED_LITERAL_REGEX.match(pattern) if isinstance(pattern, str) else None
            if m is not None:
                # Reconstruct the literal: unescape `\.` → `.` and `\/` → `/`.
                literal = m.group(1).replace(r"\.", ".").replace(r"\/", "/")
                results.append(
                    _result(
                        "BN549",
                        Severity.INFO,
                        f"{prefix}: regex {pattern!r} is a fully-anchored literal; "
                        f"can be simplified to eq operator",
                        phase,
                        ref,
                        field="value",
                        suggestion=(
                            f'Replace with: {{"variable": "{var}", "operator": "eq", '
                            f'"value": "{literal}"}}'
                        ),
                    )
                )

    # BN107: Numeric operators on non-numeric variables
    if (
        isinstance(op, str)
        and op in _NUMERIC_OPERATORS
        and isinstance(var, str)
        and var in VARIABLE
        and var not in ("args_combined_size", "response_status")
    ):
        results.append(
            _result(
                "BN107",
                Severity.WARNING,
                f"{prefix}: numeric operator {op!r} on non-numeric variable {var!r}",
                phase,
                ref,
                field="operator",
            )
        )

    # BN108: Catch-all condition detection
    value = cond.get("value", "")
    if isinstance(op, str) and op not in _DETECT_OPERATORS and isinstance(value, str):
        if (
            (op in ("contains", "contains_word", "within") and value == "")
            or (op == "begins_with" and value == "/")
            or (op == "rx" and value in (".*", "^.*$", ".+", ""))
        ):
            results.append(
                _result(
                    "BN108",
                    Severity.WARNING,
                    f"{prefix}: condition matches all traffic ({op!r} with value {value!r})",
                    phase,
                    ref,
                    field="value",
                )
            )

    # BN520: HTTP method should be uppercase when using case-sensitive operators
    if (
        isinstance(var, str)
        and var == "request_method"
        and isinstance(op, str)
        and op in _CASE_SENSITIVE_OPERATORS
        and isinstance(value, str)
    ):
        # Check if value contains lowercase ASCII letters
        if any(c.islower() for c in value if c.isascii()):
            results.append(
                _result(
                    "BN520",
                    Severity.WARNING,
                    f"{prefix}: HTTP method should be uppercase (RFC specifies uppercase); "
                    f"{op!r} is case-sensitive",
                    phase,
                    ref,
                    field="value",
                    suggestion=f"Uppercase the value: {value.upper()}",
                )
            )

    # BN521: URI variables should start with / (for literal-text operators)
    if (
        isinstance(var, str)
        and var in ("request_uri", "request_filename")
        and isinstance(op, str)
        and op in _LITERAL_TEXT_OPERATORS
        and isinstance(value, str)
        and value
        and not value.startswith("/")
    ):
        # Skip if it's a regex anchor pattern (won't fire on rx operator anyway)
        if not (op == "rx" and value.startswith("^/")):
            results.append(
                _result(
                    "BN521",
                    Severity.WARNING,
                    f"{prefix}: {var!r} value should start with '/' (normalizes path matching)",
                    phase,
                    ref,
                    field="value",
                    suggestion=f"Prepend '/': /{value}",
                )
            )

    # BN123: Percent-encoded literal on decoded URI variable
    if (
        isinstance(var, str)
        and var in _DECODED_URI_VARIABLES
        and isinstance(op, str)
        and op in _PERCENT_ENCODED_LITERAL_OPERATORS
        and isinstance(value, str)
        and _PERCENT_ENCODED_RE.search(value)
    ):
        results.append(
            _result(
                "BN123",
                Severity.WARNING,
                f"{prefix}: {var!r} is decoded; percent-encoded sequences "
                "like %2F will never match",
                phase,
                ref,
                field="value",
                suggestion="Use decoded form (e.g., '/' not '%2F') or use request_uri_raw",
            )
        )

    # BN124: CONTAINSWORD with multi-word value
    if (
        isinstance(op, str)
        and op == "contains_word"
        and isinstance(value, str)
        and any(c.isspace() for c in value)
    ):
        results.append(
            _result(
                "BN124",
                Severity.WARNING,
                f"{prefix}: contains_word requires a single word, but value contains whitespace",
                phase,
                ref,
                field="value",
                suggestion="Split into multiple contains_word conditions, or use "
                "'contains' for substring matching",
            )
        )

    # -- Sub-value validation --
    sub = cond.get("variable_value", "")

    # BN109: Sub-value on variable that doesn't support it
    if sub and isinstance(var, str) and var in VARIABLE and var not in VARIABLES_WITH_SUBVALUE:
        results.append(
            _result(
                "BN109",
                Severity.WARNING,
                f"{prefix}: variable {var!r} does not support variable_value",
                phase,
                ref,
                field="variable_value",
            )
        )

    # BN116: Invalid GEO sub-value
    if isinstance(var, str) and var == "geo" and sub:
        if sub not in GEO_SUBVALUES:
            results.append(
                _result(
                    "BN116",
                    Severity.ERROR,
                    f"{prefix}: invalid GEO sub-value {sub!r}",
                    phase,
                    ref,
                    field="variable_value",
                    suggestion=f"Valid: {sorted(GEO_SUBVALUES)}",
                )
            )

    # BN115: GEO variable without sub-value
    if isinstance(var, str) and var == "geo" and not sub:
        results.append(
            _result(
                "BN115",
                Severity.WARNING,
                f"{prefix}: 'geo' variable requires a variable_value (e.g., COUNTRY_CODE, ASN)",
                phase,
                ref,
                field="variable_value",
            )
        )

    # BN117: REQUEST_HEADERS/REQUEST_COOKIES without sub-value
    if isinstance(var, str) and var in _REQUIRES_SUBVALUE and not sub:
        results.append(
            _result(
                "BN117",
                Severity.WARNING,
                f"{prefix}: {var!r} requires variable_value (header/cookie name)",
                phase,
                ref,
                field="variable_value",
            )
        )


def _validate_custom_rule(rule: dict, results: list[LintResult], phase: str) -> None:
    """Validate a single custom WAF rule."""
    ref = str(rule.get("ref", ""))

    # BN001: missing ref
    if not ref:
        results.append(_result("BN001", Severity.ERROR, "Rule missing 'ref'", phase))
        return

    # BN010: invalid ref format (custom/rate_limit only, not access lists)
    if not _RULE_NAME_RE.fullmatch(ref):
        results.append(
            _result(
                "BN010",
                Severity.ERROR,
                "ref must match [a-zA-Z0-9 ]+ (alphanumeric and spaces only)",
                phase,
                ref,
                field="ref",
            )
        )

    # BN600: very short ref
    if len(ref.strip()) < 2:
        results.append(
            _result("BN600", Severity.INFO, "Rule name is very short", phase, ref, field="ref")
        )

    # BN004: unknown top-level fields
    known = _RATE_LIMIT_FIELDS if phase.endswith("rate_limit_rules") else _CUSTOM_WAF_FIELDS
    unknown = set(rule) - known - {"_api_id", "shieldZoneId"}
    for field_name in sorted(unknown):
        results.append(
            _result(
                "BN004",
                Severity.WARNING,
                f"Unknown top-level field: {field_name!r}",
                phase,
                ref,
                field=field_name,
            )
        )

    # BN011: description too long
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_DESCRIPTION_LEN:
        results.append(
            _result(
                "BN011",
                Severity.WARNING,
                f"Description exceeds {_MAX_DESCRIPTION_LEN} characters ({len(desc)})",
                phase,
                ref,
                field="description",
            )
        )

    # BN601: missing description
    if not desc:
        results.append(_result("BN601", Severity.INFO, "Rule has no description", phase, ref))

    # BN100: action
    action = rule.get("action", "")
    if not action:
        results.append(_result("BN003", Severity.ERROR, "Rule missing 'action'", phase, ref))
    elif isinstance(action, str) and action not in ACTION:
        results.append(
            _result(
                "BN100", Severity.ERROR, f"Invalid action {action!r}", phase, ref, field="action"
            )
        )

    # BN104: severity
    sev = rule.get("severity", "")
    if sev and isinstance(sev, str) and sev not in SEVERITY:
        results.append(
            _result(
                "BN104",
                Severity.ERROR,
                f"Invalid severity {sev!r}",
                phase,
                ref,
                field="severity",
            )
        )

    # BN005: severity must be string
    if sev and not isinstance(sev, str):
        results.append(
            _result(
                "BN005",
                Severity.ERROR,
                f"severity must be a string, got {type(sev).__name__}",
                phase,
                ref,
                field="severity",
            )
        )

    # BN005: action must be string
    if action and not isinstance(action, str):
        results.append(
            _result(
                "BN005",
                Severity.ERROR,
                f"action must be a string, got {type(action).__name__}",
                phase,
                ref,
                field="action",
            )
        )

    # Conditions
    conditions = rule.get("conditions", [])
    if not conditions:
        results.append(_result("BN003", Severity.ERROR, "Rule missing 'conditions'", phase, ref))
    elif not isinstance(conditions, list):
        results.append(_result("BN005", Severity.ERROR, "conditions must be a list", phase, ref))
        conditions = []

    # BN404: too many chained conditions
    if len(conditions) > _MAX_CHAINED_CONDITIONS:
        results.append(
            _result(
                "BN404",
                Severity.WARNING,
                f"Rule has {len(conditions)} conditions"
                f" (exceeds limit of {_MAX_CHAINED_CONDITIONS})",
                phase,
                ref,
                field="conditions",
            )
        )

    # BN403: duplicate conditions within the rule
    seen_conds: dict[str, int] = {}
    for i, cond in enumerate(conditions):
        _validate_condition(cond, results, phase, ref, i)
        key = _condition_key(cond)
        if key in seen_conds:
            results.append(
                _result(
                    "BN403",
                    Severity.WARNING,
                    f"conditions[{i}] duplicates conditions[{seen_conds[key]}]",
                    phase,
                    ref,
                    field="conditions",
                )
            )
        else:
            seen_conds[key] = i

    # Transformations (top-level, shared across conditions)
    transforms = rule.get("transformations", [])
    seen_transforms: set[str] = set()
    for t in transforms:
        if isinstance(t, str) and t not in TRANSFORMATION:
            results.append(
                _result(
                    "BN103",
                    Severity.WARNING,
                    f"Unknown transformation {t!r}",
                    phase,
                    ref,
                    field="transformations",
                )
            )
        # BN125: duplicate transformation
        if isinstance(t, str):
            if t in seen_transforms:
                results.append(
                    _result(
                        "BN125",
                        Severity.WARNING,
                        f"Duplicate transformation {t!r}",
                        phase,
                        ref,
                        field="transformations",
                    )
                )
            seen_transforms.add(t)

    # BN122: Redundant LOWERCASE transformation with case-insensitive operators
    if "lowercase" in seen_transforms and conditions:
        for cond in conditions:
            op = cond.get("operator", "")
            if isinstance(op, str) and op in _CASE_INSENSITIVE_OPERATORS:
                results.append(
                    _result(
                        "BN122",
                        Severity.INFO,
                        f"Redundant LOWERCASE transformation: operator {op!r} is case-insensitive",
                        phase,
                        ref,
                        field="transformations",
                        suggestion="Remove LOWERCASE transformation, or switch to "
                        "str_match if case-sensitive matching is needed",
                    )
                )
                # Only report once per rule
                break


def _validate_rate_limit_rule(rule: dict, results: list[LintResult], phase: str) -> None:
    """Validate a single rate limit rule."""
    ref = str(rule.get("ref", ""))

    # Reuse custom rule validation for shared fields
    _validate_custom_rule(rule, results, phase)

    # BN200: request_count
    rc = rule.get("request_count")
    if rc is None:
        results.append(_result("BN200", Severity.ERROR, "Missing 'request_count'", phase, ref))
    elif not isinstance(rc, int) or isinstance(rc, bool) or rc < 1:
        results.append(
            _result(
                "BN200",
                Severity.ERROR,
                f"request_count must be a positive integer, got {rc!r}",
                phase,
                ref,
                field="request_count",
            )
        )

    # BN201: timeframe
    tf = rule.get("timeframe")
    if not tf:
        results.append(
            _result("BN201", Severity.ERROR, "Missing 'timeframe'", phase, ref, field="timeframe")
        )
    elif isinstance(tf, str) and tf not in TIMEFRAME:
        results.append(
            _result(
                "BN201",
                Severity.ERROR,
                f"Invalid timeframe {tf!r}",
                phase,
                ref,
                field="timeframe",
                suggestion=f"Valid: {sorted(TIMEFRAME)}",
            )
        )

    # BN202: block_time
    bt = rule.get("block_time")
    if not bt:
        results.append(
            _result("BN202", Severity.ERROR, "Missing 'block_time'", phase, ref, field="block_time")
        )
    elif isinstance(bt, str) and bt not in BLOCKTIME:
        results.append(
            _result(
                "BN202",
                Severity.ERROR,
                f"Invalid block_time {bt!r}",
                phase,
                ref,
                field="block_time",
                suggestion=f"Valid: {sorted(BLOCKTIME)}",
            )
        )

    # BN210: very short block_time
    if bt == "30s":
        results.append(
            _result(
                "BN210",
                Severity.WARNING,
                "Very short block_time (30s)",
                phase,
                ref,
                field="block_time",
            )
        )

    # BN203: counter_key_type
    ck = rule.get("counter_key_type")
    if not ck:
        results.append(
            _result(
                "BN203",
                Severity.ERROR,
                "Missing 'counter_key_type'",
                phase,
                ref,
                field="counter_key_type",
            )
        )
    elif isinstance(ck, str) and ck not in COUNTER_KEY:
        results.append(
            _result(
                "BN203",
                Severity.ERROR,
                f"Invalid counter_key_type {ck!r}",
                phase,
                ref,
                field="counter_key_type",
                suggestion=f"Valid: {sorted(COUNTER_KEY)}",
            )
        )


# ---------------------------------------------------------------------------
# Access list validation
# ---------------------------------------------------------------------------
def _validate_access_list(rule: dict, results: list[LintResult], phase: str) -> None:
    """Validate a single access list rule."""
    ref = str(rule.get("ref", ""))

    if not ref:
        results.append(_result("BN001", Severity.ERROR, "Rule missing 'ref'", phase))
        return

    # BN004: unknown fields
    unknown = set(rule) - _ACCESS_LIST_FIELDS - {"_api_id", "shieldZoneId"}
    for field_name in sorted(unknown):
        results.append(
            _result(
                "BN004",
                Severity.WARNING,
                f"Unknown top-level field: {field_name!r}",
                phase,
                ref,
                field=field_name,
            )
        )

    # BN300: type
    list_type = rule.get("type", "")
    if not list_type:
        results.append(_result("BN300", Severity.ERROR, "Access list missing 'type'", phase, ref))
    elif isinstance(list_type, str) and list_type not in ACCESS_LIST_TYPE:
        results.append(
            _result(
                "BN300",
                Severity.ERROR,
                f"Invalid access list type {list_type!r}",
                phase,
                ref,
                field="type",
                suggestion=f"Valid: {sorted(ACCESS_LIST_TYPE)}",
            )
        )

    # BN005: enabled must be bool
    enabled = rule.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        results.append(
            _result(
                "BN005",
                Severity.ERROR,
                f"enabled must be a boolean, got {type(enabled).__name__}",
                phase,
                ref,
                field="enabled",
            )
        )

    # BN602: disabled access list
    if enabled is False:
        results.append(
            _result(
                "BN602",
                Severity.INFO,
                "Access list is disabled (enabled: false)",
                phase,
                ref,
                field="enabled",
            )
        )

    # BN100: action
    action = rule.get("action", "")
    if not action:
        results.append(_result("BN003", Severity.ERROR, "Access list missing 'action'", phase, ref))
    elif isinstance(action, str) and action not in ACTION:
        results.append(
            _result(
                "BN100",
                Severity.ERROR,
                f"Invalid action {action!r}",
                phase,
                ref,
                suggestion=f"Valid: {sorted(ACTION)}",
            )
        )

    # BN301: content
    content = rule.get("content", "")
    if not content or not str(content).strip():
        results.append(
            _result("BN301", Severity.ERROR, "Access list has empty content", phase, ref)
        )
        return

    entries = [line.strip() for line in str(content).splitlines() if line.strip()]

    # Type-specific content validation
    valid_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if list_type == "cidr":
        for entry in entries:
            # BN311: catch-all CIDR (runs before strict-vs-loose parse so it
            # fires cleanly regardless of parse outcome).
            if entry in _CATCH_ALL_CIDRS:
                results.append(
                    _result(
                        "BN311",
                        Severity.WARNING,
                        f"Catch-all CIDR {entry!r} matches every address",
                        phase,
                        ref,
                        field="content",
                    )
                )
            try:
                net_strict = ipaddress.ip_network(entry, strict=True)
                valid_nets.append(net_strict)
                # BN305: private/reserved ranges
                priv_desc = is_reserved(entry)
                if priv_desc:
                    results.append(
                        _result(
                            "BN305",
                            Severity.WARNING,
                            f"Private/reserved IP range: {entry!r} ({priv_desc})",
                            phase,
                            ref,
                            field="content",
                        )
                    )
            except ValueError:
                # BN306: CIDR has host bits set
                try:
                    net_loose = ipaddress.ip_network(entry, strict=False)
                    valid_nets.append(net_loose)
                    results.append(
                        _result(
                            "BN306",
                            Severity.WARNING,
                            f"CIDR has host bits set: {entry!r} (did you mean {net_loose}?)",
                            phase,
                            ref,
                            field="content",
                        )
                    )
                    priv_desc = is_reserved(entry)
                    if priv_desc:
                        results.append(
                            _result(
                                "BN305",
                                Severity.WARNING,
                                f"Private/reserved IP range: {entry!r} ({priv_desc})",
                                phase,
                                ref,
                                field="content",
                            )
                        )
                except ValueError:
                    results.append(
                        _result(
                            "BN302",
                            Severity.WARNING,
                            f"Invalid CIDR notation: {entry!r}",
                            phase,
                            ref,
                            field="content",
                        )
                    )

        # BN307: overlapping CIDRs within the same access list.  Uses a
        # sweep-line algorithm (O(n log n)) — large access lists need
        # efficient overlap detection to keep lint fast.  Skip catch-all
        # entries (0.0.0.0/0, ::/0); those are handled by BN311 and would
        # otherwise spam BN307 against every other entry.
        overlap_nets = [n for n in valid_nets if str(n) not in _CATCH_ALL_CIDRS]
        v4_nets = sorted(
            (n for n in overlap_nets if n.version == 4),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        v6_nets = sorted(
            (n for n in overlap_nets if n.version == 6),
            key=lambda n: (int(n.network_address), n.prefixlen),
        )
        for sorted_group in (v4_nets, v6_nets):
            active: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
            for net in sorted_group:
                # Pop networks whose range we've passed.
                while active and int(active[-1].broadcast_address) < int(net.network_address):
                    active.pop()
                if active:
                    parent = active[-1]
                    if net != parent:
                        results.append(
                            _result(
                                "BN307",
                                Severity.WARNING,
                                f"Overlapping CIDRs: {parent} and {net}",
                                phase,
                                ref,
                                field="content",
                            )
                        )
                active.append(net)

        # BN309: duplicate CIDRs (normalised so 10.0.0.1/24 == 10.0.0.0/24)
        seen_cidrs: set[str] = set()
        for net in valid_nets:
            key = str(net)
            if key in seen_cidrs:
                results.append(
                    _result(
                        "BN309",
                        Severity.WARNING,
                        f"Duplicate CIDR in access list: {key}",
                        phase,
                        ref,
                        field="content",
                    )
                )
            else:
                seen_cidrs.add(key)

    elif list_type == "ip":
        for entry in entries:
            try:
                ipaddress.ip_address(entry)
                priv_desc = is_reserved(entry)
                if priv_desc:
                    results.append(
                        _result(
                            "BN305",
                            Severity.WARNING,
                            f"Private/reserved IP address: {entry!r} ({priv_desc})",
                            phase,
                            ref,
                            field="content",
                        )
                    )
            except ValueError:
                try:
                    ipaddress.ip_network(entry, strict=False)
                    priv_desc = is_reserved(entry)
                    if priv_desc:
                        results.append(
                            _result(
                                "BN305",
                                Severity.WARNING,
                                f"Private/reserved IP range: {entry!r} ({priv_desc})",
                                phase,
                                ref,
                                field="content",
                            )
                        )
                except ValueError:
                    results.append(
                        _result(
                            "BN302",
                            Severity.WARNING,
                            f"Invalid IP address: {entry!r}",
                            phase,
                            ref,
                            field="content",
                        )
                    )

        # BN309: duplicate IP entries (IPv6 lowercased for case-insensitive match)
        seen_ips: set[str] = set()
        for entry in entries:
            normalized = entry.strip().lower()
            if normalized in seen_ips:
                results.append(
                    _result(
                        "BN309",
                        Severity.WARNING,
                        f"Duplicate IP in access list: {normalized}",
                        phase,
                        ref,
                        field="content",
                    )
                )
            else:
                seen_ips.add(normalized)

    elif list_type == "organization":
        # BN310: duplicate organization entries (case-insensitive)
        seen_orgs: set[str] = set()
        for entry in entries:
            normalized = entry.strip().lower()
            if normalized in seen_orgs:
                results.append(
                    _result(
                        "BN310",
                        Severity.WARNING,
                        f"Duplicate organization entry in access list: {normalized}",
                        phase,
                        ref,
                        field="content",
                    )
                )
            else:
                seen_orgs.add(normalized)

    elif list_type == "asn":
        for entry in entries:
            clean = entry.upper().removeprefix("AS")
            if not clean.isdigit():
                results.append(
                    _result(
                        "BN303",
                        Severity.WARNING,
                        f"Invalid ASN format: {entry!r} (expected numeric or AS-prefixed)",
                        phase,
                        ref,
                        field="content",
                    )
                )

    elif list_type == "country":
        for entry in entries:
            if not _COUNTRY_CODE_RE.fullmatch(entry):
                results.append(
                    _result(
                        "BN304",
                        Severity.WARNING,
                        f"Invalid country code: {entry!r} (expected 2 uppercase letters)",
                        phase,
                        ref,
                        field="content",
                    )
                )

    elif list_type == "ja4":
        for entry in entries:
            if not _JA4_RE.fullmatch(entry):
                if len(entry) != 36:
                    reason = f"must be 36 characters, got {len(entry)}"
                elif entry.count("_") != 2:
                    reason = "must have format a_b_c (3 underscore-separated sections)"
                else:
                    reason = (
                        "invalid format (expected: <proto><ver><sni><cc><ec><alpn>_<hash>_<hash>)"
                    )
                results.append(
                    _result(
                        "BN308",
                        Severity.WARNING,
                        f"Invalid JA4 fingerprint: {entry!r} ({reason})",
                        phase,
                        ref,
                        field="content",
                    )
                )


# ---------------------------------------------------------------------------
# Edge rule validation
# ---------------------------------------------------------------------------
_EDGE_RULE_FIELDS = frozenset(
    {
        "ref",
        "enabled",
        "description",
        "action_type",
        "action_parameter_1",
        "action_parameter_2",
        "trigger_matching_type",
        "triggers",
    }
)

_EDGE_TRIGGER_FIELDS = frozenset(
    {"type", "pattern_matching_type", "pattern_matches", "parameter_1"}
)


def _validate_edge_rule(rule: dict, results: list[LintResult], phase: str) -> None:
    """Validate a single edge rule."""
    ref = str(rule.get("ref", ""))

    # BN001: missing ref
    if not ref:
        results.append(_result("BN001", Severity.ERROR, "Rule missing 'ref'", phase))
        return

    # BN004: unknown top-level fields
    unknown = set(rule) - _EDGE_RULE_FIELDS - {"_api_id", "Guid"}
    for field_name in sorted(unknown):
        results.append(
            _result(
                "BN004",
                Severity.WARNING,
                f"Unknown top-level field: {field_name!r}",
                phase,
                ref,
                field=field_name,
            )
        )

    # BN005: enabled must be bool
    enabled = rule.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        results.append(
            _result(
                "BN005",
                Severity.ERROR,
                f"enabled must be a boolean, got {type(enabled).__name__}",
                phase,
                ref,
                field="enabled",
            )
        )

    # BN700: invalid action_type
    action_type = rule.get("action_type", "")
    if not action_type:
        results.append(
            _result("BN700", Severity.ERROR, "Edge rule missing 'action_type'", phase, ref)
        )
    elif isinstance(action_type, str) and action_type not in EDGE_ACTION:
        results.append(
            _result(
                "BN700",
                Severity.ERROR,
                f"Invalid edge rule action_type {action_type!r}",
                phase,
                ref,
                field="action_type",
                suggestion=f"Valid: {sorted(EDGE_ACTION)}",
            )
        )

    # BN706: action parameter requirements
    _REQUIRES_PARAM1 = frozenset(
        {
            "redirect",
            "set_response_header",
            "set_request_header",
            "set_status_code",
            "override_cache_time",
            "override_cache_time_public",
            "override_browser_cache_time",
            "set_network_rate_limit",
            "set_connection_limit",
            "set_requests_per_second_limit",
            "remove_browser_cache_response_header",
            "override_browser_cache_response_header",
            "origin_url",
            "run_edge_script",
        }
    )
    _REQUIRES_PARAM2 = frozenset(
        {
            "redirect",
            "set_response_header",
            "set_request_header",
        }
    )
    if isinstance(action_type, str) and action_type in EDGE_ACTION:
        param1 = rule.get("action_parameter_1", "")
        param2 = rule.get("action_parameter_2", "")
        p1_empty = not param1 or (isinstance(param1, str) and not param1.strip())
        p2_empty = not param2 or (isinstance(param2, str) and not param2.strip())
        if action_type in _REQUIRES_PARAM1 and p1_empty:
            results.append(
                _result(
                    "BN706",
                    Severity.ERROR,
                    f"Edge rule action {action_type!r} requires action_parameter_1",
                    phase,
                    ref,
                    field="action_parameter_1",
                )
            )
        if action_type in _REQUIRES_PARAM2 and p2_empty:
            results.append(
                _result(
                    "BN706",
                    Severity.ERROR,
                    f"Edge rule action {action_type!r} requires action_parameter_2",
                    phase,
                    ref,
                    field="action_parameter_2",
                )
            )

        # BN715: redirect status code must be 300-399
        if action_type == "redirect" and not p2_empty and isinstance(param2, str):
            try:
                code = int(param2)
                if code < 300 or code >= 400:
                    raise ValueError("not a 3xx")
            except (ValueError, TypeError):
                results.append(
                    _result(
                        "BN715",
                        Severity.ERROR,
                        f"Redirect status code {param2!r} must be an integer in 300-399",
                        phase,
                        ref,
                        field="action_parameter_2",
                    )
                )

    # BN703: invalid trigger_matching_type
    tmt = rule.get("trigger_matching_type", "")
    if tmt and isinstance(tmt, str) and tmt not in EDGE_TRIGGER_MATCH:
        results.append(
            _result(
                "BN703",
                Severity.ERROR,
                f"Invalid trigger_matching_type {tmt!r}",
                phase,
                ref,
                field="trigger_matching_type",
                suggestion=f"Valid: {sorted(EDGE_TRIGGER_MATCH)}",
            )
        )

    # BN702: triggers must be a non-empty list
    triggers = rule.get("triggers", [])
    if not triggers:
        results.append(_result("BN702", Severity.ERROR, "Edge rule has no triggers", phase, ref))
    elif not isinstance(triggers, list):
        results.append(_result("BN005", Severity.ERROR, "triggers must be a list", phase, ref))
        triggers = []

    for i, trigger in enumerate(triggers):
        prefix = f"triggers[{i}]"

        # BN701: invalid trigger type
        ttype = trigger.get("type", "")
        if not ttype:
            results.append(
                _result(
                    "BN701",
                    Severity.ERROR,
                    f"{prefix}: missing 'type'",
                    phase,
                    ref,
                    field="triggers",
                )
            )
        elif isinstance(ttype, str) and ttype not in EDGE_TRIGGER:
            results.append(
                _result(
                    "BN701",
                    Severity.ERROR,
                    f"{prefix}: invalid trigger type {ttype!r}",
                    phase,
                    ref,
                    field="triggers",
                    suggestion=f"Valid: {sorted(EDGE_TRIGGER)}",
                )
            )

        # BN704: pattern_matches must be non-empty
        patterns = trigger.get("pattern_matches", [])
        if not patterns:
            results.append(
                _result(
                    "BN704",
                    Severity.WARNING,
                    f"{prefix}: pattern_matches is empty",
                    phase,
                    ref,
                    field="triggers",
                )
            )
        elif not isinstance(patterns, list):
            results.append(
                _result(
                    "BN005",
                    Severity.ERROR,
                    f"{prefix}: pattern_matches must be a list",
                    phase,
                    ref,
                    field="triggers",
                )
            )

        # BN705: invalid pattern_matching_type
        pmt = trigger.get("pattern_matching_type", "")
        if pmt and isinstance(pmt, str) and pmt not in EDGE_PATTERN_MATCH:
            results.append(
                _result(
                    "BN705",
                    Severity.ERROR,
                    f"{prefix}: invalid pattern_matching_type {pmt!r}",
                    phase,
                    ref,
                    field="triggers",
                    suggestion=f"Valid: {sorted(EDGE_PATTERN_MATCH)}",
                )
            )

        # BN707-BN712: per-pattern content validation
        if isinstance(patterns, list):
            for pi, p in enumerate(patterns):
                if not isinstance(p, str):
                    continue
                p_prefix = f"{prefix}.pattern_matches[{pi}]"

                # BN707: empty or whitespace-only
                if not p.strip():
                    results.append(
                        _result(
                            "BN707",
                            Severity.ERROR,
                            f"{p_prefix}: empty or whitespace-only pattern",
                            phase,
                            ref,
                            field="triggers",
                        )
                    )
                    continue  # skip further checks on empty patterns

                # BN712: Lua pattern validation (pattern: prefix)
                if p.startswith("pattern:"):
                    err = _check_lua_pattern(p[len("pattern:") :])
                    if err:
                        results.append(
                            _result(
                                "BN712",
                                Severity.ERROR,
                                f"{p_prefix}: malformed Lua pattern — {err}",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )
                    continue  # Lua patterns bypass per-type checks below

                # Per-trigger-type validation (only for literal patterns)
                if ttype == "url":
                    # BN713: URL patterns must start with /, http, or *
                    if not (p.startswith("/") or p.startswith("http") or p.startswith("*")):
                        results.append(
                            _result(
                                "BN713",
                                Severity.WARNING,
                                f"{p_prefix}: URL pattern {p!r} should start with "
                                "'/', 'http', or '*' — patterns without these prefixes "
                                "will not match any URL",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )
                elif ttype == "country_code":
                    if not _COUNTRY_CODE_RE.fullmatch(p):
                        results.append(
                            _result(
                                "BN708",
                                Severity.ERROR,
                                f"{p_prefix}: invalid country code {p!r}"
                                f" (expected 2 uppercase letters)",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )
                elif ttype == "remote_ip":
                    try:
                        ipaddress.ip_network(p, strict=False)
                    except ValueError:
                        results.append(
                            _result(
                                "BN709",
                                Severity.ERROR,
                                f"{p_prefix}: invalid IP or CIDR {p!r}",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )
                elif ttype == "request_method":
                    if p not in _HTTP_METHODS:
                        results.append(
                            _result(
                                "BN710",
                                Severity.ERROR,
                                f"{p_prefix}: invalid HTTP method {p!r}"
                                f" (valid: {sorted(_HTTP_METHODS)})",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )
                elif ttype == "status_code":
                    try:
                        code = int(p)
                        if code < 100 or code > 900:
                            raise ValueError("out of range")
                    except (ValueError, TypeError):
                        results.append(
                            _result(
                                "BN711",
                                Severity.ERROR,
                                f"{p_prefix}: status code {p!r} must be"
                                f" an integer between 100 and 900",
                                phase,
                                ref,
                                field="triggers",
                            )
                        )

    # BN601: missing description
    if not rule.get("description", ""):
        results.append(_result("BN601", Severity.INFO, "Rule has no description", phase, ref))

    # BN011: description too long
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_DESCRIPTION_LEN:
        results.append(
            _result(
                "BN011",
                Severity.WARNING,
                f"Description exceeds {_MAX_DESCRIPTION_LEN} characters ({len(desc)})",
                phase,
                ref,
                field="description",
            )
        )


# ---------------------------------------------------------------------------
# Cross-rule overlap validation
# ---------------------------------------------------------------------------
def _validate_cross_rule_cidr_overlap(
    rules: list[dict], results: list[LintResult], phase: str
) -> None:
    """BN504: Detect CIDR overlap across access lists in the same phase.

    When multiple access lists reference overlapping CIDRs with different
    actions (e.g., allow in one, block in another), the evaluation order
    determines which rule wins. This creates subtle bugs if the order changes.

    Algorithm: collect every CIDR from access lists, group by IP version,
    sweep-line in O(n log n). Catch-all entries (0.0.0.0/0, ::/0) are
    skipped — those don't produce false positives anyway. Only report if
    actions differ (same action = redundant but not conflicting).
    """
    if not phase.endswith("access_list_rules"):
        return

    # Terminal actions: block/allow determine the outcome; log is non-terminal
    _TERMINAL_ACTIONS = frozenset({"block", "allow"})

    # Collect: (list_ref, action, cidr_str, parsed_network)
    entries: list[tuple[str, str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        action = str(rule.get("action", ""))
        list_type = str(rule.get("type", ""))

        # Only CIDR-based access lists can overlap
        if list_type != "cidr":
            continue

        content = rule.get("content", "")
        if not content or not str(content).strip():
            continue

        for entry in str(content).splitlines():
            entry = entry.strip()
            if not entry or entry in _CATCH_ALL_CIDRS:
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
                entries.append((ref, action, entry, net))
            except ValueError:
                continue  # BN302 handles invalid CIDRs

    if len(entries) < 2:
        return

    # Group by IP version (IPv4 and IPv6 can't overlap)
    from collections import defaultdict

    groups: dict[int, list[tuple[str, str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]]] = (
        defaultdict(list)
    )
    for ref, action, cidr, net in entries:
        groups[net.version].append((ref, action, cidr, net))

    seen_pairs: set[tuple[str, str, str, str]] = set()
    for items in groups.values():
        if len(items) < 2:
            continue
        # Sort by network address, then prefix (broadest first)
        items_sorted = sorted(items, key=lambda x: (int(x[3].network_address), x[3].prefixlen))
        active: list[tuple[str, str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for ref, action, cidr, net in items_sorted:
            while active and int(active[-1][3].broadcast_address) < int(net.network_address):
                active.pop()
            if active:
                parent_ref, parent_action, parent_cidr, parent_net = active[-1]
                # Only flag if from different lists AND actions differ (terminal mismatch)
                if (
                    parent_ref != ref
                    and parent_action in _TERMINAL_ACTIONS
                    and action in _TERMINAL_ACTIONS
                    and parent_action != action
                ):
                    pair_key = (parent_ref, parent_cidr, ref, cidr)
                    if pair_key not in seen_pairs:
                        seen_pairs.add(pair_key)
                        if net == parent_net:
                            msg = (
                                f"Duplicate CIDR across access lists with different actions: "
                                f"{cidr!r} in {ref!r} ({action}) also appears in {parent_ref!r} "
                                f"({parent_action})"
                            )
                        else:
                            msg = (
                                f"Overlapping CIDRs across access lists with different actions: "
                                f"{cidr!r} in {ref!r} ({action}) is contained in {parent_cidr!r} "
                                f"from {parent_ref!r} ({parent_action})"
                            )
                        results.append(
                            _result(
                                "BN504",
                                Severity.WARNING,
                                msg,
                                phase,
                                ref=ref,
                                field="content",
                                suggestion=(
                                    "Verify evaluation order or remove one of the overlapping lists"
                                ),
                            )
                        )
            active.append((ref, action, cidr, net))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate a list of Bunny Shield rules. Returns a list of issues."""
    results: list[LintResult] = []
    seen_refs: dict[str, int] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            results.append(_result("BN006", Severity.ERROR, "Rule entry is not a dict", phase))
            continue

        ref = str(rule.get("ref", ""))

        # BN002: duplicate ref
        if ref:
            seen_refs[ref] = seen_refs.get(ref, 0) + 1
            if seen_refs[ref] == 2:
                results.append(
                    _result("BN002", Severity.ERROR, f"Duplicate ref {ref!r}", phase, ref)
                )

        if phase.endswith("edge_rules"):
            _validate_edge_rule(rule, results, phase)
        elif phase.endswith("access_list_rules"):
            _validate_access_list(rule, results, phase)
        elif phase.endswith("rate_limit_rules"):
            _validate_rate_limit_rule(rule, results, phase)
        else:
            _validate_custom_rule(rule, results, phase)

    # BN504: Cross-rule CIDR overlap (access list phase only)
    _validate_cross_rule_cidr_overlap(rules, results, phase)

    return results
