"""Offline validation for Bunny Shield WAF rules."""

import ipaddress
import json
import re

from octorules.linter.engine import LintResult, Severity

from octorules_bunny._enums import (
    GEO_SUBVALUES,
    STR_TO_ACCESS_LIST_TYPE,
    STR_TO_ACTION,
    STR_TO_BLOCKTIME,
    STR_TO_COUNTER_KEY,
    STR_TO_EDGE_ACTION,
    STR_TO_EDGE_PATTERN_MATCH,
    STR_TO_EDGE_TRIGGER,
    STR_TO_EDGE_TRIGGER_MATCH,
    STR_TO_OPERATOR,
    STR_TO_SEVERITY,
    STR_TO_TIMEFRAME,
    STR_TO_TRANSFORMATION,
    STR_TO_VARIABLE,
    VARIABLES_WITH_SUBVALUE,
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
_DETECT_OPERATORS = frozenset({"detect_sqli", "detect_xss"})
_NUMERIC_OPERATORS = frozenset({"eq", "ge", "gt", "le", "lt"})
_MAX_DESCRIPTION_LEN = 255
_MAX_CHAINED_CONDITIONS = 10

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

# Private/reserved IP ranges.
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


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


def _is_private_ip(addr_str: str) -> bool:
    """Check if an IP or CIDR falls within private/reserved ranges."""
    try:
        net = ipaddress.ip_network(addr_str, strict=False)
    except ValueError:
        return False
    return any(net.subnet_of(priv) for priv in _PRIVATE_RANGES if net.version == priv.version)


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
    elif isinstance(var, str) and var not in STR_TO_VARIABLE:
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
    elif isinstance(op, str) and op not in STR_TO_OPERATOR:
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
    if isinstance(op, str) and op in STR_TO_OPERATOR and op not in _DETECT_OPERATORS:
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

    # BN107: Numeric operators on non-numeric variables
    if (
        isinstance(op, str)
        and op in _NUMERIC_OPERATORS
        and isinstance(var, str)
        and var in STR_TO_VARIABLE
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

    # -- Sub-value validation --
    sub = cond.get("variable_value", "")

    # BN109: Sub-value on variable that doesn't support it
    if (
        sub
        and isinstance(var, str)
        and var in STR_TO_VARIABLE
        and var not in VARIABLES_WITH_SUBVALUE
    ):
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
    elif isinstance(action, str) and action not in STR_TO_ACTION:
        results.append(
            _result(
                "BN100", Severity.ERROR, f"Invalid action {action!r}", phase, ref, field="action"
            )
        )

    # BN104: severity
    sev = rule.get("severity", "")
    if sev and isinstance(sev, str) and sev not in STR_TO_SEVERITY:
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
        key = json.dumps(cond, sort_keys=True)
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
        if isinstance(t, str) and t not in STR_TO_TRANSFORMATION:
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
    elif isinstance(tf, str) and tf not in STR_TO_TIMEFRAME:
        results.append(
            _result(
                "BN201",
                Severity.ERROR,
                f"Invalid timeframe {tf!r}",
                phase,
                ref,
                field="timeframe",
                suggestion=f"Valid: {sorted(STR_TO_TIMEFRAME)}",
            )
        )

    # BN202: block_time
    bt = rule.get("block_time")
    if not bt:
        results.append(
            _result("BN202", Severity.ERROR, "Missing 'block_time'", phase, ref, field="block_time")
        )
    elif isinstance(bt, str) and bt not in STR_TO_BLOCKTIME:
        results.append(
            _result(
                "BN202",
                Severity.ERROR,
                f"Invalid block_time {bt!r}",
                phase,
                ref,
                field="block_time",
                suggestion=f"Valid: {sorted(STR_TO_BLOCKTIME)}",
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
    elif isinstance(ck, str) and ck not in STR_TO_COUNTER_KEY:
        results.append(
            _result(
                "BN203",
                Severity.ERROR,
                f"Invalid counter_key_type {ck!r}",
                phase,
                ref,
                field="counter_key_type",
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
    elif isinstance(list_type, str) and list_type not in STR_TO_ACCESS_LIST_TYPE:
        results.append(
            _result(
                "BN300",
                Severity.ERROR,
                f"Invalid access list type {list_type!r}",
                phase,
                ref,
                field="type",
                suggestion=f"Valid: {sorted(STR_TO_ACCESS_LIST_TYPE)}",
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
    elif isinstance(action, str) and action not in STR_TO_ACTION:
        results.append(_result("BN100", Severity.ERROR, f"Invalid action {action!r}", phase, ref))

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
            try:
                net_strict = ipaddress.ip_network(entry, strict=True)
                valid_nets.append(net_strict)
                # BN305: private/reserved ranges
                if _is_private_ip(entry):
                    results.append(
                        _result(
                            "BN305",
                            Severity.WARNING,
                            f"Private/reserved IP range: {entry!r}",
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
                    if _is_private_ip(entry):
                        results.append(
                            _result(
                                "BN305",
                                Severity.WARNING,
                                f"Private/reserved IP range: {entry!r}",
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

        # BN307: overlapping CIDRs within the same access list
        for i, net_a in enumerate(valid_nets):
            for net_b in valid_nets[i + 1 :]:
                if net_a.version != net_b.version:
                    continue
                if net_a.overlaps(net_b) and net_a != net_b:
                    results.append(
                        _result(
                            "BN307",
                            Severity.WARNING,
                            f"Overlapping CIDRs: {net_a} and {net_b}",
                            phase,
                            ref,
                            field="content",
                        )
                    )

    elif list_type == "ip":
        for entry in entries:
            try:
                ipaddress.ip_address(entry)
                if _is_private_ip(entry):
                    results.append(
                        _result(
                            "BN305",
                            Severity.WARNING,
                            f"Private/reserved IP address: {entry!r}",
                            phase,
                            ref,
                            field="content",
                        )
                    )
            except ValueError:
                try:
                    ipaddress.ip_network(entry, strict=False)
                    if _is_private_ip(entry):
                        results.append(
                            _result(
                                "BN305",
                                Severity.WARNING,
                                f"Private/reserved IP range: {entry!r}",
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
    elif isinstance(action_type, str) and action_type not in STR_TO_EDGE_ACTION:
        results.append(
            _result(
                "BN700",
                Severity.ERROR,
                f"Invalid edge rule action_type {action_type!r}",
                phase,
                ref,
                field="action_type",
                suggestion=f"Valid: {sorted(STR_TO_EDGE_ACTION)}",
            )
        )

    # BN703: invalid trigger_matching_type
    tmt = rule.get("trigger_matching_type", "")
    if tmt and isinstance(tmt, str) and tmt not in STR_TO_EDGE_TRIGGER_MATCH:
        results.append(
            _result(
                "BN703",
                Severity.ERROR,
                f"Invalid trigger_matching_type {tmt!r}",
                phase,
                ref,
                field="trigger_matching_type",
                suggestion=f"Valid: {sorted(STR_TO_EDGE_TRIGGER_MATCH)}",
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
        elif isinstance(ttype, str) and ttype not in STR_TO_EDGE_TRIGGER:
            results.append(
                _result(
                    "BN701",
                    Severity.ERROR,
                    f"{prefix}: invalid trigger type {ttype!r}",
                    phase,
                    ref,
                    field="triggers",
                    suggestion=f"Valid: {sorted(STR_TO_EDGE_TRIGGER)}",
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
        if pmt and isinstance(pmt, str) and pmt not in STR_TO_EDGE_PATTERN_MATCH:
            results.append(
                _result(
                    "BN705",
                    Severity.ERROR,
                    f"{prefix}: invalid pattern_matching_type {pmt!r}",
                    phase,
                    ref,
                    field="triggers",
                    suggestion=f"Valid: {sorted(STR_TO_EDGE_PATTERN_MATCH)}",
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

    return results
