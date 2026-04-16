"""Bidirectional enum maps for the Bunny Shield WAF API.

Every ``EnumMap`` wraps a single ``{int: str}`` mapping and exposes
``.resolve()`` (int → str) and ``.unresolve()`` (str → int).  Unknown
values are kept as-is and flagged by the BN1xx lint rules.
"""


# ---------------------------------------------------------------------------
# EnumMap
# ---------------------------------------------------------------------------
class EnumMap:
    """Lightweight bidirectional int ↔ str mapping.

    Usage::

        ACTION = EnumMap({1: "block", 2: "log", ...})
        ACTION.resolve(1)        # "block"
        ACTION.unresolve("log")  # 2
        "block" in ACTION        # True
        len(ACTION)              # 2
        list(ACTION)             # ["block", "log"]
    """

    __slots__ = ("_fwd", "_rev")

    def __init__(self, mapping: dict[int, str]) -> None:
        self._fwd: dict[int, str] = dict(mapping)
        self._rev: dict[str, int] = {}
        for k, v in mapping.items():
            if v in self._rev:
                raise ValueError(f"duplicate string value {v!r}")
            self._rev[v] = k

    def resolve(self, value: int | str) -> str:
        """Resolve an API enum int to its string name, or pass through str."""
        if isinstance(value, str):
            return value
        return self._fwd.get(value, str(value))

    def unresolve(self, value: str | int) -> int | str:
        """Resolve a string name to its API enum int, or pass through int.

        Returns ``str`` when *value* is not in the mapping and not already
        an int — the BN1xx lint rules catch unknown enum values before sync.
        """
        if isinstance(value, int):
            return value
        return self._rev.get(value, value)

    def items(self) -> list[tuple[int, str]]:
        """Return ``(int, str)`` pairs like ``dict.items()``."""
        return list(self._fwd.items())

    # -- Container protocol --

    def __contains__(self, item: str) -> bool:
        return item in self._rev

    def __iter__(self):
        return iter(self._rev)

    def __len__(self) -> int:
        return len(self._fwd)

    def __repr__(self) -> str:
        return f"EnumMap({self._fwd!r})"


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
ACTION = EnumMap(
    {
        1: "block",
        2: "log",
        3: "challenge",
        4: "allow",
        5: "bypass",
    }
)

# Access list actions use a DIFFERENT numbering from WAF rule actions.
# Source: GET /shield/shield-zone/{id}/access-lists/enums → AccessListAction
ACCESS_LIST_ACTION = EnumMap(
    {
        1: "allow",
        2: "block",
        3: "challenge",
        4: "log",
        5: "bypass",
    }
)

# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------
OPERATOR = EnumMap(
    {
        0: "begins_with",
        1: "ends_with",
        2: "contains",
        3: "contains_word",
        4: "str_match",
        5: "eq",
        6: "ge",
        7: "gt",
        8: "le",
        9: "lt",
        12: "within",
        14: "rx",
        15: "str_eq",
        17: "detect_sqli",
        18: "detect_xss",
    }
)

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
VARIABLE = EnumMap(
    {
        0: "request_uri",
        1: "request_uri_raw",
        2: "args",
        3: "args_combined_size",
        4: "args_get",
        5: "args_get_names",
        6: "args_post",
        7: "args_post_names",
        8: "files_names",
        9: "geo",
        10: "remote_addr",
        11: "query_string",
        12: "request_basename",
        13: "request_body",
        14: "request_cookies_names",
        15: "request_cookies",
        16: "request_filename",
        17: "request_headers_names",
        18: "request_headers",
        19: "request_line",
        20: "request_method",
        21: "request_protocol",
        22: "response_body",
        23: "response_headers",
        24: "response_status",
        25: "fingerprint",
    }
)

# Variables that accept a sub-value (e.g., header name, cookie name, GEO field).
VARIABLES_WITH_SUBVALUE: frozenset[str] = frozenset(
    {
        "args",
        "args_get",
        "args_post",
        "geo",
        "request_cookies",
        "request_headers",
        "response_headers",
    }
)

# Valid GEO sub-values.
GEO_SUBVALUES: frozenset[str] = frozenset(
    {"COUNTRY_CODE", "LATITUDE", "LONGITUDE", "ASN", "CITY", "CONTINENT"}
)

# ---------------------------------------------------------------------------
# Transformations
# ---------------------------------------------------------------------------
TRANSFORMATION = EnumMap(
    {
        1: "cmdline",
        2: "compress_whitespace",
        3: "css_decode",
        4: "hex_encode",
        5: "html_entity_decode",
        6: "js_decode",
        7: "length",
        8: "lowercase",
        9: "md5",
        10: "normalize_path",
        11: "normalise_path",
        12: "normalize_path_win",
        13: "normalise_path_win",
        14: "remove_comments",
        15: "remove_nulls",
        16: "remove_whitespace",
        17: "replace_comments",
        18: "sha1",
        19: "url_decode",
        20: "url_decode_uni",
        21: "utf8_to_unicode",
    }
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
SEVERITY = EnumMap(
    {
        0: "info",
        1: "warning",
        2: "error",
    }
)

# ---------------------------------------------------------------------------
# Rate limit timeframes (in seconds)
# ---------------------------------------------------------------------------
TIMEFRAME = EnumMap(
    {
        1: "1s",
        10: "10s",
        60: "1m",
        300: "5m",
        900: "15m",
        3600: "1h",
    }
)

# ---------------------------------------------------------------------------
# Rate limit block times (in seconds)
# ---------------------------------------------------------------------------
BLOCKTIME = EnumMap(
    {
        30: "30s",
        60: "1m",
        300: "5m",
        900: "15m",
        1800: "30m",
        3600: "1h",
    }
)

# ---------------------------------------------------------------------------
# Access list types
# ---------------------------------------------------------------------------
ACCESS_LIST_TYPE = EnumMap(
    {
        0: "ip",
        1: "cidr",
        2: "asn",
        3: "country",
        4: "organization",
        5: "ja4",
    }
)

# ---------------------------------------------------------------------------
# Rate limit counter key types
# ---------------------------------------------------------------------------
COUNTER_KEY = EnumMap(
    {
        0: "ip",
        1: "path",
        2: "header",
        3: "cookie",
        4: "query",
        5: "body",
        6: "fingerprint",
        7: "global",
    }
)

# ---------------------------------------------------------------------------
# Bot detection / DDoS config enum helpers
# ---------------------------------------------------------------------------
EXECUTION_MODE = EnumMap({0: "off", 1: "log", 2: "block"})

SENSITIVITY = EnumMap({0: "off", 1: "low", 2: "medium", 3: "high"})


# ---------------------------------------------------------------------------
# Edge Rule action types (CDN-level, NOT Shield WAF actions)
# ---------------------------------------------------------------------------
EDGE_ACTION = EnumMap(
    {
        0: "force_ssl",
        1: "redirect",
        2: "origin_url",
        3: "override_cache_time",
        4: "block_request",
        5: "set_response_header",
        6: "set_request_header",
        7: "force_download",
        8: "disable_token_auth",
        9: "enable_token_auth",
        10: "override_cache_time_public",
        11: "ignore_query_string",
        12: "disable_optimizer",
        13: "force_compression",
        14: "set_status_code",
        15: "bypass_perma_cache",
        16: "override_browser_cache_time",
        17: "origin_storage",
        18: "set_network_rate_limit",
        19: "set_connection_limit",
        20: "set_requests_per_second_limit",
        21: "run_edge_script",
        22: "origin_magic_containers",
        23: "disable_waf",
        24: "retry_origin",
        25: "override_browser_cache_response_header",
        26: "remove_browser_cache_response_header",
        27: "disable_shield_challenge",
        28: "disable_shield",
        29: "disable_shield_bot_detection",
        30: "bypass_aws_s3_authentication",
        31: "disable_shield_access_lists",
        32: "disable_shield_rate_limiting",
        33: "enable_request_coalescing",
        34: "disable_request_coalescing",
    }
)

# ---------------------------------------------------------------------------
# Edge Rule trigger types
# ---------------------------------------------------------------------------
EDGE_TRIGGER = EnumMap(
    {
        0: "url",
        1: "request_header",
        2: "response_header",
        3: "url_extension",
        4: "country_code",
        5: "remote_ip",
        6: "url_query_string",
        7: "random_chance",
        8: "status_code",
        9: "request_method",
        10: "cookie",
        11: "country_state_code",
        12: "origin_retry_attempt_count",
        13: "origin_connection_error",
    }
)

# ---------------------------------------------------------------------------
# Edge Rule pattern matching types
# ---------------------------------------------------------------------------
EDGE_PATTERN_MATCH = EnumMap(
    {
        0: "any",
        1: "all",
        2: "none",
    }
)

# ---------------------------------------------------------------------------
# Edge Rule trigger matching types (top-level: how triggers are combined)
# ---------------------------------------------------------------------------
EDGE_TRIGGER_MATCH = EnumMap(
    {
        0: "any",
        1: "all",
        2: "none",
    }
)
