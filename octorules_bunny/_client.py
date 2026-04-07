"""Thin HTTP client for the Bunny.net Shield WAF API.

Handles authentication, pagination, retry on transient errors, and
exception classification.
"""

import logging
import time

import httpx
from octorules.retry import retry_with_backoff

log = logging.getLogger(__name__)

BASE_URL = "https://api.bunny.net"

# Safety cap to prevent infinite pagination.
_MAX_PAGES = 100

_RETRY_BACKOFF = (1.0, 2.0, 4.0)


# ---------------------------------------------------------------------------
# Exception types (internal — mapped to ProviderError subtypes by provider.py)
# ---------------------------------------------------------------------------
class BunnyAuthError(Exception):
    """Raised on 401/403 from the Bunny API."""


class BunnyAPIError(Exception):
    """Raised on non-retryable API errors (4xx other than 401/403/429)."""


class _TransientHTTPError(Exception):
    """Raised on 429/5xx — retryable by retry_with_backoff."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class BunnyShieldClient:
    """Thin HTTP client for the Bunny.net Shield and Pull Zone APIs.

    All methods return parsed JSON (dicts or lists).  Pagination is
    handled automatically.  Transient HTTP errors (429, 5xx) are retried
    with exponential backoff.
    """

    def __init__(
        self,
        api_key: str,
        *,
        timeout: float = 30.0,
        max_retries: int = 2,
        max_connections: int | None = None,
    ) -> None:
        client_kwargs: dict = {
            "base_url": BASE_URL,
            "headers": {"AccessKey": api_key, "Accept": "application/json"},
            "timeout": httpx.Timeout(timeout),
        }
        if max_connections is not None:
            client_kwargs["limits"] = httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max(20, max_connections // 2),
            )
        self._http = httpx.Client(**client_kwargs)
        self._max_retries = max_retries

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # -- Low-level request helpers ------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> dict | list:
        """Execute an HTTP request with retry on transient errors.

        Retryable errors: 429/5xx (via ``_TransientHTTPError``), transport
        errors, and ``ValueError`` from non-JSON responses (e.g., HTML
        maintenance pages on 200).  After all retries are exhausted the
        last exception propagates — ``ValueError`` is caught by the caller
        and wrapped as ``BunnyAPIError``.

        On 429 responses, the ``Retry-After`` header (seconds) is honoured:
        the client sleeps for ``max(0, retry_after - backoff_delay)`` before
        the normal retry backoff, so the total delay is at least
        ``max(retry_after, backoff_delay)``.
        """
        _retryable = (_TransientHTTPError, httpx.TransportError, ValueError)
        attempt_num = [0]

        def _do():
            cur = attempt_num[0]
            attempt_num[0] += 1
            try:
                resp = self._http.request(method, path, **kwargs)
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                _sleep_for_retry_after(exc.response, cur)
                _classify_http_error(exc)
            if resp.status_code == 204:
                return {}
            return resp.json()

        try:
            return retry_with_backoff(
                _do,
                retryable=_retryable,
                max_attempts=self._max_retries + 1,
                backoff=_RETRY_BACKOFF,
                label=f"{method} {path}",
            )
        except ValueError as exc:
            raise BunnyAPIError(f"Non-JSON response from {method} {path}: {exc}") from exc

    def _paginate(self, path: str, *, per_page: int = 50) -> list[dict]:
        """Fetch all pages from a paginated Shield API endpoint."""
        results: list[dict] = []
        for page_num in range(1, _MAX_PAGES + 1):
            body = self._request("GET", path, params={"page": page_num, "perPage": per_page})
            # Shield API wraps paginated data in various structures.
            if isinstance(body, list):
                items = body
                total_pages = 1
            elif isinstance(body, dict):
                items = body.get("data", body.get("items", []))
                if isinstance(items, dict):
                    items = list(items.values())
                page_info = body.get("page", {})
                if isinstance(page_info, dict):
                    total_pages = page_info.get("totalPages", 1)
                else:
                    total_pages = 1
            else:
                break

            if isinstance(items, list):
                results.extend(items)

            if page_num >= total_pages:
                break
        else:
            log.warning("Pagination exceeded %d pages for %s", _MAX_PAGES, path)

        return results

    # -- Pull Zone API (core, not Shield) -----------------------------------

    def list_pull_zones(self) -> list[dict]:
        """List all pull zones for the account."""
        return self._paginate("/pullzone")

    def get_pull_zone(self, pull_zone_id: int) -> dict:
        """Fetch a pull zone by ID."""
        return self._request("GET", f"/pullzone/{pull_zone_id}")

    def update_pull_zone(self, pull_zone_id: int, payload: dict) -> dict:
        """Update pull zone settings."""
        return self._request("POST", f"/pullzone/{pull_zone_id}", json=payload)

    # -- Edge Rules (CDN-level, on pull zone) --------------------------------

    def create_or_update_edge_rule(self, pull_zone_id: int, payload: dict) -> dict:
        """Create or update an edge rule on a pull zone."""
        return self._request(
            "POST", f"/pullzone/{pull_zone_id}/edgerules/addOrUpdate", json=payload
        )

    def delete_edge_rule(self, pull_zone_id: int, edge_rule_guid: str) -> None:
        """Delete an edge rule from a pull zone."""
        self._request("DELETE", f"/pullzone/{pull_zone_id}/edgerules/{edge_rule_guid}")

    # -- Shield Zone --------------------------------------------------------

    def get_shield_zone_by_pullzone(self, pull_zone_id: int) -> dict:
        """Get the Shield Zone associated with a pull zone."""
        return self._request("GET", f"/shield/shield-zone/get-by-pullzone/{pull_zone_id}")

    def get_shield_zone(self, shield_zone_id: int) -> dict:
        """Get a Shield Zone by ID."""
        return self._request("GET", f"/shield/shield-zone/{shield_zone_id}")

    def update_shield_zone(self, payload: dict) -> dict:
        """Update a Shield Zone's configuration."""
        return self._request("PATCH", "/shield/shield-zone", json=payload)

    # -- Custom WAF Rules ---------------------------------------------------

    def list_custom_waf_rules(self, shield_zone_id: int) -> list[dict]:
        """List all custom WAF rules for a shield zone."""
        return self._paginate(f"/shield/waf/custom-rules/{shield_zone_id}")

    def create_custom_waf_rule(self, payload: dict) -> dict:
        """Create a custom WAF rule."""
        return self._request("POST", "/shield/waf/custom-rule", json=payload)

    def update_custom_waf_rule(self, rule_id: int, payload: dict) -> dict:
        """Update a custom WAF rule."""
        return self._request("PATCH", f"/shield/waf/custom-rule/{rule_id}", json=payload)

    def delete_custom_waf_rule(self, rule_id: int) -> dict:
        """Delete a custom WAF rule."""
        return self._request("DELETE", f"/shield/waf/custom-rule/{rule_id}")

    # -- Rate Limit Rules ---------------------------------------------------

    def list_rate_limits(self, shield_zone_id: int) -> list[dict]:
        """List all rate limit rules for a shield zone."""
        return self._paginate(f"/shield/rate-limits/{shield_zone_id}")

    def create_rate_limit(self, payload: dict) -> dict:
        """Create a rate limit rule."""
        return self._request("POST", "/shield/rate-limit", json=payload)

    def update_rate_limit(self, rule_id: int, payload: dict) -> dict:
        """Update a rate limit rule."""
        return self._request("PATCH", f"/shield/rate-limit/{rule_id}", json=payload)

    def delete_rate_limit(self, rule_id: int) -> dict:
        """Delete a rate limit rule."""
        return self._request("DELETE", f"/shield/rate-limit/{rule_id}")

    # -- Access Lists -------------------------------------------------------

    def list_access_lists(self, shield_zone_id: int) -> list[dict]:
        """List all access lists for a shield zone."""
        return self._paginate(f"/shield/shield-zone/{shield_zone_id}/access-lists")

    def create_access_list(self, shield_zone_id: int, payload: dict) -> dict:
        """Create a custom access list."""
        return self._request(
            "POST",
            f"/shield/shield-zone/{shield_zone_id}/access-lists",
            json=payload,
        )

    def update_access_list(self, shield_zone_id: int, list_id: int, payload: dict) -> dict:
        """Update a custom access list."""
        return self._request(
            "PATCH",
            f"/shield/shield-zone/{shield_zone_id}/access-lists/{list_id}",
            json=payload,
        )

    def delete_access_list(self, shield_zone_id: int, list_id: int) -> dict:
        """Delete a custom access list."""
        return self._request(
            "DELETE",
            f"/shield/shield-zone/{shield_zone_id}/access-lists/{list_id}",
        )

    # -- Bot Detection ------------------------------------------------------

    def get_bot_detection(self, shield_zone_id: int) -> dict:
        """Get bot detection configuration."""
        return self._request("GET", f"/shield/shield-zone/{shield_zone_id}/bot-detection")

    def update_bot_detection(self, shield_zone_id: int, payload: dict) -> dict:
        """Update bot detection configuration."""
        return self._request(
            "PATCH",
            f"/shield/shield-zone/{shield_zone_id}/bot-detection",
            json=payload,
        )


# ---------------------------------------------------------------------------
# Retry-After support
# ---------------------------------------------------------------------------
def _sleep_for_retry_after(response: httpx.Response, attempt: int) -> None:
    """Sleep extra time if the server sent a ``Retry-After`` header.

    Called before the normal backoff sleep so the total delay is at least
    ``max(retry_after, backoff_delay)``.  The ``attempt`` index selects the
    expected backoff from ``_RETRY_BACKOFF`` so we only sleep the *excess*.
    """
    if response.status_code != 429:
        return
    raw = response.headers.get("Retry-After")
    if raw is None:
        return
    try:
        retry_after = int(raw)
    except (ValueError, TypeError):
        return
    if retry_after <= 0:
        return
    # Cap to prevent a rogue server from stalling the client indefinitely.
    retry_after = min(retry_after, 120)
    idx = min(attempt, len(_RETRY_BACKOFF) - 1)
    expected_backoff = _RETRY_BACKOFF[idx]
    extra = retry_after - expected_backoff
    if extra > 0:
        log.debug(
            "Retry-After %ds exceeds backoff %.1fs, sleeping %.1fs extra",
            retry_after,
            expected_backoff,
            extra,
        )
        time.sleep(extra)


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------
def _classify_http_error(exc: httpx.HTTPStatusError) -> None:
    """Raise a typed exception based on HTTP status code.

    Always raises — never returns.
    """
    status = exc.response.status_code
    if status in (401, 403):
        raise BunnyAuthError(str(exc)) from exc
    if status in (429, 500, 502, 503, 504):
        raise _TransientHTTPError(str(exc)) from exc
    raise BunnyAPIError(str(exc)) from exc
