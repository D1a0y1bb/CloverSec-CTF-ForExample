#!/usr/bin/env python3
"""Shared HTTP helpers for CloverSec CTF public-source fetches."""

from __future__ import annotations

import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


RETRYABLE_STATUS = {429, 500, 502, 503, 504}
ALLOWED_SCHEMES = {"http", "https"}


def http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    read_limit: int = 50 * 1024 * 1024 + 1,
    retries: int = 2,
    backoff: float = 0.4,
    user_agent: str = "CloverSec-CTF-For-Example",
    max_redirects: int | None = None,
    blocked_url_checker: Any | None = None,
) -> dict[str, Any]:
    validate_http_url(url)
    merged_headers = {"User-Agent": user_agent}
    if headers:
        merged_headers.update(headers)
    attempts = max(1, int(retries) + 1)
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = Request(url, headers=merged_headers)
        try:
            opener = build_limited_redirect_opener(max_redirects, blocked_url_checker)
            fetch = opener.open if opener else urlopen
            with fetch(request, timeout=timeout) as response:  # noqa: S310 - public-source fetch helper.
                body = response.read(read_limit)
                payload = response_payload(response, body, attempt)
                payload["redirect_count"] = redirect_count(opener)
                return payload
        except HTTPError as exc:
            try:
                body = exc.read(read_limit)
                payload = response_payload(exc, body, attempt)
                payload["error_kind"] = "http_status"
                payload["redirect_count"] = redirect_count(locals().get("opener", None))
                if exc.code not in RETRYABLE_STATUS or attempt == attempts - 1:
                    return payload
            finally:
                exc.close()
        except RedirectLimitExceeded:
            raise
        except RedirectTargetBlocked:
            raise
        except URLError as exc:
            last_error = exc
            if attempt == attempts - 1:
                break
        sleep_before_retry(attempt, backoff)
    raise RuntimeError(f"network_error: failed to fetch {url}: {last_error}") from last_error


def response_payload(response: Any, body: bytes, attempt: int) -> dict[str, Any]:
    headers = getattr(response, "headers", {})
    return {
        "status": getattr(response, "status", getattr(response, "code", 200)),
        "headers": {key.lower(): value for key, value in headers.items()},
        "body": body,
        "final_url": response.geturl() if hasattr(response, "geturl") else "",
        "attempts": attempt + 1,
        "cache_hit": False,
    }


def sleep_before_retry(attempt: int, backoff: float) -> None:
    if backoff <= 0:
        return
    time.sleep(backoff * (2**attempt))


def validate_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError("only http and https URLs are supported")


class RedirectLimitExceeded(RuntimeError):
    pass


class RedirectTargetBlocked(RuntimeError):
    pass


class LimitedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, max_redirects: int, blocked_url_checker: Any | None = None):
        self.max_redirects = max(0, int(max_redirects))
        self.blocked_url_checker = blocked_url_checker
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise RedirectLimitExceeded(f"redirect count exceeds max_redirects={self.max_redirects}")
        if self.blocked_url_checker:
            blocked_reason = str(self.blocked_url_checker(str(newurl or "")) or "")
            if blocked_reason:
                raise RedirectTargetBlocked(f"redirect target blocked: {blocked_reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_limited_redirect_opener(max_redirects: int | None, blocked_url_checker: Any | None = None) -> Any | None:
    if max_redirects is None:
        return None
    handler = LimitedRedirectHandler(max_redirects, blocked_url_checker)
    opener = build_opener(handler)
    opener.cloversec_redirect_handler = handler  # type: ignore[attr-defined]
    return opener


def redirect_count(opener: Any | None) -> int:
    handler = getattr(opener, "cloversec_redirect_handler", None)
    return int(getattr(handler, "redirect_count", 0) or 0)
