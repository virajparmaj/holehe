"""HTTP client construction, per-host throttling, and the retry policy.

Two measured facts shape this module:

* Global concurrency was never the constraint. Re-running the whole suite gated
  at 4 concurrent requests with jitter changed 2 outcomes out of 69, because
  every site is a different host. So the limiter is *per host*, which is the only
  place sequential requests to one origin actually collide.
* Only 2 of 76 failures were genuine 429s. Retrying is therefore reserved for
  429 and 503; retrying a 403 or a 404 just burns time on a stale definition.
"""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from urllib.parse import urlsplit

import httpx

# The legacy user-agent pool shipped Chrome 36-41 -- browsers from 2014, which
# any current WAF flags on sight. Several of the measured 403s are likely this.
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
)

# Deliberately no Accept-Encoding: httpx advertises exactly the encodings it has
# decoders for. Setting it by hand advertises brotli even when no brotli decoder
# is installed, and response.text then yields raw compressed bytes -- a silent
# corruption that looks exactly like a site changing its response format.
DEFAULT_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "DNT": "1",
    "Connection": "keep-alive",
}

RETRYABLE_STATUS = frozenset({429, 503})


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def build_client(timeout: float = 15.0, *, max_connections: int = 30,
                 verify: bool = True) -> httpx.AsyncClient:
    """A shared client with a bounded pool.

    The original code shared one unbounded client across 123 simultaneous tasks,
    so on a constrained link the 10s default timeout fired for reasons that had
    nothing to do with the target site.
    """
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=verify,
        limits=httpx.Limits(max_connections=max_connections,
                            max_keepalive_connections=10),
        headers={**DEFAULT_HEADERS, "User-Agent": random_user_agent()},
    )


class HostLimiter:
    """One semaphore per hostname, created on demand."""

    def __init__(self, per_host: int = 2) -> None:
        self._per_host = per_host
        self._locks: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(per_host)
        )

    def for_url(self, url: str) -> asyncio.Semaphore:
        return self._locks[urlsplit(url).hostname or url]


def retry_after_seconds(response: httpx.Response, default: float = 2.0) -> float:
    """Honour Retry-After when the server sends one; cap it so a scan can finish."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return default
    try:
        return min(float(raw), 30.0)
    except ValueError:
        return default
