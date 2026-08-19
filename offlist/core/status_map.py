"""The single place that turns an HTTP response or a transport exception into a Status.

Keeping this in one function is what makes the failure taxonomy trustworthy: the
audit found 36 sites returning HTTP 200 whose modules could not parse the body,
13 returning 403 from a WAF, and 9 returning 404 -- all three of which the old
code reported identically as a rate limit.
"""

from __future__ import annotations

from offlist.core.models import Status

#: Body markers that mean "a bot check answered, not the application".
BLOCK_MARKERS = (
    "cf-browser-verification",
    "cf_chl_opt",
    "cloudflare",
    "just a moment",
    "attention required",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "access denied",
    "request unsuccessful",
    "incapsula",
    "perimeterx",
    "are you a robot",
    "enable javascript and cookies to continue",
)

#: Exception class names that mean we never got an application response at all.
UNREACHABLE_EXCEPTIONS = (
    "ConnectError",
    "ConnectTimeout",
    "ReadTimeout",
    "WriteTimeout",
    "PoolTimeout",
    "ReadError",
    "WriteError",
    "RemoteProtocolError",
    "LocalProtocolError",
    "ProxyError",
    "UnsupportedProtocol",
    "TooManyRedirects",
    "NetworkError",
)


def status_for_exception(exc: BaseException) -> tuple[Status, str]:
    """Classify a transport-level failure."""
    kind = type(exc).__name__
    if kind in UNREACHABLE_EXCEPTIONS:
        return Status.UNREACHABLE, f"{kind}: {exc}"
    return Status.PARSE_FAILED, f"{kind}: {exc}"


def status_for_response(status_code: int, body: str = "") -> tuple[Status, str]:
    """Classify an HTTP response that no decision rule matched."""
    lowered = body[:4000].lower()

    if status_code == 429:
        return Status.RATE_LIMITED, "HTTP 429"
    if status_code in (401, 403):
        for marker in BLOCK_MARKERS:
            if marker in lowered:
                return Status.BLOCKED, f"HTTP {status_code} ({marker})"
        return Status.BLOCKED, f"HTTP {status_code}"
    if status_code in (404, 410):
        return Status.ENDPOINT_GONE, f"HTTP {status_code}"
    if 500 <= status_code <= 599:
        return Status.SERVER_ERROR, f"HTTP {status_code}"

    # A 200 that reached a bot wall is still a block, not a parse failure --
    # several sites serve their challenge page with a 200.
    for marker in BLOCK_MARKERS:
        if marker in lowered:
            return Status.BLOCKED, f"HTTP {status_code} ({marker})"

    if 300 <= status_code <= 399:
        return Status.PARSE_FAILED, f"HTTP {status_code} (unexpected redirect)"

    return Status.PARSE_FAILED, f"HTTP {status_code} (no rule matched)"
