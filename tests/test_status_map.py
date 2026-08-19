"""The taxonomy that replaced the rateLimit boolean.

The audit measured 76 failures reported as rate limits when only 2 were. These
tests pin each distinct cause to a distinct status.
"""

import httpx
import pytest

from offlist.core.models import Status
from offlist.core.status_map import status_for_exception, status_for_response


@pytest.mark.parametrize("code,expected", [
    (429, Status.RATE_LIMITED),
    (403, Status.BLOCKED),
    (401, Status.BLOCKED),
    (404, Status.ENDPOINT_GONE),
    (410, Status.ENDPOINT_GONE),
    (500, Status.SERVER_ERROR),
    (503, Status.SERVER_ERROR),
    (200, Status.PARSE_FAILED),
])
def test_status_codes_map_to_distinct_causes(code, expected):
    status, _ = status_for_response(code, "")
    assert status is expected


def test_bot_wall_served_with_200_is_a_block_not_a_parse_failure():
    status, detail = status_for_response(200, "<h1>Just a moment...</h1> cf_chl_opt")
    assert status is Status.BLOCKED
    assert "cf_chl_opt" in detail


def test_connect_error_is_unreachable_not_rate_limited():
    status, _ = status_for_exception(httpx.ConnectError("nope"))
    assert status is Status.UNREACHABLE


def test_unknown_exception_is_parse_failed_not_unreachable():
    status, _ = status_for_exception(ValueError("bad json"))
    assert status is Status.PARSE_FAILED


def test_no_status_is_ever_silently_a_rate_limit():
    """Only a real 429 or an explicit throttle body may claim rate limiting."""
    non_429 = [200, 301, 400, 403, 404, 410, 500, 502, 503]
    for code in non_429:
        status, _ = status_for_response(code, "")
        assert status is not Status.RATE_LIMITED, code
