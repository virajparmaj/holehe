"""HIBP source: the k-anonymity path must never disclose the whole address."""

import hashlib

import httpx
import pytest
import respx

from offlist.core.email import EmailAddress
from offlist.sources.base import RunContext
from offlist.sources.breach_hibp import (
    HibpSource,
    fetch_breaches_kanon,
    to_evidence,
)

EMAIL = EmailAddress("alice@example.com")
SHA1 = hashlib.sha1(b"alice@example.com").hexdigest().upper()
PREFIX, SUFFIX = SHA1[:6], SHA1[6:]

CATALOGUE = [
    {"Name": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
     "DataClasses": ["Email addresses", "Passwords"], "PwnCount": 152000000,
     "IsVerified": True},
    {"Name": "Gawker", "Domain": "gawker.com", "BreachDate": "2010-12-11",
     "DataClasses": ["Email addresses"], "PwnCount": 1247000, "IsVerified": True},
]


def _range_payload(match=True):
    suffix = SUFFIX if match else "0" * len(SUFFIX)
    return [
        {"hashSuffix": suffix, "websites": ["Adobe", "Gawker"]},
        {"hashSuffix": "F" * len(SUFFIX), "websites": ["SomeoneElse"]},
    ]


@respx.mock
async def test_kanon_sends_only_the_hash_prefix_never_the_address():
    range_route = respx.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{PREFIX}"
    ).mock(return_value=httpx.Response(200, json=_range_payload()))
    respx.get("https://haveibeenpwned.com/api/v3/breaches").mock(
        return_value=httpx.Response(200, json=CATALOGUE))

    breaches = await fetch_breaches_kanon(EMAIL, "key")

    # The request path carries six hash characters and nothing that reveals the
    # address -- this is the whole point of the private path.
    called_url = str(range_route.calls.last.request.url)
    assert PREFIX in called_url
    assert "alice" not in called_url
    assert "example.com" not in called_url
    assert {b["Domain"] for b in breaches} == {"adobe.com", "gawker.com"}


@respx.mock
async def test_kanon_returns_nothing_when_the_local_suffix_does_not_match():
    respx.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{PREFIX}"
    ).mock(return_value=httpx.Response(200, json=_range_payload(match=False)))
    # No suffix match means the catalogue must not even be fetched.
    respx.get("https://haveibeenpwned.com/api/v3/breaches").mock(
        return_value=httpx.Response(500))

    assert await fetch_breaches_kanon(EMAIL, "key") == []


@respx.mock
async def test_source_defaults_to_kanon_and_yields_breach_evidence():
    respx.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{PREFIX}"
    ).mock(return_value=httpx.Response(200, json=_range_payload()))
    respx.get("https://haveibeenpwned.com/api/v3/breaches").mock(
        return_value=httpx.Response(200, json=CATALOGUE))
    # If the source ever touched the plaintext endpoint this would 500 the test.
    respx.get(url__startswith=(
        "https://haveibeenpwned.com/api/v3/breachedaccount/alice")).mock(
        return_value=httpx.Response(500))

    ctx = RunContext(hibp_api_key="key")  # hibp_kanon defaults to True
    out = [ev async for ev in HibpSource().collect(EMAIL, ctx)]

    assert {e.domain for e in out} == {"adobe.com", "gawker.com"}
    assert all(e.is_positive for e in out)


@respx.mock
async def test_plaintext_path_is_used_only_when_explicitly_selected():
    plaintext = respx.get(url__startswith=(
        "https://haveibeenpwned.com/api/v3/breachedaccount/alice")).mock(
        return_value=httpx.Response(200, json=CATALOGUE))

    ctx = RunContext(hibp_api_key="key", hibp_kanon=False)
    out = [ev async for ev in HibpSource().collect(EMAIL, ctx)]

    assert plaintext.called
    assert {e.domain for e in out} == {"adobe.com", "gawker.com"}


def test_a_breach_missing_from_the_catalogue_is_still_reported():
    """A name with no catalogue entry falls back to the name, never vanishes."""
    out = to_evidence([{"Name": "FreshLeak", "Domain": ""}])
    assert len(out) == 1
    assert out[0].domain == "freshleak"
