"""Have I Been Pwned -- which companies have already lost your address.

Opt-in, and deliberately careful about what it discloses. There are two ways to
ask HIBP whether an address is in a breach:

* the plaintext endpoint, which sends the whole address; and
* the k-anonymity range endpoint, which sends only the first six characters of
  the address's SHA-1 hash and returns every matching suffix, so the identifying
  comparison happens locally and the address never leaves your machine.

We default to the second. The range endpoint answers in breach *names* only, so
we join those against the public breach catalogue (``/breaches``, no key) to
recover the same domain/date/data-class detail the plaintext endpoint returns --
the output is identical, the disclosure is not. Either way nothing runs without
an explicit key, because both endpoints require one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import AsyncIterator

import httpx

from offlist import __version__
from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, Status
from offlist.sources.base import RunContext

API_ROOT = "https://haveibeenpwned.com/api/v3"

CONSENT_NOTICE = (
    "HIBP is queried through its k-anonymity range endpoint by default: only the\n"
    "first six characters of the SHA-1 hash of your address are sent, and the\n"
    "match is completed locally, so the address itself never leaves this machine.\n"
    "Passing --hibp-plaintext instead sends the whole address to haveibeenpwned.com.\n"
    "Nothing is queried at all without --hibp-key or OFFLIST_HIBP_KEY."
)

#: The range API always answers 200 -- HIBP holds a result for every possible
#: prefix -- so the hash prefix length is the only thing that varies. Email
#: search uses six characters; Pwned Passwords uses five.
_PREFIX_LEN = 6


def _headers(api_key: str) -> dict[str, str]:
    return {
        "hibp-api-key": api_key,
        # HIBP rejects requests without a descriptive user agent.
        "User-Agent": f"offlist/{__version__}",
        "Accept": "application/json",
    }


async def fetch_breaches(email: EmailAddress, api_key: str, *,
                         timeout: float = 30.0) -> list[dict]:
    """Plaintext lookup: sends the whole address. The private path is preferred."""
    url = f"{API_ROOT}/breachedaccount/{email.urlencoded}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers=_headers(api_key),
                                    params={"truncateResponse": "false"})
    if response.status_code == 404:
        return []            # documented "no breaches" response, not an error
    response.raise_for_status()
    return response.json()


async def fetch_catalogue(api_key: str, *, timeout: float = 30.0,
                          client: httpx.AsyncClient | None = None) -> dict[str, dict]:
    """The full public breach catalogue, keyed by breach name.

    The range endpoint returns breach *names*; this recovers the metadata behind
    each name so k-anonymity output matches the plaintext path. ``/breaches`` is
    public, but we send the key and user agent anyway so one client config works
    for both calls.
    """
    owns = client is None
    client = client or httpx.AsyncClient(timeout=timeout)
    try:
        response = await client.get(f"{API_ROOT}/breaches", headers=_headers(api_key))
        response.raise_for_status()
        return {b["Name"]: b for b in response.json() if b.get("Name")}
    finally:
        if owns:
            await client.aclose()


async def fetch_breaches_kanon(email: EmailAddress, api_key: str, *,
                               timeout: float = 30.0,
                               client: httpx.AsyncClient | None = None) -> list[dict]:
    """Private lookup: sends six hash characters, matches the suffix locally.

    Returns the same breach dicts the plaintext endpoint would, reconstructed
    from the public catalogue. A breach named in the range response but absent
    from the catalogue (a race around a fresh breach) is still reported, with the
    name standing in for the domain so it never silently vanishes.
    """
    prefix, suffix = email.sha1[:_PREFIX_LEN], email.sha1[_PREFIX_LEN:]
    owns = client is None
    client = client or httpx.AsyncClient(timeout=timeout)
    try:
        response = await client.get(f"{API_ROOT}/breachedaccount/range/{prefix}",
                                    headers=_headers(api_key))
        response.raise_for_status()
        rows = response.json()
        names: list[str] = []
        for row in rows:
            # HIBP concatenates the returned suffix without the sent prefix; the
            # comparison is over the same uppercase hex EmailAddress.sha1 emits.
            if str(row.get("hashSuffix", "")).upper() == suffix:
                names = list(row.get("websites") or [])
                break
        if not names:
            return []
        catalogue = await fetch_catalogue(api_key, timeout=timeout, client=client)
    finally:
        if owns:
            await client.aclose()

    return [catalogue.get(name, {"Name": name, "Domain": ""}) for name in names]


def to_evidence(breaches: list[dict]) -> list[Evidence]:
    now = datetime.now(timezone.utc)
    out = []
    for breach in breaches:
        # A catalogue miss leaves no domain; fall back to the breach name so the
        # finding is still grouped and reported rather than dropped.
        domain = (breach.get("Domain") or breach.get("Name") or "").lower()
        if not domain:
            continue
        classes = breach.get("DataClasses") or []
        out.append(Evidence(
            source="hibp",
            domain=domain,
            status=Status.REGISTERED,
            confidence=Confidence.HIGH,
            detail=(f"breached in {breach.get('BreachDate', 'an undated incident')} "
                    f"-- exposed: {', '.join(classes[:6]) or 'unspecified'}"),
            payload={
                "breach_name": breach.get("Name"),
                "breach_date": breach.get("BreachDate"),
                "pwn_count": breach.get("PwnCount"),
                "data_classes": classes,
                "is_verified": breach.get("IsVerified"),
            },
            observed_at=now,
        ))
    return out


class HibpSource:
    id = "hibp"
    requires_network = True
    requires_consent = True

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        if not ctx.hibp_api_key:
            return
        if ctx.hibp_kanon:
            breaches = await fetch_breaches_kanon(email, ctx.hibp_api_key,
                                                  timeout=ctx.timeout)
        else:
            breaches = await fetch_breaches(email, ctx.hibp_api_key,
                                            timeout=ctx.timeout)
        for ev in to_evidence(breaches):
            yield ev
