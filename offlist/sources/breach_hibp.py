"""Have I Been Pwned -- which companies have already lost your address.

Opt-in, and deliberately noisy about why. Unlike the Pwned Passwords range API,
the breach endpoint has no k-anonymity: querying it sends your address in
plaintext to a third party. That is a reasonable trade for most people, but it is
their call to make, not ours, so nothing here runs without an explicit key.
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
    "The HIBP breach API has no k-anonymity: this sends your address in plaintext\n"
    "to haveibeenpwned.com. Nothing is queried without --hibp-key or OFFLIST_HIBP_KEY."
)


async def fetch_breaches(email: EmailAddress, api_key: str, *,
                         timeout: float = 30.0) -> list[dict]:
    headers = {
        "hibp-api-key": api_key,
        # HIBP rejects requests without a descriptive user agent.
        "User-Agent": f"offlist/{__version__}",
        "Accept": "application/json",
    }
    url = f"{API_ROOT}/breachedaccount/{email.urlencoded}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers=headers,
                                    params={"truncateResponse": "false"})
    if response.status_code == 404:
        return []            # documented "no breaches" response, not an error
    response.raise_for_status()
    return response.json()


def to_evidence(breaches: list[dict]) -> list[Evidence]:
    now = datetime.now(timezone.utc)
    out = []
    for breach in breaches:
        domain = (breach.get("Domain") or "").lower()
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
        for ev in to_evidence(await fetch_breaches(email, ctx.hibp_api_key,
                                                   timeout=ctx.timeout)):
            yield ev
