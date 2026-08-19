"""Where your address is publicly visible without any account existing.

These are the "I did not know that was public" findings. None of them requires
an account, a key, or a probe against a signup form -- they read data the
services already publish.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import AsyncIterator

import httpx

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, Status
from offlist.sources.base import RunContext


async def check_gravatar(email: EmailAddress,
                         client: httpx.AsyncClient) -> Evidence | None:
    """Gravatar keys public profiles on the md5 of the address.

    Anyone holding your address can look this up. If a profile exists, your name,
    photo, linked accounts and websites are public to anyone who knows the
    address -- which is a meaningful exposure finding, not just an account hit.
    """
    url = f"https://en.gravatar.com/{email.md5}.json"
    try:
        response = await client.get(url, headers={"Accept": "application/json"})
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        entry = (response.json().get("entry") or [{}])[0]
    except (ValueError, AttributeError, IndexError):
        return None

    disclosed = {k: entry.get(k) for k in
                 ("displayName", "profileUrl", "name", "aboutMe", "currentLocation")
                 if entry.get(k)}
    accounts = [a.get("url") for a in entry.get("accounts", []) if a.get("url")]
    if accounts:
        disclosed["linked_accounts"] = accounts

    return Evidence(
        source="public_exposure",
        domain="gravatar.com",
        status=Status.REGISTERED,
        confidence=Confidence.HIGH,
        detail=("a public Gravatar profile is served for the md5 of this address -- "
                "anyone who knows the address can read it"),
        payload={"profile": disclosed, "hash": email.md5, "lookup_url": url},
        observed_at=datetime.now(timezone.utc),
    )


async def check_github_commits(email: EmailAddress,
                               client: httpx.AsyncClient) -> Evidence | None:
    """Public commits publish the author address in the commit metadata."""
    try:
        response = await client.get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email.raw}", "per_page": 1},
            headers={"Accept": "application/vnd.github+json"},
        )
    except Exception:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    total = payload.get("total_count", 0)
    if not total:
        return None

    items = payload.get("items") or [{}]
    repo = (items[0].get("repository") or {}).get("full_name", "")
    return Evidence(
        source="public_exposure",
        domain="github.com",
        status=Status.REGISTERED,
        confidence=Confidence.HIGH,
        detail=(f"this address appears as the author of {total} public commit(s) -- "
                f"git metadata is permanent and scraped routinely"),
        payload={"commit_count": total, "example_repo": repo,
                 "fix": "set a noreply address with `git config user.email`"},
        observed_at=datetime.now(timezone.utc),
    )


class PublicExposureSource:
    id = "public_exposure"
    requires_network = True
    requires_consent = False

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        from offlist.core.http import build_client

        async with build_client(timeout=ctx.timeout) as client:
            for check in (check_gravatar, check_github_commits):
                found = await check(email, client)
                if found is not None:
                    yield found
