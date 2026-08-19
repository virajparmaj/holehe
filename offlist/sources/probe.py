"""Endpoint probing -- what the original tool did, demoted to one source of five.

It answers a narrow question the other sources cannot: accounts you have no
record of, either because you forgot them or because someone else created them
with your address. It is also the least reliable source, which is why its
negatives are downgraded unless a canary proved the site discriminates.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Iterable, Sequence

import httpx

from offlist.catalogue.loader import load_catalogue, selectable
from offlist.catalogue.schema import Entry
from offlist.core.email import EmailAddress
from offlist.core.http import DEFAULT_HEADERS, HostLimiter, random_user_agent
from offlist.core.models import Confidence, Evidence, ProbeResult, Status
from offlist.engine.executor import run_entry
from offlist.plugins.legacy import RecordingClient
from offlist.sources.base import RunContext


async def _run_one(entry: Entry, email: EmailAddress, client: httpx.AsyncClient,
                   limiter: HostLimiter, timeout: float,
                   progress=None, *, downgrade: bool = True) -> ProbeResult:
    url = entry.steps[0].url if entry.steps else f"https://{entry.domain}"
    try:
        async with limiter.for_url(url):
            result = await run_entry(entry, email, client, default_timeout=timeout)
    except Exception as exc:  # nothing below should escape, but a scan must not die
        from offlist.core.status_map import status_for_exception

        status, detail = status_for_exception(exc)
        result = ProbeResult(site_id=entry.id, domain=entry.domain, status=status,
                             category=entry.category, method=entry.method, detail=detail,
                             discriminating=entry.canary.discriminating)
    finally:
        if progress is not None:
            progress.update(1)
    # The canary needs the raw verdict: downgrading before judging would make a
    # tier-C check unpassable by construction, since the downgrade is exactly what
    # a passing canary is supposed to lift.
    return result.downgraded() if downgrade else result


async def run_probes(email: EmailAddress, ctx: RunContext,
                     entries: Sequence[Entry] | None = None,
                     *, show_progress: bool = False,
                     downgrade: bool = True) -> list[ProbeResult]:
    """Probe every selected catalogue entry, bounded globally and per host."""
    if entries is None:
        entries = load_catalogue(include_disabled=ctx.include_disabled)
        entries = selectable(
            entries,
            allow_login_probe=ctx.allow_login_probe,
            allow_email_sending=ctx.allow_email_sending,
            no_password_recovery=ctx.no_password_recovery,
        )
    if ctx.only:
        wanted = set(ctx.only)
        entries = [e for e in entries if e.id in wanted or e.category in wanted]

    progress = None
    if show_progress:
        try:
            from tqdm import tqdm

            progress = tqdm(total=len(entries), unit="site", leave=False)
        except ImportError:
            progress = None

    limiter = HostLimiter(per_host=2)
    sem = asyncio.Semaphore(ctx.concurrency)

    # RecordingClient so legacy-bridged entries can still be classified by what
    # the server actually did rather than by their own rateLimit boolean.
    client = RecordingClient(
        timeout=ctx.timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=30, max_keepalive_connections=10),
        headers={**DEFAULT_HEADERS, "User-Agent": random_user_agent()},
    )

    async def guarded(entry: Entry) -> ProbeResult:
        async with sem:
            return await _run_one(entry, email, client, limiter, ctx.timeout,
                                  progress, downgrade=downgrade)

    try:
        results = await asyncio.gather(*(guarded(e) for e in entries),
                                       return_exceptions=True)
    finally:
        await client.aclose()
        if progress is not None:
            progress.close()

    out: list[ProbeResult] = []
    for entry, res in zip(entries, results, strict=True):
        if isinstance(res, BaseException):
            out.append(ProbeResult(site_id=entry.id, domain=entry.domain,
                                   status=Status.PARSE_FAILED,
                                   category=entry.category, method=entry.method,
                                   detail=f"runner error: {type(res).__name__}: {res}"))
        else:
            out.append(res)
    return sorted(out, key=lambda r: r.site_id)


def to_evidence(results: Iterable[ProbeResult]) -> list[Evidence]:
    """Only positives become evidence -- an absence is not an observation."""
    evidence = []
    for r in results:
        if r.status is not Status.REGISTERED:
            continue
        detail = "an account exists for this address"
        if r.emailrecovery or r.phone_number:
            detail += " (and the site leaked a masked recovery identifier)"
        evidence.append(Evidence(
            source="probe",
            domain=r.domain,
            status=Status.REGISTERED,
            confidence=Confidence.HIGH if r.discriminating.value == "yes" else Confidence.MEDIUM,
            detail=detail,
            payload={k: v for k, v in {
                "site_id": r.site_id,
                "method": r.method,
                "emailrecovery": r.emailrecovery,
                "phoneNumber": r.phone_number,
                "full_name": r.full_name,
                "created_at": r.created_at,
            }.items() if v},
            observed_at=r.checked_at,
        ))
    return evidence


class ProbeSource:
    id = "probe"
    requires_network = True
    requires_consent = False

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        for ev in to_evidence(await run_probes(email, ctx)):
            yield ev
