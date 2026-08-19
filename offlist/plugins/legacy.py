"""Bridge to the original holehe module tree.

Entries carrying `plugin: legacy` have not been ported to declarative steps yet.
They still run, so coverage never regresses mid-migration, but they get the new
status taxonomy: the adapter watches the actual HTTP exchange and classifies a
legacy `rateLimit: True` by what the server really did, rather than repeating the
claim. That is what turns "76 rate limits" back into 2.
"""

from __future__ import annotations

import contextvars
import importlib
from typing import Any

import httpx

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, ProbeResult, Status
from offlist.core.status_map import status_for_exception, status_for_response
from offlist.plugins import register

#: Per-task record of the last response a legacy module received.
_LAST_RESPONSE: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "offlist_last_response", default=None
)


class RecordingClient(httpx.AsyncClient):
    """An AsyncClient that remembers the last exchange of the current task.

    Legacy modules swallow their own exceptions and report a bare boolean, so the
    only way to recover the real cause is to observe the traffic underneath them.
    httpx routes get/post/head through request(), so one override covers them all.
    """

    async def request(self, method: str, url: Any, **kwargs: Any) -> httpx.Response:
        try:
            response = await super().request(method, url, **kwargs)
        except Exception as exc:
            _LAST_RESPONSE.set({"exception": exc})
            raise
        _LAST_RESPONSE.set({
            "status_code": response.status_code,
            "text": response.text[:4000],
        })
        return response


def _classify_failure() -> tuple[Status, str]:
    """Work out why a legacy module reported a rate limit."""
    last = _LAST_RESPONSE.get()
    if not last:
        return Status.PARSE_FAILED, "legacy module made no request"
    if "exception" in last:
        return status_for_exception(last["exception"])
    status, detail = status_for_response(last["status_code"], last.get("text", ""))
    return status, f"{detail} (legacy module reported a rate limit)"


def _import_module(entry: Any):
    path = f"holehe.modules.{entry.category}.{entry.id}"
    module = importlib.import_module(path)
    return getattr(module, entry.id)


@register("legacy")
async def legacy_probe(email: EmailAddress, client: httpx.AsyncClient,
                       entry: Any) -> ProbeResult:
    """Run a legacy module and translate its result dict into a ProbeResult."""
    _LAST_RESPONSE.set(None)

    def result(status: Status, detail: str = "", **extra: Any) -> ProbeResult:
        return ProbeResult(
            site_id=entry.id,
            domain=entry.domain,
            status=status,
            category=entry.category,
            method=entry.method,
            detail=detail,
            discriminating=entry.canary.discriminating,
            confidence=Confidence.HIGH if status.is_answer else Confidence.MEDIUM,
            http_code=(_LAST_RESPONSE.get() or {}).get("status_code"),
            **extra,
        )

    try:
        fn = _import_module(entry)
    except (ImportError, AttributeError) as exc:
        return result(Status.PARSE_FAILED, f"legacy module unavailable: {exc}")

    out: list[dict] = []
    try:
        await fn(str(email), client, out)
    except Exception as exc:
        status, detail = status_for_exception(exc)
        return result(status, f"legacy module raised: {detail}")

    if not out:
        # The instagram module used to do exactly this on an unrecognised error
        # code: report nothing at all and vanish from the results.
        return result(Status.PARSE_FAILED, "legacy module returned no result")

    row = out[0]
    extra: dict[str, Any] = {}
    if row.get("emailrecovery"):
        extra["emailrecovery"] = str(row["emailrecovery"])
    if row.get("phoneNumber"):
        extra["phone_number"] = str(row["phoneNumber"])
    others = row.get("others")
    if isinstance(others, dict):
        if others.get("FullName"):
            extra["full_name"] = str(others["FullName"])
        if others.get("Date, time of the creation"):
            extra["created_at"] = str(others["Date, time of the creation"])
        extra["others"] = others

    if row.get("error"):
        return result(Status.PARSE_FAILED, "legacy module errored", **extra)
    if row.get("rateLimit"):
        status, detail = _classify_failure()
        return result(status, detail, **extra)
    if row.get("exists"):
        return result(Status.REGISTERED, "legacy module reported an account", **extra)
    return result(Status.NOT_REGISTERED, "legacy module reported no account", **extra)
