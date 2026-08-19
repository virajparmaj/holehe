"""RFC 8058 one-click unsubscribe.

The whole mechanism is a POST to the https URI in List-Unsubscribe with the body
``List-Unsubscribe=One-Click``. What makes it safe to automate is not the POST --
it is everything checked before it. See offlist.act.dkim_check.
"""

from __future__ import annotations

import httpx

from offlist.act.dkim_check import DkimVerdict, check as dkim_check
from offlist.act.message import SenderMessage
from offlist.act.models import Action, ActionKind, ActionResult, Blocked

BODY = "List-Unsubscribe=One-Click"
CONTENT_TYPE = "application/x-www-form-urlencoded"


def evaluate(message: SenderMessage, *, dnsfunc=None,
             cryptographic: bool = True) -> tuple[Blocked | None, DkimVerdict]:
    """Decide whether this message may be unsubscribed from automatically."""
    if not message.one_click:
        return Blocked.NOT_ONE_CLICK, DkimVerdict()
    if not message.https_uri:
        return Blocked.NO_HTTPS_URI, DkimVerdict()

    verdict = dkim_check(message, dnsfunc=dnsfunc, cryptographic=cryptographic)
    if not verdict.present:
        return Blocked.DKIM_MISSING, verdict
    if not verdict.covers_unsubscribe:
        return Blocked.DKIM_NOT_COVERING, verdict
    if verdict.signature_valid is None:
        # Never checked is not the same as checked and failed; say which.
        return Blocked.DKIM_UNCHECKED, verdict
    if verdict.signature_valid is not True:
        return Blocked.DKIM_INVALID, verdict
    if not verdict.aligned:
        return Blocked.DKIM_UNALIGNED, verdict
    return None, verdict


def build_action(service: str, display_name: str, message: SenderMessage, *,
                 dnsfunc=None, cryptographic: bool = True) -> Action:
    blocked, verdict = evaluate(message, dnsfunc=dnsfunc, cryptographic=cryptographic)
    url = message.https_uri or message.mailto_uri or ""

    preview = "\n".join([
        f"POST {url}",
        f"Content-Type: {CONTENT_TYPE}",
        "",
        BODY,
        "",
        f"# sender          : {message.from_address}",
        f"# message         : {message.subject}",
        f"# DKIM signed by  : {verdict.signing_domain or '(none)'}",
        f"# covers unsub    : {verdict.covers_unsubscribe}",
        f"# signature valid : {verdict.signature_valid}",
        f"# domain aligned  : {verdict.aligned}",
    ])

    notes = verdict.detail
    if blocked is not None:
        notes = f"{blocked.value}. {verdict.detail}".strip()
        if blocked in (Blocked.DKIM_MISSING, Blocked.DKIM_NOT_COVERING,
                       Blocked.DKIM_INVALID, Blocked.DKIM_UNALIGNED):
            notes += (" -- POSTing anyway would confirm to the sender that this "
                      "address is live and monitored, so it is refused.")

    return Action(
        service=service,
        display_name=display_name,
        kind=ActionKind.UNSUBSCRIBE_ONECLICK,
        summary=f"one-click unsubscribe from {message.from_address}",
        preview=preview,
        url=url,
        method="POST",
        body=BODY,
        headers={"Content-Type": CONTENT_TYPE},
        blocked=blocked,
        notes=notes,
    )


async def execute(action: Action, *, timeout: float = 20.0,
                  client: httpx.AsyncClient | None = None) -> ActionResult:
    """Perform the POST. Only ever called after an explicit per-item yes."""
    if not action.executable:
        return ActionResult(action, "refused", action.notes or "not executable")

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    try:
        response = await client.post(action.url, content=BODY,
                                     headers={"Content-Type": CONTENT_TYPE})
    except Exception as exc:
        return ActionResult(action, "failed", f"{type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            await client.aclose()

    ok = 200 <= response.status_code < 400
    return ActionResult(
        action,
        "executed" if ok else "failed",
        f"HTTP {response.status_code}",
        http_code=response.status_code,
    )
