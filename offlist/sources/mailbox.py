"""Your own mailbox -- the strongest forgotten-account signal there is.

A verification or welcome message in your own saved mail is better evidence than
any signup probe: it is a record you kept, it names the service, and its date is
roughly when you first dealt with them. A probe can only ever guess at "is there
an account now"; the mailbox answers "you made one, on this date".

Entirely offline. It reads the same ``.eml`` / mbox / maildir exports the
unsubscribe path already reads (drag messages out of any mail client), so no
cloud project or OAuth consent screen is needed to use it. The README's "Phase 8"
OAuth path drops straight in through ``mail_raw_messages`` in the run context --
this source classifies raw bytes, it does not care where they came from.

Nothing here decides anything: it emits dated `Evidence`, and the cross-source
reasoning stays in offlist.worklist.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, Status
from offlist.sources.base import RunContext
from offlist.worklist.merge import registrable

# Subject/body markers, strongest first. A message is labelled by the first tier
# whose phrases it matches, so an unambiguous account signal wins over a mere
# "welcome". Kept deliberately small and literal -- a wrong match here invents an
# account that never existed, so recall is traded for precision on purpose.
MARKER_TIERS: tuple[tuple[str, Confidence, tuple[str, ...]], ...] = (
    ("email_verification", Confidence.HIGH, (
        "verify your email", "confirm your email", "verify your account",
        "confirm your account", "activate your account", "email verification",
        "verify your address", "confirm your email address",
        "please verify", "please confirm your", "verify your new",
    )),
    ("account_created", Confidence.HIGH, (
        "account created", "your account is ready", "your new account",
        "thanks for signing up", "thank you for signing up",
        "thanks for registering", "thank you for registering",
        "complete your registration", "finish setting up",
        "your registration is complete", "registration confirmation",
    )),
    ("password_reset", Confidence.HIGH, (
        "password reset", "reset your password", "forgot your password",
        "your password has been", "change your password",
        "reset password request",
    )),
    ("credentials", Confidence.HIGH, (
        "your username", "your login", "your user name", "your sign-in",
        "your account details", "here is your username",
    )),
    ("welcome", Confidence.MEDIUM, (
        "welcome to", "getting started with", "welcome aboard",
        "your account", "your membership", "your subscription",
    )),
)

#: Subtypes that assert a deliberate account rather than a mere mailing.
_ACCOUNT_SUBTYPES = {"email_verification", "account_created",
                     "password_reset", "credentials", "welcome"}

_RECIPIENT_HEADERS = ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To")


def _decode_body(msg: email.message.EmailMessage, *, limit: int = 8000) -> str:
    """A bounded plain-text view of the body for keyword scanning."""
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
    except Exception:
        part = None
    if part is None:
        return ""
    try:
        text = part.get_content()
    except Exception:
        return ""
    if part.get_content_subtype() == "html":
        # Cheap tag strip -- we only need words to match against, not structure.
        import re

        text = re.sub(r"<[^>]+>", " ", text)
    return text[:limit].lower()


def classify(subject: str, body: str) -> tuple[str, Confidence]:
    """Label a message by the strongest account marker it contains.

    Returns ``("marketing", LOW)`` for a message that shows no account marker,
    and ``("", LOW)`` for one that is not usable evidence at all -- the caller
    decides marketing is worth a weak record and silence is not.
    """
    haystack = f"{subject}\n{body}".lower()
    for subtype, confidence, phrases in MARKER_TIERS:
        if any(phrase in haystack for phrase in phrases):
            return subtype, confidence
    return "marketing", Confidence.LOW


def _message_date(msg: email.message.EmailMessage) -> datetime:
    """When the message was sent -- i.e. roughly when the account was used."""
    raw = msg.get("Date")
    if raw:
        try:
            parsed = email.utils.parsedate_to_datetime(str(raw))
            if parsed is not None:
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            pass
    return datetime.now(timezone.utc)


def _addressed_to(msg: email.message.EmailMessage, target: str) -> bool:
    for header in _RECIPIENT_HEADERS:
        for value in msg.get_all(header, []):
            if target in str(value).lower():
                return True
    return False


def _sender_domain(msg: email.message.EmailMessage) -> str:
    sender = str(msg.get("From", "") or "")
    if "<" in sender:
        sender = sender.split("<", 1)[1].split(">", 1)[0]
    _, addr = email.utils.parseaddr(sender)
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def _iter_raw(email_addr: EmailAddress, ctx: RunContext) -> Iterable[tuple[bytes, str]]:
    """Raw messages from an injected provider, else from local mail exports.

    ``mail_raw_messages`` lets an OAuth fetcher hand bytes straight in without
    this source knowing anything about tokens; ``mail_paths`` is the offline
    default that reuses the unsubscribe path's file/mbox/maildir reader.
    """
    injected = ctx.extras.get("mail_raw_messages")
    if injected is not None:
        for i, item in enumerate(injected):
            raw, label = item if isinstance(item, tuple) else (item, f"oauth:{i}")
            yield raw, label
        return

    from offlist.act.message import load_messages

    paths = [Path(p) for p in ctx.extras.get("mail_paths", ())]
    for message in load_messages(paths):
        yield message.raw, message.source


def collect_sync(email_addr: EmailAddress, ctx: RunContext) -> list[Evidence]:
    """One Evidence per (service, subtype), carrying the count and the earliest date.

    Grouping keeps the worklist readable while preserving the multiplicity the
    report leans on -- several account-management messages over time is stronger
    evidence than one, and the group's ``count`` records exactly that.
    """
    target = email_addr.normalized
    groups: dict[tuple[str, str], dict] = {}

    for raw, label in _iter_raw(email_addr, ctx):
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception:
            continue
        domain = _sender_domain(msg)
        if not domain:
            continue
        subject = str(msg.get("Subject", "") or "")
        subtype, confidence = classify(subject, _decode_body(msg))
        if not subtype:
            continue

        key = (registrable(domain), subtype)
        when = _message_date(msg)
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "domain": domain, "subtype": subtype, "confidence": confidence,
                "count": 1, "first": when, "last": when,
                "subject": subject[:160], "source": label,
                "to_self": _addressed_to(msg, target),
            }
        else:
            group["count"] += 1
            group["first"] = min(group["first"], when)
            group["last"] = max(group["last"], when)
            group["to_self"] = group["to_self"] or _addressed_to(msg, target)

    out: list[Evidence] = []
    for group in groups.values():
        subtype = group["subtype"]
        account_like = subtype in _ACCOUNT_SUBTYPES
        noun = "account-management" if account_like else "marketing"
        detail = (f"{group['count']} {noun} email(s) ({subtype}); "
                  f"first seen {group['first'].date().isoformat()}")
        out.append(Evidence(
            source="mailbox",
            domain=group["domain"],
            status=Status.REGISTERED,
            confidence=group["confidence"],
            detail=detail,
            payload={
                "subtype": subtype,
                "message_count": group["count"],
                "first_seen": group["first"].date().isoformat(),
                "last_seen": group["last"].date().isoformat(),
                "example_subject": group["subject"],
                "addressed_to_target": group["to_self"],
                "account_signal": account_like,
            },
            # The mail's own date, so first_seen across sources reflects when the
            # account was actually touched rather than when the audit ran.
            observed_at=group["first"],
        ))
    return out


class MailboxSource:
    id = "mailbox"
    requires_network = False
    requires_consent = False

    async def collect(self, email_addr: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        for ev in collect_sync(email_addr, ctx):
            yield ev
