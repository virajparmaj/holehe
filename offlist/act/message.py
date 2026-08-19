"""Parse saved email messages for unsubscribe metadata.

Phase 8 will feed this from Gmail/Graph over OAuth. Until then it reads .eml
files, mbox files and maildir directories, which anyone can produce by dragging
messages out of a mail client -- so the unsubscribe path is complete and testable
without a cloud project.
"""

from __future__ import annotations

import email
import email.policy
import mailbox
import re
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

#: RFC 8058 fixes this value exactly; anything else is not one-click.
ONE_CLICK_POST = "List-Unsubscribe=One-Click"

_URI_RE = re.compile(r"<([^>]+)>")


@dataclass(frozen=True)
class SenderMessage:
    """The unsubscribe-relevant parts of one message."""

    source: str
    from_address: str
    from_domain: str
    subject: str
    list_unsubscribe: tuple[str, ...] = ()
    one_click: bool = False
    dkim_signatures: tuple[str, ...] = ()
    raw: bytes = b""

    @property
    def https_uri(self) -> str | None:
        """RFC 8058 requires an https URI; a mailto cannot be POSTed."""
        for uri in self.list_unsubscribe:
            if uri.lower().startswith("https://"):
                return uri
        return None

    @property
    def mailto_uri(self) -> str | None:
        for uri in self.list_unsubscribe:
            if uri.lower().startswith("mailto:"):
                return uri
        return None

    @property
    def unsubscribe_host(self) -> str:
        uri = self.https_uri
        return (urlsplit(uri).hostname or "") if uri else ""


def _address_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def parse_message(raw: bytes, source: str = "") -> SenderMessage:
    msg: EmailMessage = email.message_from_bytes(raw, policy=email.policy.default)

    sender = ""
    try:
        sender = str(msg.get("From", "") or "")
        if "<" in sender:
            sender = sender.split("<", 1)[1].split(">", 1)[0]
    except Exception:
        sender = ""

    header = str(msg.get("List-Unsubscribe", "") or "")
    uris = tuple(u.strip() for u in _URI_RE.findall(header))
    if header and not uris:
        # Some senders omit the angle brackets even though the RFC requires them.
        uris = tuple(p.strip() for p in header.split(",") if p.strip())

    post = str(msg.get("List-Unsubscribe-Post", "") or "").strip()

    return SenderMessage(
        source=source,
        from_address=sender.strip().lower(),
        from_domain=_address_domain(sender),
        subject=str(msg.get("Subject", "") or "")[:160],
        list_unsubscribe=uris,
        one_click=post.replace(" ", "").lower() == ONE_CLICK_POST.replace(" ", "").lower(),
        dkim_signatures=tuple(str(v) for v in msg.get_all("DKIM-Signature", [])),
        raw=raw,
    )


def load_messages(paths: Sequence[Path]) -> list[SenderMessage]:
    """Read .eml files, mbox files, and maildir/plain directories of .eml."""
    out: list[SenderMessage] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            if (path / "cur").is_dir():
                for key, msg in mailbox.Maildir(str(path)).items():
                    out.append(parse_message(msg.as_bytes(), f"{path.name}:{key}"))
            else:
                for child in sorted(path.rglob("*.eml")):
                    out.append(parse_message(child.read_bytes(), str(child)))
        elif path.suffix.lower() in (".mbox", ".mbx"):
            for key, msg in mailbox.mbox(str(path)).items():
                out.append(parse_message(msg.as_bytes(), f"{path.name}:{key}"))
        elif path.is_file():
            out.append(parse_message(path.read_bytes(), str(path)))
    return out


def index_by_domain(messages: Sequence[SenderMessage]) -> dict[str, list[SenderMessage]]:
    """Group by sending domain, preferring messages that offer one-click."""
    index: dict[str, list[SenderMessage]] = {}
    for msg in messages:
        if not msg.from_domain:
            continue
        index.setdefault(msg.from_domain, []).append(msg)
    for items in index.values():
        items.sort(key=lambda m: (not m.one_click, not m.https_uri))
    return index
