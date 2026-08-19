"""Types describing a proposed action and what happened to it."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class ActionKind(str, Enum):
    #: RFC 8058 one-click: a plain POST. The only kind this tool executes.
    UNSUBSCRIBE_ONECLICK = "unsubscribe_oneclick"
    #: A letter written to disk for you to send yourself.
    WRITE_LETTER = "write_letter"
    #: A URL to open. We never drive someone else's web form.
    OPEN_URL = "open_url"
    #: Nothing to do, and we say why.
    NOTHING = "nothing"


class Blocked(str, Enum):
    """Why an otherwise-automatable action is refused."""

    NOT_ONE_CLICK = "no List-Unsubscribe-Post: List-Unsubscribe=One-Click header"
    NO_HTTPS_URI = "List-Unsubscribe offers no https URI (mailto alone cannot be automated)"
    DKIM_MISSING = "the message carries no DKIM signature"
    DKIM_NOT_COVERING = "the DKIM signature does not cover the List-Unsubscribe headers"
    DKIM_INVALID = "the DKIM signature failed verification"
    DKIM_UNCHECKED = ("the DKIM signature could not be checked -- "
                      "install offlist[dkim] to enable one-click unsubscribe")
    DKIM_UNALIGNED = "the DKIM signing domain does not align with the unsubscribe endpoint"
    NO_MESSAGE = "no signed message for this sender was supplied"


@dataclass(frozen=True)
class Action:
    """One proposed step, fully described before anyone is asked to approve it."""

    service: str
    display_name: str
    kind: ActionKind
    summary: str
    #: The literal request or file that would be produced. Shown verbatim at the
    #: confirmation prompt -- an approval you cannot inspect is not an approval.
    preview: str = ""
    url: str | None = None
    method: str = "POST"
    body: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    letter_path: str | None = None
    letter_text: str | None = None
    blocked: Blocked | None = None
    notes: str = ""

    @property
    def executable(self) -> bool:
        """Only a verified one-click unsubscribe is ever executed by this tool."""
        return self.kind is ActionKind.UNSUBSCRIBE_ONECLICK and self.blocked is None


@dataclass(frozen=True)
class ActionResult:
    action: Action
    outcome: str            # executed | declined | skipped | written | failed | refused
    detail: str = ""
    http_code: int | None = None
    performed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_record(self) -> dict[str, Any]:
        return {
            "kind": self.action.kind.value,
            "outcome": self.outcome,
            "detail": self.detail,
            "url": self.action.url,
            "http_code": self.http_code,
            "performed_at": self.performed_at.isoformat(),
        }
