"""The evidence-source protocol.

A source never decides whether you should act on something -- it reports dated
observations. All cross-source reasoning happens in offlist.worklist.merge, so
adding a source is a new file rather than a change to existing logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import AsyncIterator, Protocol, runtime_checkable

from offlist.core.email import EmailAddress
from offlist.core.models import Evidence


@dataclass
class RunContext:
    """Options a source may need, gathered in one place rather than passed piecemeal."""

    timeout: float = 15.0
    concurrency: int = 16
    include_disabled: bool = False
    allow_login_probe: bool = False
    allow_email_sending: bool = False
    no_password_recovery: bool = False
    only: tuple[str, ...] = ()
    vault_paths: tuple[str, ...] = ()
    hibp_api_key: str | None = None
    extras: dict = field(default_factory=dict)


@runtime_checkable
class EvidenceSource(Protocol):
    id: str
    requires_network: bool
    #: True when running the source discloses the address to a third party.
    requires_consent: bool

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]: ...
