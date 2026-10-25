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

    #: httpx's per-operation timeout: connect, read, write and pool each get
    #: this long. It does not bound one site, because an entry may take several
    #: steps and a trickling response resets the read clock.
    timeout: float = 15.0
    #: The wall-clock one site may consume before it is cut and recorded as
    #: TIMED_OUT. This is what actually bounds a scan: measured over 852 site
    #: runs the slowest site that produced a real answer took 4.7s, while the
    #: slowest overall took 10.1s and answered nothing -- and a scan's wall clock
    #: is set by its single slowest site, not by its median.
    site_budget: float | None = 8.0
    concurrency: int = 16
    include_disabled: bool = False
    allow_login_probe: bool = False
    allow_email_sending: bool = False
    no_password_recovery: bool = False
    only: tuple[str, ...] = ()
    vault_paths: tuple[str, ...] = ()
    hibp_api_key: str | None = None
    #: Query HIBP through the k-anonymity range endpoint (send 6 hash characters)
    #: rather than the plaintext endpoint (send the whole address). Defaults to
    #: the private path; set False only when the user opts into plaintext.
    hibp_kanon: bool = True
    extras: dict = field(default_factory=dict)


@runtime_checkable
class EvidenceSource(Protocol):
    id: str
    requires_network: bool
    #: True when running the source discloses the address to a third party.
    requires_consent: bool

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]: ...
