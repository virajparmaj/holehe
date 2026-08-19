"""Result and evidence types shared by every part of offlist.

The central design decision here is that a source never returns a verdict, only
dated `Evidence`. Reasoning across sources happens in exactly one place
(offlist.worklist.merge), so a new source is a new file rather than a refactor.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence


class Status(str, Enum):
    """Why a probe ended the way it did.

    The original tool collapsed every failure into a single `rateLimit` boolean,
    which is why a measured 76 failures reported as rate limits when only 2 were.
    Each member below is a distinct remedy: retry later, change client, fix the
    definition, or delete the site.
    """

    REGISTERED = "registered"
    NOT_REGISTERED = "not_registered"
    #: Ran cleanly, but the site is not known to distinguish a real address from
    #: a fake one, so a negative carries no information.
    INDETERMINATE = "indeterminate"
    RATE_LIMITED = "rate_limited"          # 429 / explicit throttle -- retry later
    BLOCKED = "blocked"                    # WAF, bot check, captcha -- needs a different client
    ENDPOINT_GONE = "endpoint_gone"        # 404/410 -- the definition is stale
    UNREACHABLE = "unreachable"            # DNS/connect/TLS/timeout -- the host may be dead
    SERVER_ERROR = "server_error"          # 5xx -- their problem, probably transient
    PARSE_FAILED = "parse_failed"          # 200, but nothing matched -- the definition is stale
    DISABLED = "disabled"                  # not executed: enabled=false in the catalogue
    SKIPPED = "skipped"                    # not executed: gated behind a consent flag

    @property
    def is_answer(self) -> bool:
        """True if the probe actually determined something."""
        return self in (Status.REGISTERED, Status.NOT_REGISTERED)

    @property
    def is_failure(self) -> bool:
        """True if the probe wanted to answer and could not."""
        return self in (
            Status.RATE_LIMITED,
            Status.BLOCKED,
            Status.ENDPOINT_GONE,
            Status.UNREACHABLE,
            Status.SERVER_ERROR,
            Status.PARSE_FAILED,
        )

    @property
    def is_actionable_by_us(self) -> bool:
        """True if the fix is ours (a stale definition) rather than theirs."""
        return self in (Status.ENDPOINT_GONE, Status.PARSE_FAILED)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Discriminating(str, Enum):
    """Whether a site has been proven to tell a real address from a fake one.

    `UNVERIFIED` is the honest default. A site that has only ever been tested
    with an unregistrable address has proven its transport works, not that its
    negative means anything -- so its negatives are reported as INDETERMINATE.
    """

    YES = "yes"
    NO = "no"
    UNVERIFIED = "unverified"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProbeResult:
    """The outcome of running one catalogue entry against one address."""

    site_id: str
    domain: str
    status: Status
    confidence: Confidence = Confidence.MEDIUM
    category: str = ""
    method: str = ""
    http_code: int | None = None
    detail: str = ""
    discriminating: Discriminating = Discriminating.UNVERIFIED
    emailrecovery: str | None = None
    phone_number: str | None = None
    full_name: str | None = None
    created_at: str | None = None
    others: Mapping[str, Any] | None = None
    elapsed_ms: int | None = None
    checked_at: datetime = field(default_factory=_now)

    def downgraded(self) -> "ProbeResult":
        """Rewrite an uninformative negative into INDETERMINATE.

        A `not_registered` from a site that has never been shown to discriminate
        is exactly the failure mode measured in the audit: 26 modules answered
        "not used" for both a real and a fabricated address. Rather than drop
        those sites, we keep them and stop pretending their negatives are answers.
        Positives are never downgraded -- a hit is a hit.
        """
        if self.status is not Status.NOT_REGISTERED:
            return self
        if self.discriminating is Discriminating.YES:
            return self
        return replace(
            self,
            status=Status.INDETERMINATE,
            confidence=Confidence.LOW,
            detail=self.detail or "site not proven to distinguish a real address from a fake one",
        )


@dataclass(frozen=True)
class Evidence:
    """One dated observation that a service holds this address.

    Evidence is append-only. A later run adds a new record rather than mutating
    an old one, so the worklist doubles as an audit log of what was seen when.
    """

    source: str
    domain: str
    status: Status
    confidence: Confidence
    detail: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=_now)

    @property
    def is_positive(self) -> bool:
        """True if this evidence asserts the service actually holds the address."""
        return self.status is Status.REGISTERED


@dataclass
class ServiceRecord:
    """Everything known about one canonical service, across all sources."""

    service: str
    display_name: str
    domains: list[str] = field(default_factory=list)
    category: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    in_vault: bool = False
    why_flagged: list[str] = field(default_factory=list)
    severity: str = "low"
    remediation: Mapping[str, Any] | None = None
    state: str = "todo"
    actions_taken: list[Mapping[str, Any]] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime | None:
        return min((e.observed_at for e in self.evidence), default=None)

    @property
    def last_seen(self) -> datetime | None:
        return max((e.observed_at for e in self.evidence), default=None)

    @property
    def confidence(self) -> Confidence:
        """Best confidence across all evidence."""
        order = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
        best = max((e.confidence for e in self.evidence), key=lambda c: order[c], default=None)
        return best or Confidence.LOW

    def sources(self) -> Sequence[str]:
        seen: list[str] = []
        for e in self.evidence:
            if e.source not in seen:
                seen.append(e.source)
        return seen
