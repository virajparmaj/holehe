"""Why a service is on your list, and how much it should worry you.

The flags are the product. "You have an account at X" is a fact; "X holds your
address and you never gave it to them" is a reason to act.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from offlist.core.models import ServiceRecord
from offlist.worklist.score import score_for

DORMANT_AFTER = timedelta(days=365 * 3)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

FLAG_DESCRIPTIONS = {
    "never_signed_up": "holds your address but is absent from your vault -- you did not sign up here",
    "account_on_record": "your own saved mail shows you signed up here -- an account you may have forgotten",
    "data_broker": "a registered data broker: it trades in personal data and you never had a relationship with it",
    "breached": "has already lost your address in a known breach",
    "publicly_exposed": "your address is publicly readable through this service",
    "recovery_leak": "leaks a masked recovery email or phone to anyone holding your address",
    "dormant": "in your vault but not used for years",
}


def _last_used(record: ServiceRecord) -> datetime | None:
    """When the credential was last actually used, per the vault export."""
    best: datetime | None = None
    for ev in record.evidence:
        raw = ev.payload.get("last_used_at")
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(str(raw))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        best = parsed if best is None else max(best, parsed)
    return best


def flags_for(record: ServiceRecord, *, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(timezone.utc)
    sources = set(record.sources())
    flags: list[str] = []

    if "broker_registry" in sources:
        flags.append("data_broker")
    if "hibp" in sources:
        flags.append("breached")
    if "public_exposure" in sources:
        flags.append("publicly_exposed")

    if any(e.payload.get("emailrecovery") or e.payload.get("phoneNumber")
           for e in record.evidence):
        flags.append("recovery_leak")

    # Your own mail showing a verification/welcome/reset message is a record that
    # you did sign up -- so it is the opposite of `never_signed_up`, and it must
    # suppress that flag rather than sit alongside it.
    has_signup_mail = any(e.source == "mailbox" and e.payload.get("account_signal")
                          for e in record.evidence)
    if has_signup_mail:
        flags.append("account_on_record")

    # The headline signal: something can prove it holds the address, and you have
    # no record of ever creating an account -- neither a stored credential nor a
    # signup message in your own mail.
    positives = [e for e in record.evidence if e.is_positive]
    has_signup_record = record.in_vault or has_signup_mail
    if positives and not has_signup_record and "data_broker" not in flags:
        flags.append("never_signed_up")

    if record.in_vault:
        # Deliberately NOT record.last_seen: that is when *we* looked, which on a
        # fresh import is always today, so dormancy could never fire. The vault's
        # own last-used timestamp is the only thing that answers this.
        last_used = _last_used(record)
        if last_used and (now - last_used) > DORMANT_AFTER:
            flags.append("dormant")

    return flags


def severity_for(flags: Sequence[str], *, corroborated: bool = False) -> str:
    """Rank by how much is actually known, not by how alarming a label sounds.

    Being on the broker registry is a fact about the company, not proof it holds
    your address, so on its own it is medium. It becomes high when some other
    source independently puts your address there.
    """
    if "recovery_leak" in flags:
        return "high"
    if "data_broker" in flags and corroborated:
        return "high"
    if "never_signed_up" in flags and "breached" in flags:
        return "high"
    if flags:
        return "medium"
    return "low"


def triage(records: Iterable[ServiceRecord], *,
           now: datetime | None = None) -> list[ServiceRecord]:
    out = []
    for record in records:
        record.why_flagged = flags_for(record, now=now)
        # "Corroborated" means a source other than the statutory registry also
        # places your address here -- a probe hit, a breach record, your vault.
        corroborated = any(e.source != "broker_registry" for e in record.evidence)
        record.severity = severity_for(record.why_flagged, corroborated=corroborated)
        record.score, record.association = score_for(record)
        out.append(record)
    return sorted(out, key=lambda r: (-SEVERITY_RANK[r.severity], r.service))
