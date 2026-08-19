"""Canary checks -- the thing whose absence let this catalogue rot.

You cannot register on a hundred sites, so most entries can never have a real
positive. Pretending otherwise is how the original tool ended up reporting "not
used" for amazon and wordpress. Three tiers, and the tier bounds what the check
can prove:

* Tier A -- a real positive from your own vault export. Proves discrimination.
* Tier B -- a publicly-knowable positive with recorded provenance. Proves it too.
* Tier C -- negative only, the majority. Proves the probe is mechanically alive:
  a fresh unregistrable address must produce exactly NOT_REGISTERED, not a parse
  failure or a block. It says nothing about discrimination, so the entry stays
  `unverified` and its negatives render as INDETERMINATE.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Sequence

import yaml

from offlist.catalogue.loader import catalogue_root
from offlist.catalogue.schema import Entry
from offlist.core.email import EmailAddress
from offlist.core.models import Discriminating, ProbeResult, Status

#: A random local part at a large real provider. RFC 2606 domains like
#: example.com would be cleaner in principle, but many signup endpoints reject
#: them outright as invalid, which produces a parse failure rather than the
#: negative we are trying to observe.
NEGATIVE_DOMAIN = "gmail.com"


def random_negative(domain: str = NEGATIVE_DOMAIN) -> EmailAddress:
    local = "".join(random.choice(string.ascii_lowercase + string.digits)
                    for _ in range(24))
    return EmailAddress(f"{local}@{domain}")


@dataclass
class CanaryOutcome:
    site_id: str
    tier: str
    negative_status: Status
    positive_status: Status | None
    discriminating: Discriminating
    passed: bool
    note: str = ""


def judge(entry: Entry, negative: ProbeResult,
          positive: ProbeResult | None) -> CanaryOutcome:
    """Decide what a canary run proved about one entry."""
    # A committed public positive is tier B, not tier A; the ledger should not
    # overstate provenance.
    declared = (entry.canary.tier or "c").lower()
    if positive is None:
        tier = "c"
    else:
        tier = "b" if declared == "c" else declared

    # Tier C: the only claim is that the probe still mechanically works.
    if positive is None:
        passed = negative.status is Status.NOT_REGISTERED
        note = "" if passed else f"negative probe returned {negative.status.value}"
        return CanaryOutcome(entry.id, tier, negative.status, None,
                             Discriminating.UNVERIFIED, passed, note)

    # Tier A/B: a known-registered address must come back registered, and must
    # differ from the fabricated one. Same answer for both means the site is
    # answering without looking.
    if positive.status is not Status.REGISTERED:
        return CanaryOutcome(entry.id, tier, negative.status, positive.status,
                             Discriminating.UNVERIFIED, False,
                             f"known-positive returned {positive.status.value}")
    if negative.status is Status.REGISTERED:
        return CanaryOutcome(entry.id, tier, negative.status, positive.status,
                             Discriminating.NO, False,
                             "fabricated address also reported as registered")
    if negative.status is not Status.NOT_REGISTERED:
        return CanaryOutcome(entry.id, tier, negative.status, positive.status,
                             Discriminating.UNVERIFIED, False,
                             f"negative probe returned {negative.status.value}")
    return CanaryOutcome(entry.id, tier, negative.status, positive.status,
                         Discriminating.YES, True)


def write_ledger(outcomes: Sequence[CanaryOutcome], root: Path | None = None,
                 *, measured: str | None = None) -> Path:
    """Persist measured state. Written by the canary run, never edited by hand."""
    root = root or catalogue_root()
    path = root / "ledger.yaml"

    existing = {}
    if path.is_file():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        existing = loaded.get("sites", {}) or {}

    when = measured or date.today().isoformat()
    for o in outcomes:
        record = dict(existing.get(o.site_id, {}))
        record["last_status"] = o.negative_status.value
        record["last_checked"] = when
        record["discriminating"] = o.discriminating.value
        record["canary_tier"] = o.tier
        if o.passed:
            record["consecutive_failures"] = 0
        else:
            record["consecutive_failures"] = int(record.get("consecutive_failures", 0)) + 1
            record["first_failed"] = record.get("first_failed", when)
            record["note"] = o.note
        existing[o.site_id] = record

    header = (
        "# Measured per-site state. Written by `offlist canary`; do not hand-edit.\n"
        "# `discriminating` is what downgrades an uninformative negative to\n"
        "# INDETERMINATE at report time.\n"
    )
    path.write_text(header + yaml.safe_dump({"sites": existing}, sort_keys=True),
                    encoding="utf-8")
    return path


def auto_disable_candidates(root: Path | None = None, *, threshold: int = 3) -> list[str]:
    """Sites the ledger says have failed often enough to propose disabling.

    Deliberately returns candidates rather than mutating the catalogue: three
    consecutive failures from one IP is indistinguishable from a real death, so a
    human (or a PR) makes the call.
    """
    from offlist.catalogue.loader import load_ledger

    return sorted(
        site_id for site_id, rec in load_ledger(root).items()
        if int(rec.get("consecutive_failures", 0)) >= threshold
    )
