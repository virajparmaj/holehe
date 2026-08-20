"""Generate deletion-request letters.

Written to disk, never sent. There is deliberately no SMTP client anywhere in
this package: a tool that can mail on your behalf is a bulk sender operating
under your identity, and a misfire leaves no audit trail. Generating a correct
letter is the useful part; pressing send is yours.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from offlist.core.email import EmailAddress
from offlist.core.paths import PRIVATE_DIR, write_private_text
from offlist.core.models import ServiceRecord


@dataclass(frozen=True)
class LetterSpec:
    statute: str
    right: str
    #: Statutory response window. GDPR Art.12(3) is one month; CCPA
    #: §1798.130(a)(2) is 45 days. Both allow a documented extension.
    response_days: int
    extension_note: str


SPECS = {
    "EU": LetterSpec(
        statute="Articles 15 and 17 of the General Data Protection Regulation (EU) 2016/679",
        right="erasure of my personal data, and access to any data you hold about me",
        response_days=30,
        extension_note="Article 12(3) allows a further two months where necessary, "
                       "provided you tell me within one month and explain why.",
    ),
    "UK": LetterSpec(
        statute="Articles 15 and 17 of the UK GDPR and the Data Protection Act 2018",
        right="erasure of my personal data, and access to any data you hold about me",
        response_days=30,
        extension_note="You may extend by a further two months where necessary, "
                       "provided you tell me within one month and explain why.",
    ),
    "CA": LetterSpec(
        statute="Section 1798.105 of the California Consumer Privacy Act, "
                "as amended by the CPRA",
        right="deletion of my personal information, and disclosure of the categories "
              "of personal information you have collected about me",
        response_days=45,
        extension_note="Section 1798.130(a)(2) allows one further 45-day extension "
                       "where reasonably necessary, with notice to me.",
    ),
}

VOLUNTARY = LetterSpec(
    statute="",
    right="deletion of any personal data you hold about me",
    response_days=30,
    extension_note="",
)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "service"


def compose(record: ServiceRecord, email: EmailAddress, *,
            jurisdiction: str = "", today: date | None = None,
            full_name: str = "") -> str:
    """Render a deletion request for one service."""
    today = today or date.today()
    spec = SPECS.get(jurisdiction.upper(), VOLUNTARY)
    deadline = today + timedelta(days=spec.response_days)
    contact = (record.remediation or {}).get("contact_email") or "(privacy contact not known)"

    why = []
    for ev in record.evidence:
        why.append(f"  - {ev.detail} (observed {ev.observed_at.date().isoformat()}, "
                   f"source: {ev.source})")

    if spec.statute:
        basis = (f"I am exercising my rights under {spec.statute}. "
                 f"I request {spec.right}.")
        timing = (f"Please confirm in writing what you have done by "
                  f"{deadline.isoformat()}. {spec.extension_note}")
    else:
        # Saying this plainly matters. A large share of voluntary requests are
        # simply ignored, and the user should know that going in.
        basis = (f"I request {spec.right}. I am not asserting a statutory right here: "
                 f"as far as I can establish, no deletion statute applies to me in "
                 f"your jurisdiction, so this is a request you may decline.")
        timing = (f"I would appreciate a reply by {deadline.isoformat()}.")

    is_broker = "data_broker" in (record.why_flagged or [])
    subject = ("Access and deletion request" if is_broker
               else "Data deletion request")

    lines = [
        f"To: {contact}",
        f"Subject: {subject} - {email.raw}",
        "",
        f"Date: {today.isoformat()}",
        "",
        "To whom it may concern,",
        "",
        f"My email address is {email.raw}."
        + (f" My name is {full_name}." if full_name else ""),
        "",
        basis,
        "",
        "Specifically, I ask that you:",
        "  1. Delete all personal data associated with this email address, including "
        "any inferences or derived profiles.",
        "  2. Tell me the categories of data you held and where you obtained them.",
        "  3. Instruct any third parties you sold or shared that data with to do the same.",
        "  4. Stop sending me marketing of any kind.",
        "",
    ]

    # Data brokers profile people who never signed up, so the question that
    # matters is often "are you processing my data at all", not "close my
    # account". Ask for confirmation of processing and the access items the
    # statutory right of access covers, alongside the deletion above.
    if is_broker:
        lines += [
            "As a data broker you may hold information about me without my ever "
            "having had a direct relationship with you. I therefore also exercise "
            "my right of access. Please confirm whether you are processing personal "
            "information relating to this address and, if so, provide:",
            "  a. a copy of that information;",
            "  b. the source or sources from which you obtained it;",
            "  c. the purposes for which you process it;",
            "  d. the categories of recipients you have sold or disclosed it to;",
            "  e. the applicable retention period, or the criteria used to set it; and",
            "  f. any account, profile, or listing identifier associated with this address.",
            "",
        ]

    lines += [
        timing,
        "",
    ]

    if why:
        lines += ["For reference, this is why I believe you hold data about me:"] + why + [""]

    lines += [
        "If you believe an exemption applies to any part of this request, please "
        "identify the specific exemption and the data it covers, rather than "
        "declining the request as a whole.",
        "",
        "Regards,",
        full_name or email.raw,
        "",
        "--",
        "This letter was generated locally by offlist and has not been sent by any "
        "automated system.",
    ]
    return "\n".join(lines)


def write(record: ServiceRecord, email: EmailAddress, directory: Path, *,
          jurisdiction: str = "", full_name: str = "",
          today: date | None = None) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, PRIVATE_DIR)
    text = compose(record, email, jurisdiction=jurisdiction, full_name=full_name,
                   today=today)
    # Carries your name, address and the services involved.
    return write_private_text(
        directory / f"{_slug(record.service)}-deletion-request.txt", text)
