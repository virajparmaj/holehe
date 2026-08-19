"""Turn a worklist into a list of concrete, inspectable actions."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from offlist.act.message import SenderMessage, index_by_domain
from offlist.act.models import Action, ActionKind, Blocked
from offlist.act.unsubscribe import build_action as build_unsubscribe
from offlist.core.email import EmailAddress
from offlist.core.models import ServiceRecord

#: Remediation kinds that resolve to "here is a URL, you open it". The tool does
#: not drive someone else's web form: those flows carry identity checks and
#: CAPTCHAs by design, and automating them is both fragile and rude.
URL_KINDS = {"self_serve_delete", "opt_out_form", "unsubscribe_link", "drop_covered_only"}


def _pick_message(record: ServiceRecord,
                  by_domain: dict[str, list[SenderMessage]]) -> SenderMessage | None:
    for domain in record.domains:
        found = by_domain.get(domain.lower())
        if found:
            return found[0]
    # fall back to a suffix match, since mail often comes from a subdomain
    for domain in record.domains:
        for sender_domain, msgs in by_domain.items():
            if sender_domain.endswith("." + domain.lower()) and msgs:
                return msgs[0]
    return None


def build(records: Sequence[ServiceRecord], email: EmailAddress, *,
          messages: Sequence[SenderMessage] = (), letters_dir: Path | None = None,
          jurisdiction: str = "", full_name: str = "",
          dnsfunc=None, cryptographic: bool = True) -> list[Action]:
    """One action per service, fully described before anything is approved."""
    from offlist.act import letters

    by_domain = index_by_domain(messages)
    actions: list[Action] = []

    for record in records:
        remediation = record.remediation or {}
        kind = remediation.get("kind", "none_known")
        message = _pick_message(record, by_domain)

        # A signed one-click header beats whatever the catalogue says, because it
        # is evidence from the sender themselves rather than a curated guess.
        if message is not None and message.one_click:
            actions.append(build_unsubscribe(record.service, record.display_name,
                                             message, dnsfunc=dnsfunc,
                                             cryptographic=cryptographic))
            continue

        if kind == "unsubscribe_oneclick":
            actions.append(Action(
                service=record.service, display_name=record.display_name,
                kind=ActionKind.UNSUBSCRIBE_ONECLICK,
                summary="one-click unsubscribe",
                blocked=Blocked.NO_MESSAGE,
                notes=("The catalogue says this sender supports one-click, but no "
                       "signed message from them was supplied. Pass one with "
                       "`--mail`, or unsubscribe from the message itself."),
            ))
            continue

        if kind == "email_request":
            text = letters.compose(record, email, jurisdiction=jurisdiction,
                                   full_name=full_name)
            path = (letters_dir / f"{record.service}-deletion-request.txt"
                    if letters_dir else None)
            actions.append(Action(
                service=record.service, display_name=record.display_name,
                kind=ActionKind.WRITE_LETTER,
                summary=f"write a deletion request to "
                        f"{remediation.get('contact_email', 'their privacy contact')}",
                preview=text,
                letter_path=str(path) if path else None,
                letter_text=text,
                notes="Written to disk only. Send it yourself.",
            ))
            continue

        if kind in URL_KINDS and remediation.get("url"):
            note = remediation.get("notes", "")
            if remediation.get("requires_identity_proof"):
                note = (note + " Requires proof of identity.").strip()
            actions.append(Action(
                service=record.service, display_name=record.display_name,
                kind=ActionKind.OPEN_URL,
                summary=f"{kind.replace('_', ' ')}: open in a browser",
                preview=remediation["url"],
                url=remediation["url"],
                method="GET",
                notes=note,
            ))
            continue

        actions.append(Action(
            service=record.service, display_name=record.display_name,
            kind=ActionKind.NOTHING,
            summary="no known removal route",
            notes="Catalogue TODO -- add an entry to offlist/data/remediation.yaml.",
        ))

    return actions


def summarise(actions: Sequence[Action]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for action in actions:
        if action.executable:
            key = "ready to execute"
        elif action.blocked is not None:
            key = "refused"
        elif action.kind is ActionKind.WRITE_LETTER:
            key = "letter to write"
        elif action.kind is ActionKind.OPEN_URL:
            key = "manual, url provided"
        else:
            key = "no route known"
        counts[key] = counts.get(key, 0) + 1
    return counts
