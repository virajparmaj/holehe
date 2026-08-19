"""What "get off their list" actually resolves to for a given service.

Seven kinds, ordered by how automatable they are. Only the first is a plain HTTP
call, and even that one is gated behind per-item confirmation -- see the note on
RFC 8058 below.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Iterable, Mapping

import yaml

from offlist.core.models import ServiceRecord

KINDS = (
    "unsubscribe_oneclick",   # RFC 8058: POST List-Unsubscribe=One-Click
    "unsubscribe_link",       # legacy List-Unsubscribe, open in a browser
    "self_serve_delete",      # a stable account-deletion URL
    "opt_out_form",           # broker opt-out, may require identity proof
    "email_request",          # generate a GDPR Art.17 / CCPA letter -- never send it
    "drop_covered_only",      # registered CA broker, no usable direct path
    "none_known",             # honest gap; counts as a catalogue TODO
)

#: Statutory rights by jurisdiction. Outside these, a request is voluntary, and
#: saying so matters -- a large share of voluntary requests are simply ignored.
LEGAL_BASIS = {
    "CA": ["CCPA/CPRA §1798.105 (deletion)", "California Delete Act / DROP"],
    "EU": ["GDPR Art.17 (erasure)", "GDPR Art.15 (access)"],
    "UK": ["UK GDPR Art.17 (erasure)", "UK GDPR Art.15 (access)"],
}


def load_table(path: Path | None = None) -> Mapping[str, dict]:
    path = path or Path(str(files("offlist") / "data" / "remediation.yaml"))
    if not Path(path).is_file():
        return {}
    return (yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}).get("services", {})


def resolve(record: ServiceRecord, table: Mapping[str, dict] | None = None,
            *, jurisdiction: str = "") -> dict:
    table = table if table is not None else load_table()
    entry = dict(table.get(record.service) or {})

    if not entry:
        if "data_broker" in record.why_flagged:
            # Registration is mandatory, so a broker with no curated opt-out is
            # still reachable through the statutory route.
            entry = {
                "kind": "drop_covered_only",
                "url": "https://privacy.ca.gov/data-brokers",
                "notes": ("Registered CA data broker with no curated opt-out yet. "
                          "DROP covers every registered broker with a single request, "
                          "but it is consumer-authenticated and California-resident "
                          "only -- no tool can submit it for you."),
                "drop_covered": True,
            }
        else:
            entry = {"kind": "none_known",
                     "notes": "No documented removal path yet. Catalogue TODO."}

    entry.setdefault("kind", "none_known")
    entry.setdefault("drop_covered", False)
    entry.setdefault("requires_identity_proof", False)
    entry.setdefault("automatable", entry["kind"] == "unsubscribe_oneclick")
    entry["legal_basis"] = LEGAL_BASIS.get(jurisdiction.upper(), [])
    if not entry["legal_basis"]:
        entry["legal_basis_note"] = (
            "No statutory deletion right identified for your jurisdiction; "
            "this request is voluntary and may simply be ignored."
        )
    return entry


def attach(records: Iterable[ServiceRecord], *, jurisdiction: str = "") -> list[ServiceRecord]:
    table = load_table()
    out = []
    for record in records:
        record.remediation = resolve(record, table, jurisdiction=jurisdiction)
        out.append(record)
    return out
