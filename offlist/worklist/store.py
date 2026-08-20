"""Where the worklist lives between runs.

The file is a concentrated dossier -- every service you use, which have been
breached, which leak recovery identifiers. It is kept out of the working
directory, out of git, mode 0600, and the address is hashed into the path rather
than written into a filename.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, ServiceRecord, Status


def state_root() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    return Path(base) / "offlist"


def state_dir(email: EmailAddress) -> Path:
    digest = hashlib.sha256(email.normalized.encode()).hexdigest()[:16]
    return state_root() / digest


def _encode(record: ServiceRecord) -> dict:
    return {
        "service": record.service,
        "display_name": record.display_name,
        "domains": record.domains,
        "category": record.category,
        "why_flagged": record.why_flagged,
        "severity": record.severity,
        "score": record.score,
        "association": record.association,
        "in_vault": record.in_vault,
        "confidence": record.confidence.value,
        "first_seen": record.first_seen.isoformat() if record.first_seen else None,
        "last_seen": record.last_seen.isoformat() if record.last_seen else None,
        "remediation": dict(record.remediation) if record.remediation else None,
        "state": record.state,
        "actions_taken": list(record.actions_taken),
        "evidence": [
            {
                "source": e.source,
                "domain": e.domain,
                "status": e.status.value,
                "confidence": e.confidence.value,
                "detail": e.detail,
                "payload": dict(e.payload),
                "observed_at": e.observed_at.isoformat(),
            }
            for e in record.evidence
        ],
    }


def _decode(raw: dict) -> ServiceRecord:
    record = ServiceRecord(
        service=raw["service"],
        display_name=raw.get("display_name", raw["service"]),
        domains=list(raw.get("domains", [])),
        category=raw.get("category", ""),
        in_vault=bool(raw.get("in_vault")),
        why_flagged=list(raw.get("why_flagged", [])),
        severity=raw.get("severity", "low"),
        score=int(raw.get("score", 0)),
        association=raw.get("association", "unknown"),
        remediation=raw.get("remediation"),
        state=raw.get("state", "todo"),
        actions_taken=list(raw.get("actions_taken", [])),
    )
    record.evidence = [
        Evidence(
            source=e["source"], domain=e["domain"],
            status=Status(e["status"]), confidence=Confidence(e["confidence"]),
            detail=e.get("detail", ""), payload=e.get("payload", {}),
            observed_at=datetime.fromisoformat(e["observed_at"]),
        )
        for e in raw.get("evidence", [])
    ]
    return record


def _json_default(value):
    """YAML turns a bare `verified: 2026-08-18` into a date; JSON needs a string."""
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def load(email: EmailAddress) -> list[ServiceRecord]:
    path = state_dir(email) / "worklist.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [_decode(r) for r in payload.get("services", [])]


def save(email: EmailAddress, records: Sequence[ServiceRecord]) -> Path:
    directory = state_dir(email)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / "worklist.json"
    payload = {
        "schema_version": 1,
        "updated_at": datetime.now().astimezone().isoformat(),
        "services": [_encode(r) for r in records],
    }
    path.write_text(json.dumps(payload, indent=2, default=_json_default),
                    encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def merge_with_history(email: EmailAddress,
                       fresh: Iterable[ServiceRecord]) -> list[ServiceRecord]:
    """Carry forward user state and older evidence.

    Evidence is append-only, so `first_seen` is stable and a service that stops
    showing up does not silently vanish from the record.
    """
    previous = {r.service: r for r in load(email)}
    out = []
    for record in fresh:
        old = previous.pop(record.service, None)
        if old is not None:
            known = {(e.source, e.domain, e.detail, e.observed_at.isoformat())
                     for e in old.evidence}
            added = [e for e in record.evidence
                     if (e.source, e.domain, e.detail,
                         e.observed_at.isoformat()) not in known]
            record.evidence = sorted(old.evidence + added, key=lambda e: e.observed_at)
            record.state = old.state
            record.actions_taken = old.actions_taken
        out.append(record)
    out.extend(previous.values())      # keep services no longer observed
    return sorted(out, key=lambda r: r.service)
