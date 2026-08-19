"""CSV export with a fixed header.

The original derived its fieldnames from `data[0].keys()`, so a run in which any
module errored produced rows with mismatched keys and DictWriter raised
ValueError; an empty result set raised IndexError. Pinning the header fixes both.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence

from offlist.core.models import ProbeResult

FIELDNAMES = (
    "site_id", "domain", "category", "method", "status", "confidence",
    "discriminating", "http_code", "detail", "emailrecovery", "phoneNumber",
    "full_name", "created_at", "elapsed_ms", "checked_at",
)


def to_row(r: ProbeResult) -> dict:
    return {
        "site_id": r.site_id,
        "domain": r.domain,
        "category": r.category,
        "method": r.method,
        "status": r.status.value,
        "confidence": r.confidence.value,
        "discriminating": r.discriminating.value,
        "http_code": r.http_code or "",
        "detail": r.detail,
        "emailrecovery": r.emailrecovery or "",
        "phoneNumber": r.phone_number or "",
        "full_name": r.full_name or "",
        "created_at": r.created_at or "",
        "elapsed_ms": r.elapsed_ms if r.elapsed_ms is not None else "",
        "checked_at": r.checked_at.isoformat(),
    }


def write(results: Sequence[ProbeResult], path: Path) -> Path:
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES,
                                extrasaction="ignore", restval="")
        writer.writeheader()
        writer.writerows(to_row(r) for r in results)
    return path
