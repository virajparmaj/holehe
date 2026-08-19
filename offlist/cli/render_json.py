"""Versioned JSON output, so downstream tooling can pin a shape."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from offlist import __version__
from offlist.core.models import ProbeResult

SCHEMA_VERSION = 1


def to_dict(results: Sequence[ProbeResult], email: str, elapsed: float) -> dict:
    counts = Counter(r.status.value for r in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "email": email,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "summary": dict(sorted(counts.items())),
        "results": [
            {
                "site_id": r.site_id,
                "domain": r.domain,
                "category": r.category,
                "method": r.method,
                "status": r.status.value,
                "confidence": r.confidence.value,
                "discriminating": r.discriminating.value,
                "http_code": r.http_code,
                "detail": r.detail,
                "emailrecovery": r.emailrecovery,
                "phoneNumber": r.phone_number,
                "full_name": r.full_name,
                "created_at": r.created_at,
                "elapsed_ms": r.elapsed_ms,
                "checked_at": r.checked_at.isoformat(),
            }
            for r in results
        ],
    }


def write(results: Sequence[ProbeResult], email: str, elapsed: float,
          path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(to_dict(results, email, elapsed), indent=2),
                    encoding="utf-8")
    return path
