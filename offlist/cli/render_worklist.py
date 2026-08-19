"""Render the worklist as something you can actually work through."""

from __future__ import annotations

import json
from typing import Sequence

from offlist.core.models import ServiceRecord
from offlist.worklist.triage import FLAG_DESCRIPTIONS

SEVERITY_ORDER = ("high", "medium", "low")


def to_markdown(records: Sequence[ServiceRecord], email: str) -> str:
    lines = [f"# Removal worklist for {email}", ""]
    if not records:
        lines.append("No evidence collected yet. Run `offlist scan` and "
                     "`offlist import <vault.csv>` first.")
        return "\n".join(lines)

    counts = {s: sum(1 for r in records if r.severity == s) for s in SEVERITY_ORDER}
    lines.append(f"{len(records)} services · "
                 + " · ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER))
    lines.append("")

    for severity in SEVERITY_ORDER:
        rows = [r for r in records if r.severity == severity]
        if not rows:
            continue
        lines += [f"## {severity.title()} priority ({len(rows)})", ""]
        for r in rows:
            lines.append(f"### {r.display_name}")
            lines.append(f"`{', '.join(r.domains)}`")
            lines.append("")
            if r.why_flagged:
                lines.append("**Why it's here**")
                for flag in r.why_flagged:
                    lines.append(f"- {FLAG_DESCRIPTIONS.get(flag, flag)}")
                lines.append("")

            lines.append("**Evidence**")
            for e in r.evidence:
                when = e.observed_at.date().isoformat()
                lines.append(f"- `{e.source}` ({when}, {e.confidence.value} confidence): {e.detail}")
            lines.append("")

            rem = r.remediation or {}
            lines.append("**How to get off their list**")
            lines.append(f"- Route: `{rem.get('kind', 'none_known')}`")
            if rem.get("url"):
                lines.append(f"- Link: {rem['url']}")
            if rem.get("contact_email"):
                lines.append(f"- Contact: {rem['contact_email']}")
            if rem.get("requires_identity_proof"):
                lines.append("- Requires proof of identity")
            if rem.get("drop_covered"):
                lines.append("- Also covered by California DROP "
                             "(one request at privacy.ca.gov reaches every registered broker)")
            if rem.get("legal_basis"):
                lines.append(f"- Legal basis: {', '.join(rem['legal_basis'])}")
            elif rem.get("legal_basis_note"):
                lines.append(f"- {rem['legal_basis_note']}")
            if rem.get("notes"):
                lines.append(f"- {rem['notes']}")
            lines.append("")
    return "\n".join(lines)


def to_terminal(records: Sequence[ServiceRecord], email: str) -> str:
    lines = [f"removal worklist for {email}", ""]
    if not records:
        return lines[0] + "\n\nnothing collected yet -- run `offlist scan` first."
    for severity in SEVERITY_ORDER:
        rows = [r for r in records if r.severity == severity]
        if not rows:
            continue
        lines.append(f"{severity.upper()} ({len(rows)})")
        for r in rows:
            rem = r.remediation or {}
            flags = ",".join(r.why_flagged) or "-"
            lines.append(f"  {r.display_name:32s} {flags}")
            lines.append(f"    {rem.get('kind','none_known')}: {rem.get('url','(no known route)')}")
        lines.append("")
    lines.append("full detail: offlist worklist --format md")
    return "\n".join(lines)


def to_json(records: Sequence[ServiceRecord], email: str) -> str:
    from offlist.worklist.store import _encode, _json_default

    return json.dumps({"email": email, "services": [_encode(r) for r in records]},
                      indent=2, default=_json_default)
