"""Dry-run rendering of an action plan."""

from __future__ import annotations

from typing import Sequence

from offlist.act.models import Action, ActionKind
from offlist.act.plan import summarise

ORDER = [
    ("ready to execute", lambda a: a.executable),
    ("refused", lambda a: a.blocked is not None),
    ("letter to write", lambda a: a.kind is ActionKind.WRITE_LETTER),
    ("manual, url provided", lambda a: a.kind is ActionKind.OPEN_URL),
    ("no route known", lambda a: a.kind is ActionKind.NOTHING),
]

HEADINGS = {
    "ready to execute":
        "can be done for you (a signed one-click unsubscribe)",
    "refused":
        "refused -- automating these would do more harm than good",
    "letter to write":
        "letters offlist will write for you to send yourself",
    "manual, url provided":
        "open these yourself -- offlist does not drive other people's forms",
    "no route known":
        "no documented removal route yet",
}


def render(actions: Sequence[Action], email: str, *, executed: bool = False) -> str:
    lines = [f"action plan for {email}", ""]
    if not actions:
        return lines[0] + "\n\nnothing to act on -- run `offlist worklist` first."

    for key, predicate in ORDER:
        rows = [a for a in actions if predicate(a)]
        # `refused` overlaps nothing else because executable implies blocked is None
        if key != "ready to execute":
            rows = [a for a in rows if not a.executable]
        if key == "refused":
            rows = [a for a in actions if a.blocked is not None]
        if not rows:
            continue
        lines.append(f"{HEADINGS[key]}  ({len(rows)})")
        for a in rows:
            lines.append(f"  {a.display_name:34s} {a.summary}")
            if a.url and a.kind is not ActionKind.UNSUBSCRIBE_ONECLICK:
                lines.append(f"    {a.url}")
            if a.blocked is not None:
                lines.append(f"    refused: {a.notes}")
            elif a.letter_path:
                lines.append(f"    -> {a.letter_path}")
        lines.append("")

    counts = summarise(actions)
    lines.append(" · ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    if not executed:
        ready = counts.get("ready to execute", 0)
        lines.append("")
        lines.append("Nothing has been sent. This is a dry run.")
        if ready:
            lines.append(f"Run with --execute to be asked about each of the "
                         f"{ready} sendable item(s), one at a time.")
    return "\n".join(lines)
