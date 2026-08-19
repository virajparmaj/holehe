"""The consent gate.

Deliberately not configurable. There is no `--yes-to-all`, because the value of
this prompt is that a person read the specific request before it went out. A flag
that skips reading is a flag that removes the only safeguard.
"""

from __future__ import annotations

import sys
from typing import Callable

from offlist.act.models import Action

Prompter = Callable[[str], str]


class ConsentUnavailable(RuntimeError):
    """Raised when execution is requested but nobody can be asked."""


def require_interactive() -> None:
    """Refuse to execute when there is no human at the keyboard.

    Without this, `offlist act --execute` in a cron job or a pipe would sail
    through every prompt on default input and unsubscribe from things nobody
    approved.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ConsentUnavailable(
            "--execute needs an interactive terminal so each action can be "
            "confirmed individually. Run it directly, or drop --execute to see "
            "the plan without sending anything."
        )


def render_action(action: Action, index: int, total: int) -> str:
    lines = [
        "",
        "─" * 72,
        f"[{index}/{total}]  {action.display_name}  ({action.service})",
        f"  {action.summary}",
    ]
    if action.notes:
        lines.append(f"  note: {action.notes}")
    if action.preview:
        lines += ["", "  this is exactly what would be sent:", ""]
        lines += [f"    {line}" for line in action.preview.splitlines()]
    lines.append("")
    return "\n".join(lines)


def ask(action: Action, index: int, total: int, *,
        prompter: Prompter | None = None) -> bool:
    """Show the exact request and ask about this one item only."""
    prompter = prompter or input
    print(render_action(action, index, total))
    try:
        answer = prompter("  send this?  [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  aborted.")
        return False
    return answer in ("y", "yes")
