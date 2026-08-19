"""Writing files that describe a person.

Almost everything this tool emits is a dossier: an address plus the services
that hold it, which of them were breached, which leak recovery identifiers, and
sometimes a real name. The worklist store already took care over this; the CSV,
JSON and letter writers did not, which was an inconsistency rather than a
decision.

These helpers create the file with 0600 from the start rather than writing it
and chmod-ing afterwards, so there is no window in which the contents are
readable by other users on the machine.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO

#: Owner read/write only.
PRIVATE_FILE = 0o600
PRIVATE_DIR = 0o700


@contextmanager
def open_private(path: Path, *, newline: str | None = None) -> Iterator[TextIO]:
    """Open a text file for writing, owner-only from the moment it exists."""
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, PRIVATE_DIR)

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE)
    handle = os.fdopen(fd, "w", encoding="utf-8", newline=newline)
    try:
        yield handle
    finally:
        handle.close()
    # An existing file keeps its old mode through O_CREAT, so restate it.
    os.chmod(path, PRIVATE_FILE)


def write_private_text(path: Path, text: str) -> Path:
    path = Path(path)
    with open_private(path) as handle:
        handle.write(text)
    return path
