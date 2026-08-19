"""Placeholder expansion for catalogue definitions.

The set of placeholders is closed on purpose. Anything a definition can reference
is computed here, so a typo raises rather than silently sending literal text --
which is exactly the bug that left the original mail_ru module posting the string
"{email}" to the API instead of an address.
"""

from __future__ import annotations

import random
import re
import string
from typing import Any, Mapping

from offlist.core.email import EmailAddress

_TOKEN_RE = re.compile(r"\{([a-z_][a-z0-9_]*(?:\.[A-Za-z0-9_]+)?)(?:\(([^)]*)\))?\}")

_ALNUM_LOWER = string.ascii_lowercase + string.digits


class TemplateError(ValueError):
    pass


def _ints(args: str, where: str, count: int) -> list[int]:
    parts = [p.strip() for p in args.split(",") if p.strip()]
    if len(parts) != count:
        raise TemplateError(f"{where}: expected {count} numeric argument(s), got {args!r}")
    try:
        return [int(p) for p in parts]
    except ValueError as exc:
        raise TemplateError(f"{where}: non-numeric argument in {args!r}") from exc


def render(value: Any, email: EmailAddress, captured: Mapping[str, str] | None = None) -> Any:
    """Expand placeholders in a string, or recursively through a dict/list."""
    if isinstance(value, Mapping):
        return {k: render(v, email, captured) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, email, captured) for v in value]
    if not isinstance(value, str):
        return value

    captured = captured or {}

    def _swap(m: re.Match) -> str:
        name, args = m.group(1), m.group(2)
        where = m.group(0)

        if name.startswith("captured."):
            key = name.split(".", 1)[1]
            if key not in captured:
                raise TemplateError(f"{where}: nothing captured under {key!r}")
            return str(captured[key])

        if name == "email":
            return email.raw
        if name == "email_urlencoded":
            return email.urlencoded
        if name == "email_local":
            return email.local
        if name == "email_domain":
            return email.domain
        if name == "email_normalized":
            return email.normalized
        if name == "md5":
            return email.md5
        if name == "sha256":
            return email.sha256

        if name == "random_alpha":
            (n,) = _ints(args or "", where, 1)
            return "".join(random.choice(string.ascii_lowercase) for _ in range(n))
        if name == "random_digits":
            (n,) = _ints(args or "", where, 1)
            return "".join(random.choice(string.digits) for _ in range(n))
        if name == "random_alnum_lower":
            nums = _ints(args or "", where, 2) if "," in (args or "") else _ints(args or "", where, 1) * 2
            length = random.randint(min(nums), max(nums))
            return "".join(random.choice(_ALNUM_LOWER) for _ in range(length))
        if name == "random_int":
            lo, hi = _ints(args or "", where, 2)
            return str(random.randint(lo, hi))

        raise TemplateError(f"{where}: unknown placeholder {name!r}")

    return _TOKEN_RE.sub(_swap, value)
