"""Email address handling.

Modules in the original tree hand-rolled `email.replace('@', '%40')` in several
places and one of them (mail_ru) shipped a format string with no `f` prefix, so
it sent the literal text `{email}` for years. Centralising the derivations here
means a template can only ever reference forms that are actually computed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import quote

# Deliberately permissive: this rejects obvious junk, it does not attempt to
# implement RFC 5322. Anything stricter starts rejecting real addresses.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class InvalidEmail(ValueError):
    pass


@dataclass(frozen=True)
class EmailAddress:
    raw: str

    def __post_init__(self) -> None:
        if not EMAIL_RE.match(self.raw):
            raise InvalidEmail(f"not a valid email address: {self.raw!r}")

    @property
    def local(self) -> str:
        return self.raw.rsplit("@", 1)[0]

    @property
    def domain(self) -> str:
        return self.raw.rsplit("@", 1)[1]

    @property
    def urlencoded(self) -> str:
        return quote(self.raw, safe="")

    @property
    def md5(self) -> str:
        """Gravatar keys profiles on the md5 of the lowercased, trimmed address."""
        return hashlib.md5(self.normalized.encode()).hexdigest()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.normalized.encode()).hexdigest()

    @property
    def sha1(self) -> str:
        """Uppercase SHA-1 of the normalised address.

        HIBP's k-anonymity email search keys on this: the address is treated as
        case-insensitive and trimmed, so hashing the normalized form matches what
        the service hashed on its side. Uppercase hex matches the range API's
        returned `hashSuffix` casing, so a suffix comparison needs no folding.
        """
        return hashlib.sha1(self.normalized.encode()).hexdigest().upper()

    @property
    def normalized(self) -> str:
        return self.raw.strip().lower()

    def __str__(self) -> str:
        return self.raw


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value))
