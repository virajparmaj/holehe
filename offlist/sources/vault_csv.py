"""Password-manager / browser CSV import.

This is the cheapest source to build and often the most complete, and it is the
one that makes the headline signal computable: a service holding your address
that does *not* appear in your vault is a service you never deliberately signed
up with. It is also the only realistic supply of tier-A canary positives.

Entirely offline. No API key, no OAuth consent screen, no network.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable, Iterator

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, Status
from offlist.sources.base import RunContext

#: Column names used by the common exporters, lowercased.
URL_COLUMNS = ("url", "urls", "login_uri", "website", "site", "web site", "hostname")
USER_COLUMNS = ("username", "login_username", "user", "email", "account", "login")
NAME_COLUMNS = ("name", "title", "item name", "display name")
DATE_COLUMNS = ("last used", "last_used", "modified", "last modified",
                "password_last_changed", "created")


def parse_timestamp(value: str) -> datetime | None:
    """Best-effort parse of the many shapes exporters use for a date.

    1Password and Bitwarden write ISO 8601; Firefox writes unix milliseconds;
    others write a plain date. Anything unrecognised returns None rather than a
    guess -- a wrong date here silently mis-flags an account as dormant.
    """
    raw = (value or "").strip()
    if not raw:
        return None

    if raw.isdigit():
        number = int(raw)
        if number > 10_000_000_000:      # Firefox exports milliseconds
            number //= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d",
                "%d %b %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _pick(row: dict[str, str], candidates: Iterable[str]) -> str:
    for key in candidates:
        for actual, value in row.items():
            if actual and actual.strip().lower() == key and value:
                return value.strip()
    return ""


def domain_of(url: str) -> str:
    """Reduce a stored URL to its registrable domain."""
    if not url:
        return ""
    # Registry and vault cells sometimes hold several URLs in one field.
    raw = url.strip()
    for sep in (";", ",", " and ", "\n"):
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0]
    raw = raw.rsplit("@", 1)[-1].split(":", 1)[0]
    try:
        import tldextract

        parts = tldextract.extract(raw)
        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}".lower()
    except Exception:
        pass
    return raw.lower().removeprefix("www.")


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def read_vault(path: Path) -> Iterator[dict]:
    """Yield normalised records from a 1Password / Bitwarden / browser export."""
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            url = _pick(row, URL_COLUMNS)
            domain = domain_of(url)
            if not domain:
                continue
            yield {
                "domain": domain,
                "url": url,
                "username": _pick(row, USER_COLUMNS),
                "name": _pick(row, NAME_COLUMNS) or domain,
                "last_used": _pick(row, DATE_COLUMNS),
                "last_used_at": _iso(parse_timestamp(_pick(row, DATE_COLUMNS))),
                "source_file": path.name,
            }


def collect_sync(email: EmailAddress, paths: Iterable[Path]) -> list[Evidence]:
    """Evidence for entries whose stored username matches the address."""
    seen: set[str] = set()
    out: list[Evidence] = []
    target = email.normalized

    for path in paths:
        for rec in read_vault(path):
            if rec["username"].strip().lower() != target:
                continue
            if rec["domain"] in seen:
                continue
            seen.add(rec["domain"])
            out.append(Evidence(
                source="vault_csv",
                domain=rec["domain"],
                status=Status.REGISTERED,
                confidence=Confidence.HIGH,
                detail=f"stored credential in {rec['source_file']}",
                payload={k: v for k, v in rec.items() if v},
                observed_at=datetime.now(timezone.utc),
            ))
    return out


def vault_domains(paths: Iterable[Path]) -> set[str]:
    """Every domain in the vault, regardless of which address it is under.

    Used to answer "did I sign up here at all?", which is a different question
    from "did I sign up here with this address".
    """
    return {rec["domain"] for path in paths for rec in read_vault(path)}


class VaultCsvSource:
    id = "vault_csv"
    requires_network = False
    requires_consent = False

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        for ev in collect_sync(email, [Path(p) for p in ctx.vault_paths]):
            yield ev
