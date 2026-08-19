"""Data brokers, from the statutory registries.

This is the highest-precision source in the tool and the one that best matches
the actual question: a registered data broker is, by the statutory definition,
a business that collects and sells personal information about people it has no
direct relationship with. If your address is in circulation at all, it is
probably here -- and you certainly never signed up.

Registration is compulsory, so unlike endpoint probing this source has
essentially no false positives. It also needs no probing whatsoever.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable

import httpx

from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, Status
from offlist.sources.base import RunContext

#: California Delete Act (SB 362) registry. Refreshed after each 31 January
#: registration deadline; ~545 brokers as of 2026-01-01.
CA_REGISTRY_URL = "https://cppa.ca.gov/data_broker_registry/registry.csv"
VT_REGISTRY_URL = "https://bizfilings.vermont.gov/online/DatabrokerInquire/"

# The published headers carry trailing colons and a UTF-8 BOM, and the wording
# shifts between registry years -- so match on a normalised prefix rather than an
# exact string.
NAME_COLUMNS = ("data broker name", "business name", "name", "company")
SITE_COLUMNS = ("data broker primary website", "website", "website url", "url", "web site")
EMAIL_COLUMNS = ("data broker primary contact email address", "email address",
                 "contact email", "email")


def _normalise(header: str) -> str:
    return (header or "").lstrip("\ufeff").strip().rstrip(":").strip().lower()


def _pick(row: dict, keys: Iterable[str]) -> str:
    normalised = {_normalise(k): (v or "") for k, v in row.items()}
    for key in keys:
        value = normalised.get(key)
        if value:
            return str(value).strip()
    # fall back to a prefix match, so a reworded header still resolves
    for key in keys:
        for actual, value in normalised.items():
            if value and actual.startswith(key):
                return str(value).strip()
    return ""


def parse_registry_csv(text: str, jurisdiction: str = "CA") -> list[dict]:
    """Normalise a statutory registry export into broker records."""
    rows = []
    for raw in csv.DictReader(io.StringIO(text.lstrip("\ufeff"))):
        name = _pick(raw, NAME_COLUMNS)
        if not name:
            continue
        site = _pick(raw, SITE_COLUMNS)
        from offlist.sources.vault_csv import domain_of

        rows.append({
            "name": name,
            "domain": domain_of(site),
            "website": site,
            "contact_email": _pick(raw, EMAIL_COLUMNS),
            "jurisdiction": jurisdiction,
        })
    return rows


async def fetch_registry(url: str = CA_REGISTRY_URL, *,
                         timeout: float = 60.0) -> list[dict]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return parse_registry_csv(response.text)


def cache_path() -> Path:
    from importlib.resources import files

    return Path(str(files("offlist") / "data" / "brokers" / "cppa.csv"))


def load_cached() -> list[dict]:
    path = cache_path()
    if not path.is_file():
        return []
    return parse_registry_csv(path.read_text(encoding="utf-8"))


def save_cache(rows: list[dict]) -> Path:
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=("name", "domain", "website",
                                                "contact_email", "jurisdiction"))
        writer.writeheader()
        writer.writerows(rows)
    return path


def to_evidence(rows: Iterable[dict], *, curated: set[str] | None = None,
                include_all: bool = False) -> list[Evidence]:
    """Turn registry rows into evidence -- selectively.

    Registration proves a company trades in personal data. It does not prove it
    holds *your* address, and emitting 600 line items that each claim it would be
    exactly the overclaiming this rebuild exists to remove. So by default the
    source emits:

    * one item per curated broker -- the people-search sites that index
      individuals by name and email, and that have a direct opt-out worth doing;
    * one aggregate item for the rest, because the useful action there is a single
      DROP request rather than 600 separate ones.

    `include_all` restores the per-broker firehose for anyone who wants it.
    """
    now = datetime.now(timezone.utc)
    curated = curated or set()
    out: list[Evidence] = []
    remainder = 0

    for row in rows:
        domain = row.get("domain")
        if not domain:
            continue
        if include_all or domain in curated:
            out.append(Evidence(
                source="broker_registry",
                domain=domain,
                status=Status.REGISTERED,
                confidence=Confidence.MEDIUM,
                detail=(f"registered data broker ({row['jurisdiction']} statutory "
                        f"registry) -- trades in personal data, and you never signed up"),
                payload=row,
                observed_at=now,
            ))
        else:
            remainder += 1

    if remainder and not include_all:
        out.append(Evidence(
            source="broker_registry",
            domain="privacy.ca.gov",
            status=Status.REGISTERED,
            confidence=Confidence.MEDIUM,
            detail=(f"{remainder} further companies are on the California statutory "
                    f"data-broker registry. Registration is compulsory, so this list is "
                    f"complete rather than a guess -- but it does not prove any single "
                    f"one holds your address. One DROP request covers all of them."),
            payload={"broker_count": remainder, "jurisdiction": "CA",
                     "name": "California data-broker registry (aggregate)"},
            observed_at=now,
        ))
    return out


def curated_domains() -> set[str]:
    """Brokers we have a hand-verified direct opt-out for."""
    from offlist.worklist.merge import load_services
    from offlist.worklist.remediation import load_table

    services = load_services()
    table = load_table()
    domains: set[str] = set()
    for key, entry in table.items():
        if entry.get("kind") not in ("opt_out_form", "email_request"):
            continue
        for domain in services.get(key, {}).get("domains", []):
            domains.add(domain.lower())
    return domains


class BrokerRegistrySource:
    id = "broker_registry"
    requires_network = False   # served from the cached snapshot
    requires_consent = False

    async def collect(self, email: EmailAddress,
                      ctx: RunContext) -> AsyncIterator[Evidence]:
        include_all = bool(ctx.extras.get("include_all_brokers"))
        for ev in to_evidence(load_cached(), curated=curated_domains(),
                              include_all=include_all):
            yield ev
