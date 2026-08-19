"""Collapse evidence from every source into one record per service."""

from __future__ import annotations

from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from typing import Iterable, Mapping

import yaml

from offlist.core.models import Evidence, ServiceRecord


def registrable(domain: str) -> str:
    """Reduce a host to its registrable domain so subdomains collapse."""
    if not domain:
        return ""
    host = domain.strip().lower().removeprefix("www.")
    try:
        import tldextract

        parts = tldextract.extract(host)
        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}"
    except Exception:
        pass
    return host


def load_services(path: Path | None = None) -> Mapping[str, dict]:
    """Alias table: many domains, one service you actually delete an account at."""
    path = path or Path(str(files("offlist") / "data" / "services.yaml"))
    if not Path(path).is_file():
        return {}
    return (yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}).get("services", {})


def _alias_index(services: Mapping[str, dict]) -> dict[str, str]:
    index: dict[str, str] = {}
    for key, meta in services.items():
        for domain in meta.get("domains", []):
            index[registrable(domain)] = key
    return index


def _dedupe(items: Iterable[Evidence]) -> list[Evidence]:
    """Drop evidence that says the same thing twice.

    A service with several aliases (acxiom.com and liveramp.com) otherwise picks
    up one identical registry row per alias.
    """
    seen: set[tuple] = set()
    out = []
    for e in items:
        key = (e.source, e.detail, e.observed_at.date().isoformat())
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def merge(evidence: Iterable[Evidence], *, vault_domains: set[str] | None = None,
          services: Mapping[str, dict] | None = None) -> list[ServiceRecord]:
    """Group evidence by canonical service.

    Evidence is appended, never replaced, and conflicting evidence is kept side
    by side rather than resolved: "the probe says no account, the vault says you
    have a password there" is itself a finding, and it is how a mis-mapped site
    like Flickr gets caught.
    """
    services = services if services is not None else load_services()
    alias = _alias_index(services)
    vault_domains = {registrable(d) for d in (vault_domains or set())}

    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for ev in evidence:
        base = registrable(ev.domain)
        grouped[alias.get(base, base)].append(ev)

    records = []
    for key, items in grouped.items():
        meta = services.get(key, {})
        # Show the domains as observed. `registrable` is only for grouping --
        # collapsing privacy.ca.gov to ca.gov in the report would be misleading.
        domains = sorted({e.domain for e in items})
        deduped = _dedupe(items)
        records.append(ServiceRecord(
            service=key,
            display_name=meta.get("display_name") or key,
            domains=domains,
            category=meta.get("category") or next((e.payload.get("category", "")
                                                   for e in items if e.payload), ""),
            evidence=sorted(deduped, key=lambda e: e.observed_at),
            in_vault=bool(vault_domains & set(domains)) or key in vault_domains,
        ))
    return sorted(records, key=lambda r: r.service)
