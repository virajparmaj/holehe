"""Escape hatch for the handful of sites that cannot be expressed declaratively.

A plugin still gets a catalogue entry -- it carries the domain, canary, enabled
flag and remediation link -- so disabling, ledger tracking and reporting work the
same for a plugin as for a declarative row. Only the request logic is code.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Protocol

import httpx

from offlist.core.email import EmailAddress
from offlist.core.models import ProbeResult


class SiteProbe(Protocol):
    def __call__(self, email: EmailAddress, client: httpx.AsyncClient,
                 entry: "object") -> Awaitable[ProbeResult]: ...


PLUGINS: dict[str, SiteProbe] = {}


def register(site_id: str) -> Callable[[SiteProbe], SiteProbe]:
    def wrap(fn: SiteProbe) -> SiteProbe:
        if site_id in PLUGINS:
            raise RuntimeError(f"plugin {site_id!r} registered twice")
        PLUGINS[site_id] = fn
        return fn
    return wrap


def get_plugin(site_id: str) -> SiteProbe | None:
    if not PLUGINS:
        _load_all()
    return PLUGINS.get(site_id)


def _load_all() -> None:
    import importlib
    import pkgutil

    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")
