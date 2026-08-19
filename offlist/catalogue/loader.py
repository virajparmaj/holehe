"""Load site definitions, expand engine templates, overlay the measured ledger.

Engines are the reason this is worth doing at all: 25 of the original modules
were byte-identical MyBB clones differing only in a base URL, roughly 2,000
lines of Python that become one engine and 25 one-line rows.
"""

from __future__ import annotations

import re
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from offlist.catalogue.schema import CatalogueError, Entry, parse_entry
from offlist.core.models import Discriminating

# Only substitutes names that the engine actually declares, so runtime
# placeholders such as {email} and {captured.token} survive untouched.
_VAR_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}", re.I)


def substitute_vars(obj: Any, variables: Mapping[str, Any]) -> Any:
    """Recursively expand `{name}` for names present in `variables`."""
    if isinstance(obj, str):
        def _swap(m: re.Match) -> str:
            key = m.group(1)
            return str(variables[key]) if key in variables else m.group(0)
        return _VAR_RE.sub(_swap, obj)
    if isinstance(obj, Mapping):
        return {k: substitute_vars(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_vars(v, variables) for v in obj]
    return obj


def _deep_merge(base: Mapping[str, Any], over: Mapping[str, Any]) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def expand_engine(row: Mapping[str, Any], engines: Mapping[str, Mapping[str, Any]]) -> dict:
    """Turn `{engine: mybb, vars: {...}}` into a full standalone entry."""
    name = row.get("engine")
    if not name:
        return dict(row)
    if name not in engines:
        raise CatalogueError(f"[{row.get('id')}]: unknown engine {name!r} "
                             f"(known: {sorted(engines)})")

    engine = engines[name]
    variables = _deep_merge(engine.get("defaults") or {}, row.get("vars") or {})

    expanded = {
        "category": engine.get("defaults", {}).get("category", ""),
        "method": engine.get("defaults", {}).get("method", "register"),
        "steps": substitute_vars(engine.get("steps") or [], variables),
        "rules": substitute_vars(engine.get("rules") or [], variables),
    }
    # The row wins over anything the engine supplied.
    merged = _deep_merge(expanded, {k: v for k, v in row.items()
                                    if k not in ("engine", "vars")})
    return merged


def _read_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def catalogue_root() -> Path:
    """Locate the packaged catalogue.

    Uses importlib.resources rather than __file__ so the catalogue is still found
    when the package is installed as a wheel or zipapp.
    """
    return Path(str(files("offlist") / "catalogue"))


def load_engines(root: Path | None = None) -> dict[str, dict]:
    root = root or catalogue_root()
    engines: dict[str, dict] = {}
    d = root / "engines"
    if not d.is_dir():
        return engines
    for path in sorted(d.glob("*.yaml")):
        data = _read_yaml(path)
        if not isinstance(data, Mapping) or "id" not in data:
            raise CatalogueError(f"{path.name}: an engine file needs a top-level `id`")
        if data["id"] in engines:
            raise CatalogueError(f"{path.name}: duplicate engine id {data['id']!r}")
        engines[data["id"]] = data
    return engines


def load_ledger(root: Path | None = None) -> dict[str, dict]:
    """Measured per-site state, written by the canary run rather than by hand."""
    root = root or catalogue_root()
    path = root / "ledger.yaml"
    if not path.is_file():
        return {}
    data = _read_yaml(path)
    return (data or {}).get("sites", {}) if isinstance(data, Mapping) else {}


def apply_ledger(entry: Entry, ledger: Mapping[str, Any]) -> Entry:
    """Overlay measured discrimination onto a hand-written entry."""
    record = ledger.get(entry.id)
    if not record:
        return entry
    value = record.get("discriminating")
    if value is None:
        return entry
    canary = replace(entry.canary, discriminating=Discriminating(str(value)))
    return replace(entry, canary=canary)


def load_catalogue(root: Path | None = None, *, include_disabled: bool = False) -> list[Entry]:
    """Load, expand and validate every site definition.

    Raises CatalogueError with a path-qualified message on the first problem so a
    malformed row is easy to locate.
    """
    root = root or catalogue_root()
    engines = load_engines(root)
    ledger = load_ledger(root)

    entries: list[Entry] = []
    seen: dict[str, str] = {}

    sites_dir = root / "sites"
    if not sites_dir.is_dir():
        return entries

    for path in sorted(sites_dir.glob("*.yaml")):
        rows = _read_yaml(path)
        if not isinstance(rows, list):
            raise CatalogueError(f"{path.name}: expected a list of site entries")
        for row in rows:
            merged = expand_engine(row, engines)
            merged.setdefault("category", path.stem)
            entry = parse_entry(merged, path.name)
            if entry.id in seen:
                raise CatalogueError(
                    f"{path.name}: duplicate site id {entry.id!r} "
                    f"(already defined in {seen[entry.id]})")
            seen[entry.id] = path.name
            entries.append(apply_ledger(entry, ledger))

    if not include_disabled:
        entries = [e for e in entries if e.enabled]
    return entries


def selectable(entries: Iterable[Entry], *, allow_login_probe: bool = False,
               allow_email_sending: bool = False,
               no_password_recovery: bool = False) -> list[Entry]:
    """Filter by consent gates.

    Login probes submit a deliberately wrong password, which increments failed
    login counters and can lock you out of your own account. Recovery probes send
    a real email to the address. Both are off unless explicitly enabled.
    """
    out = []
    for e in entries:
        if e.side_effect == "creates_account":
            continue
        if e.side_effect == "failed_login" and not allow_login_probe:
            continue
        if e.side_effect == "sends_email" and not allow_email_sending:
            continue
        if no_password_recovery and e.method == "password_recovery":
            continue
        out.append(e)
    return out
