"""Pull a token out of a response.

Every extractor returns `None` on failure rather than raising, so the caller can
apply the definition's `on_missing` policy. The default policy is `parse_failed`,
not `rate_limited` -- the single most consequential difference from the original
code, where a failed `.split()[1]` was indistinguishable from being throttled.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from offlist.catalogue.schema import Extractor


def json_path(data: Any, path: str) -> Any:
    """Resolve a dotted path with optional [i] indices, e.g. `errors.email[0].code`.

    Returns the sentinel `MISSING` when any segment is absent, so a legitimately
    null value stays distinguishable from an absent one.
    """
    cur = data
    for raw in path.lstrip("$").lstrip(".").split("."):
        if not raw:
            continue
        name, *idxs = re.split(r"\[(\d+)\]", raw)
        if name:
            if not isinstance(cur, dict) or name not in cur:
                return MISSING
            cur = cur[name]
        for idx in [i for i in idxs if i.isdigit()]:
            if not isinstance(cur, (list, tuple)) or int(idx) >= len(cur):
                return MISSING
            cur = cur[int(idx)]
    return cur


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


def _between(text: str, start: str, end: str, occurrence: int) -> str | None:
    pos = -1
    for _ in range(max(1, occurrence)):
        pos = text.find(start, pos + 1)
        if pos == -1:
            return None
    tail = text[pos + len(start):]
    stop = tail.find(end)
    return tail[:stop] if stop != -1 else None


def _css(text: str, selector: str, attr: str | None, index: int) -> str | None:
    from bs4 import BeautifulSoup

    nodes = BeautifulSoup(text, "html.parser").select(selector)
    if index >= len(nodes):
        return None
    node = nodes[index]
    if not attr:
        return node.get_text()
    value = node.get(attr)
    # BeautifulSoup hands back a list for multi-valued attributes like class;
    # interpolating that into a request would send "['a', 'b']".
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return value


def _script_json(text: str, path: str, selector: str | None) -> Any:
    """Find a <script> whose body parses as JSON and resolve a path inside it."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(text, "html.parser")
    for node in soup.select(selector or "script"):
        raw = node.string or (node.contents[0] if node.contents else None)
        if not raw:
            continue
        try:
            data = json.loads(str(raw).strip())
        except (ValueError, TypeError):
            continue
        found = json_path(data, path)
        if found is not MISSING:
            return found
    return None


def form_replay(text: str, selector: str) -> dict[str, str]:
    """Harvest every named input from a form so hidden fields survive the round trip."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(text, "html.parser")
    return {
        node["name"]: node.get("value", "")
        for node in soup.select(selector)
        if node.has_attr("name")
    }


def extract(spec: Extractor, response: httpx.Response) -> Any:
    """Apply one extractor. Returns None (or {} for form_replay) when it misses."""
    if spec.source == "status":
        return str(response.status_code)

    if spec.source == "header":
        return response.headers.get(spec.header or spec.name)

    if spec.source == "cookie":
        return response.cookies.get(spec.cookie or spec.name)

    if spec.source == "json":
        try:
            data = response.json()
        except (ValueError, UnicodeDecodeError):
            return None
        found = json_path(data, spec.path or "")
        return None if found is MISSING else found

    text = response.text

    if spec.via == "between":
        return _between(text, spec.start or "", spec.end or "", spec.occurrence)
    if spec.via == "regex":
        m = re.search(spec.pattern or "", text, re.S)
        if not m:
            return None
        try:
            return m.group(spec.group)
        except (IndexError, re.error):
            return None
    if spec.via == "css":
        return _css(text, spec.selector or "", spec.attr, spec.index)
    if spec.via == "script_json":
        return _script_json(text, spec.path or "", spec.selector)
    if spec.via == "form_replay":
        return form_replay(text, spec.selector or "form input") or None

    return None
