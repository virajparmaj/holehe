"""Typed model for a site definition, plus validation with useful error messages.

Validation is hand-rolled rather than pulled from pydantic so the catalogue has
no runtime dependency beyond PyYAML; the schema is small and the error messages
matter more than the generality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from offlist.core.models import Discriminating, Status

# Outcomes a rule is allowed to declare. `from_status` defers to status_map so a
# definition never has to enumerate HTTP codes itself.
RULE_OUTCOMES = {
    "registered",
    "not_registered",
    "rate_limited",
    "blocked",
    "endpoint_gone",
    "parse_failed",
    "from_status",
}

OUTCOME_TO_STATUS = {
    "registered": Status.REGISTERED,
    "not_registered": Status.NOT_REGISTERED,
    "rate_limited": Status.RATE_LIMITED,
    "blocked": Status.BLOCKED,
    "endpoint_gone": Status.ENDPOINT_GONE,
    "parse_failed": Status.PARSE_FAILED,
}

EXTRACT_FROM = {"body", "header", "cookie", "json", "status"}
EXTRACT_VIA = {"between", "regex", "css", "json_path", "script_json", "form_replay"}
BODY_KINDS = {"form", "json", "raw", "replay_form"}
METHODS = {"register", "login", "password_recovery", "public_lookup", "other"}
SIDE_EFFECTS = {"none", "sends_email", "failed_login", "creates_account"}


class CatalogueError(ValueError):
    """Raised with a path-qualified message so a bad row is easy to find."""


@dataclass(frozen=True)
class Extractor:
    name: str
    source: str = "body"          # EXTRACT_FROM
    via: str = "between"          # EXTRACT_VIA
    start: str | None = None
    end: str | None = None
    occurrence: int = 1
    pattern: str | None = None
    group: int = 1
    selector: str | None = None
    attr: str | None = None
    index: int = 0
    path: str | None = None
    header: str | None = None
    cookie: str | None = None
    on_missing: str = "parse_failed"


@dataclass(frozen=True)
class Rule:
    when: Mapping[str, Any] | None
    then: str
    is_else: bool = False


@dataclass(frozen=True)
class Step:
    id: str
    method: str = "GET"
    url: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    timeout: float | None = None
    body_kind: str | None = None
    body_value: Any = None
    guards: Sequence[Rule] = ()
    capture: Sequence[Extractor] = ()


@dataclass(frozen=True)
class Canary:
    positive: str | None = None
    negative_mode: str = "random"
    tier: str = "c"
    provenance: str = ""
    discriminating: Discriminating = Discriminating.UNVERIFIED


@dataclass(frozen=True)
class Disabled:
    status: str = ""
    http_code: int | None = None
    measured: str = ""
    note: str = ""


@dataclass(frozen=True)
class Entry:
    id: str
    domain: str
    category: str = ""
    method: str = "register"
    side_effect: str = "none"
    frequent_rate_limit: bool = False
    enabled: bool = True
    disabled: Disabled | None = None
    plugin: str | None = None
    timeout: float | None = None
    steps: Sequence[Step] = ()
    rules: Sequence[Rule] = ()
    harvest: Mapping[str, Any] = field(default_factory=dict)
    canary: Canary = field(default_factory=Canary)
    remediation_ref: str | None = None

    @property
    def negative_is_explicit(self) -> bool:
        """True if a non-`else` rule claims not_registered.

        A site whose negative comes from an explicit matched marker is far better
        evidence than one whose negative is just the fallthrough, so a passing
        negative-only canary means more. Cheap to compute, worth reporting.
        """
        return any(r.then == "not_registered" and not r.is_else for r in self.rules)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _require(cond: bool, where: str, msg: str) -> None:
    if not cond:
        raise CatalogueError(f"{where}: {msg}")


def parse_extractor(name: str, raw: Mapping[str, Any], where: str) -> Extractor:
    where = f"{where}.capture.{name}"
    _require(isinstance(raw, Mapping), where, "must be a mapping")
    src = raw.get("from", "body")
    via = raw.get("via", "between")
    _require(src in EXTRACT_FROM, where, f"unknown `from: {src}` (expected one of {sorted(EXTRACT_FROM)})")
    _require(via in EXTRACT_VIA, where, f"unknown `via: {via}` (expected one of {sorted(EXTRACT_VIA)})")

    # `via` describes how to dig through a response body. Header, cookie and
    # status sources read a single named value, so the body-oriented requirements
    # do not apply to them.
    body_like = src in ("body", "json")
    if body_like:
        if via == "between":
            _require(raw.get("start") is not None, where, "`via: between` needs `start`")
            _require(raw.get("end") is not None, where, "`via: between` needs `end`")
        if via == "regex":
            _require(raw.get("pattern") is not None, where, "`via: regex` needs `pattern`")
        if via in ("css", "form_replay"):
            _require(raw.get("selector") is not None, where,
                     f"`via: {via}` needs `selector`")
        if via == "json_path":
            _require(raw.get("path") is not None, where, "`via: json_path` needs `path`")
    if src == "header":
        _require(raw.get("header") is not None, where, "`from: header` needs `header`")
    if src == "cookie":
        _require(raw.get("cookie") is not None, where, "`from: cookie` needs `cookie`")

    on_missing = raw.get("on_missing", "parse_failed")
    _require(on_missing in RULE_OUTCOMES | {"continue"}, where,
             f"unknown `on_missing: {on_missing}`")

    return Extractor(
        name=name, source=src, via=via,
        start=raw.get("start"), end=raw.get("end"),
        occurrence=int(raw.get("occurrence", 1)),
        pattern=raw.get("pattern"), group=int(raw.get("group", 1)),
        selector=raw.get("selector"), attr=raw.get("attr"),
        index=int(raw.get("index", 0)),
        path=raw.get("path"), header=raw.get("header"), cookie=raw.get("cookie"),
        on_missing=on_missing,
    )


def parse_rule(raw: Mapping[str, Any], where: str) -> Rule:
    _require(isinstance(raw, Mapping), where, "rule must be a mapping")
    if "else" in raw:
        outcome = raw["else"]
        _require(outcome in RULE_OUTCOMES, where, f"unknown outcome `{outcome}`")
        return Rule(when=None, then=outcome, is_else=True)
    _require("when" in raw and "then" in raw, where, "rule needs both `when` and `then` (or `else`)")
    outcome = raw["then"]
    _require(outcome in RULE_OUTCOMES, where, f"unknown outcome `{outcome}`")
    return Rule(when=raw["when"], then=outcome)


def parse_step(raw: Mapping[str, Any], idx: int, where: str) -> Step:
    where = f"{where}.steps[{idx}]"
    _require(isinstance(raw, Mapping), where, "step must be a mapping")
    _require(bool(raw.get("url")), where, "step needs a `url`")

    body_kind, body_value = None, None
    body = raw.get("body")
    if body is not None:
        _require(isinstance(body, Mapping), f"{where}.body", "must be a mapping")
        present = [k for k in BODY_KINDS if k in body]
        _require(len(present) == 1, f"{where}.body",
                 f"needs exactly one of {sorted(BODY_KINDS)}, found {present}")
        body_kind = present[0]
        body_value = body[body_kind]

    return Step(
        id=str(raw.get("id", f"step{idx}")),
        method=str(raw.get("method", "GET")).upper(),
        url=raw["url"],
        params=raw.get("params") or {},
        headers=raw.get("headers") or {},
        cookies=raw.get("cookies") or {},
        follow_redirects=bool(raw.get("follow_redirects", True)),
        timeout=raw.get("timeout"),
        body_kind=body_kind,
        body_value=body_value,
        guards=tuple(parse_rule(g, f"{where}.guards[{i}]")
                     for i, g in enumerate(raw.get("guards") or [])),
        capture=tuple(parse_extractor(n, c, where)
                      for n, c in (raw.get("capture") or {}).items()),
    )


def parse_entry(raw: Mapping[str, Any], where: str) -> Entry:
    _require(isinstance(raw, Mapping), where, "entry must be a mapping")
    _require(bool(raw.get("id")), where, "entry needs an `id`")
    where = f"{where}[{raw['id']}]"
    _require(bool(raw.get("domain")), where, "entry needs a `domain`")

    method = raw.get("method", "register")
    _require(method in METHODS, where, f"unknown `method: {method}`")
    side_effect = raw.get("side_effect", "none")
    _require(side_effect in SIDE_EFFECTS, where, f"unknown `side_effect: {side_effect}`")

    steps = tuple(parse_step(s, i, where) for i, s in enumerate(raw.get("steps") or []))
    rules = tuple(parse_rule(r, f"{where}.rules[{i}]") for i, r in enumerate(raw.get("rules") or []))
    plugin = raw.get("plugin")
    _require(bool(steps) or bool(plugin), where, "entry needs either `steps` or `plugin`")

    else_rules = [r for r in rules if r.is_else]
    _require(len(else_rules) <= 1, where, "at most one `else` rule")
    if else_rules:
        _require(rules[-1].is_else, where, "`else` must be the last rule")

    dis = raw.get("disabled")
    disabled = None
    if dis:
        disabled = Disabled(status=dis.get("status", ""), http_code=dis.get("http_code"),
                            measured=str(dis.get("measured", "")), note=dis.get("note", ""))

    can = raw.get("canary") or {}
    # YAML 1.1 reads bare `yes`/`no` as booleans, so a hand-written
    # `discriminating: yes` arrives here as True. Accept both spellings.
    _disc = can.get("discriminating", "unverified")
    if isinstance(_disc, bool):
        _disc = "yes" if _disc else "no"
    canary = Canary(
        positive=can.get("positive"),
        negative_mode=can.get("negative", {}).get("mode", "random")
        if isinstance(can.get("negative"), Mapping) else "random",
        tier=str(can.get("tier", "c")).lower(),
        provenance=can.get("provenance", ""),
        discriminating=Discriminating(str(_disc)),
    )

    return Entry(
        id=raw["id"],
        domain=raw["domain"],
        category=raw.get("category", ""),
        method=method,
        side_effect=side_effect,
        frequent_rate_limit=bool(raw.get("frequent_rate_limit", False)),
        enabled=bool(raw.get("enabled", True)),
        disabled=disabled,
        plugin=plugin,
        timeout=raw.get("timeout"),
        steps=steps,
        rules=rules,
        harvest=raw.get("harvest") or {},
        canary=canary,
        remediation_ref=raw.get("remediation_ref"),
    )
