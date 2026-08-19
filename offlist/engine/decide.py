"""Evaluate an ordered rule list against a response.

Two deliberate choices, both aimed at the failure mode measured in the audit:

* Rules are ordered and the first match wins, so a definition reads top-down.
* There is no implicit `not_registered`. A definition that falls off the end of
  its rules reports `parse_failed`, because reaching the end means the site said
  something the definition has never seen. Claiming "no account here" requires an
  explicit `else`, which forces the author to have actually observed a negative.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

import httpx

from offlist.catalogue.schema import OUTCOME_TO_STATUS
from offlist.core.models import Status
from offlist.core.status_map import status_for_response
from offlist.engine.extract import MISSING, json_path


def _json_of(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, UnicodeDecodeError):
        return MISSING


def _as_text(value: Any) -> str:
    """Render a value for the string operators.

    JSON fields are not always strings, and a rule like
    `{path: code, contains: taken}` against `{"code": 5}` used to raise
    TypeError straight out of the executor. Comparing the rendered value is what
    an author expects, and it cannot crash.
    """
    if value is None or value is MISSING:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return str(value)


def _cmp_scalar(actual: Any, spec: Mapping[str, Any]) -> bool:
    for op, expected in spec.items():
        if op in ("eq", "equals"):
            if actual != expected:
                return False
        elif op in ("ne", "not_equals"):
            if actual == expected:
                return False
        elif op == "in":
            if actual not in expected:
                return False
        elif op == "gte":
            if not (isinstance(actual, (int, float)) and actual >= expected):
                return False
        elif op == "lte":
            if not (isinstance(actual, (int, float)) and actual <= expected):
                return False
        elif op == "contains":
            if str(expected) not in _as_text(actual):
                return False
        elif op == "not_contains":
            if str(expected) in _as_text(actual):
                return False
        elif op == "startswith":
            if not _as_text(actual).startswith(str(expected)):
                return False
        elif op == "matches":
            if not re.search(expected, _as_text(actual), re.S):
                return False
        elif op == "truthy":
            if bool(actual) is not bool(expected):
                return False
        elif op == "exists":
            if (actual is not MISSING and actual is not None) is not bool(expected):
                return False
        elif op in ("key_exists", "path"):
            continue  # handled by the caller
        else:
            raise ValueError(f"unknown comparison operator {op!r}")
    return True


def _check_clause(key: str, spec: Any, response: httpx.Response) -> bool:
    if key == "all":
        return all(evaluate_when(s, response) for s in spec)
    if key == "any":
        return any(evaluate_when(s, response) for s in spec)

    if key == "status":
        return _cmp_scalar(response.status_code, spec)

    if key == "body":
        return _cmp_scalar(response.text, spec)

    if key == "header":
        value = response.headers.get(spec.get("name", ""), "")
        return _cmp_scalar(value, {k: v for k, v in spec.items() if k != "name"})

    if key == "cookie":
        value = response.cookies.get(spec.get("name", ""))
        return _cmp_scalar(value, {k: v for k, v in spec.items() if k != "name"})

    if key == "json":
        data = _json_of(response)
        if data is MISSING:
            return False
        found = json_path(data, spec.get("path", ""))
        if "key_exists" in spec:
            return isinstance(found, Mapping) and spec["key_exists"] in found
        if found is MISSING:
            return "exists" in spec and not spec["exists"]
        return _cmp_scalar(found, {k: v for k, v in spec.items() if k != "path"})

    if key == "json_str":
        # For payloads whose shape varies but whose text is diagnostic, e.g. a
        # marker that may sit at any depth inside an errors object.
        data = _json_of(response)
        if data is MISSING:
            return False
        found = json_path(data, spec.get("path", ""))
        if found is MISSING:
            return False
        return _cmp_scalar(str(found), {k: v for k, v in spec.items() if k != "path"})

    raise ValueError(f"unknown rule clause {key!r}")


def evaluate_when(when: Mapping[str, Any], response: httpx.Response) -> bool:
    """A mapping of clauses is an AND; use `all:`/`any:` for explicit nesting."""
    return all(_check_clause(k, v, response) for k, v in when.items())


def decide(rules, response: httpx.Response) -> tuple[Status, str]:
    """Return the first matching outcome, or PARSE_FAILED if nothing matched."""
    for rule in rules:
        matched = rule.is_else or evaluate_when(rule.when or {}, response)
        if not matched:
            continue
        if rule.then == "from_status":
            return status_for_response(response.status_code, response.text)
        detail = "matched `else`" if rule.is_else else f"matched rule -> {rule.then}"
        return OUTCOME_TO_STATUS[rule.then], detail

    # Nothing matched. Let status_map decide whether that is a block, a dead
    # endpoint, or a genuinely stale definition.
    return status_for_response(response.status_code, response.text)


def first_match(rules, response: httpx.Response) -> tuple[Status, str] | None:
    """Like decide(), but returns None when no rule matched. Used for step guards."""
    for rule in rules:
        matched = rule.is_else or evaluate_when(rule.when or {}, response)
        if not matched:
            continue
        if rule.then == "from_status":
            return status_for_response(response.status_code, response.text)
        return OUTCOME_TO_STATUS[rule.then], f"guard -> {rule.then}"
    return None
