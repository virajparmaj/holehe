"""Run one catalogue entry against one address."""

from __future__ import annotations

import time
from typing import Any, Mapping

import httpx

from offlist.catalogue.schema import (
    OUTCOME_TO_STATUS,
    Entry,
    Extractor,
    Step,
)
from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, ProbeResult, Status
from offlist.core.status_map import status_for_exception
from offlist.engine.decide import decide, first_match
from offlist.engine.extract import extract, json_path, MISSING
from offlist.engine.template import TemplateError, render


def _result(entry: Entry, status: Status, detail: str = "", *,
            http_code: int | None = None, started: float | None = None,
            **extra: Any) -> ProbeResult:
    return ProbeResult(
        site_id=entry.id,
        domain=entry.domain,
        status=status,
        category=entry.category,
        method=entry.method,
        http_code=http_code,
        detail=detail,
        discriminating=entry.canary.discriminating,
        confidence=Confidence.HIGH if status.is_answer else Confidence.MEDIUM,
        elapsed_ms=int((time.monotonic() - started) * 1000) if started else None,
        **extra,
    )


def _apply_on_missing(entry: Entry, spec: Extractor, started: float,
                      response: httpx.Response) -> ProbeResult | None:
    """Turn a failed capture into the outcome the definition asked for."""
    if spec.on_missing == "continue":
        return None
    if spec.on_missing == "from_status":
        from offlist.core.status_map import status_for_response
        status, detail = status_for_response(response.status_code, response.text)
        return _result(entry, status, detail, http_code=response.status_code, started=started)
    return _result(
        entry,
        OUTCOME_TO_STATUS[spec.on_missing],
        f"could not capture {spec.name!r} from {spec.source} via {spec.via}",
        http_code=response.status_code,
        started=started,
    )


def _build_request(step: Step, email: EmailAddress, captured: Mapping[str, str],
                   default_timeout: float | None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "method": step.method,
        "url": render(step.url, email, captured),
        "follow_redirects": step.follow_redirects,
    }
    if step.params:
        kwargs["params"] = render(dict(step.params), email, captured)
    if step.headers:
        kwargs["headers"] = render(dict(step.headers), email, captured)
    if step.cookies:
        kwargs["cookies"] = render(dict(step.cookies), email, captured)

    timeout = step.timeout if step.timeout is not None else default_timeout
    if timeout is not None:
        kwargs["timeout"] = timeout

    if step.body_kind == "form":
        kwargs["data"] = render(dict(step.body_value or {}), email, captured)
    elif step.body_kind == "json":
        kwargs["json"] = render(step.body_value, email, captured)
    elif step.body_kind == "raw":
        kwargs["content"] = render(step.body_value, email, captured)
    elif step.body_kind == "replay_form":
        harvested = dict(captured.get("__replay__") or {})
        overrides = render(dict((step.body_value or {}).get("overrides") or {}), email, captured)
        harvested.update(overrides)
        kwargs["data"] = harvested

    return kwargs


def _harvest(entry: Entry, response: httpx.Response) -> dict[str, Any]:
    """Pull optional extra fields (masked recovery address, phone, name) out."""
    out: dict[str, Any] = {}
    if not entry.harvest:
        return out
    try:
        data = response.json()
    except (ValueError, UnicodeDecodeError):
        return out
    mapping = {"emailrecovery": "emailrecovery", "phoneNumber": "phone_number",
               "phone_number": "phone_number", "full_name": "full_name",
               "created_at": "created_at"}
    for key, path in entry.harvest.items():
        field = mapping.get(key)
        if not field or not isinstance(path, str):
            continue
        found = json_path(data, path)
        if found is not MISSING and found not in (None, ""):
            out[field] = str(found)
    return out


async def run_entry(entry: Entry, email: EmailAddress, client: httpx.AsyncClient,
                    *, default_timeout: float | None = None) -> ProbeResult:
    """Execute an entry's steps and decide an outcome.

    Never raises: a transport error or a bad template becomes a classified result,
    so one broken definition can never take down a run.
    """
    started = time.monotonic()

    if not entry.enabled:
        note = entry.disabled.status if entry.disabled else ""
        return _result(entry, Status.DISABLED, note, started=started)

    if entry.plugin:
        from offlist.plugins import get_plugin

        probe = get_plugin(entry.plugin)
        if probe is None:
            return _result(entry, Status.PARSE_FAILED,
                           f"no plugin registered as {entry.plugin!r}", started=started)
        try:
            return await probe(email, client, entry)
        except Exception as exc:  # a plugin is arbitrary code; contain it
            status, detail = status_for_exception(exc)
            return _result(entry, status, detail, started=started)

    captured: dict[str, Any] = {}
    response: httpx.Response | None = None
    timeout = entry.timeout if entry.timeout is not None else default_timeout

    for step in entry.steps:
        try:
            kwargs = _build_request(step, email, captured, timeout)
        except TemplateError as exc:
            return _result(entry, Status.PARSE_FAILED, str(exc), started=started)

        try:
            response = await client.request(**kwargs)
        except Exception as exc:
            status, detail = status_for_exception(exc)
            return _result(entry, status, f"{step.id}: {detail}", started=started)

        guard = first_match(step.guards, response)
        if guard is not None:
            status, detail = guard
            return _result(entry, status, f"{step.id}: {detail}",
                           http_code=response.status_code, started=started)

        for spec in step.capture:
            value = extract(spec, response)
            # "" is a legitimate captured value (MyBB serves an empty post key to
            # guests); only a genuine miss returns None/MISSING.
            if value is None or value is MISSING or value == {}:
                missed = _apply_on_missing(entry, spec, started, response)
                if missed is not None:
                    return missed
                continue
            captured[spec.name] = value
            if spec.via == "form_replay":
                captured["__replay__"] = value

    if response is None:
        return _result(entry, Status.PARSE_FAILED, "entry declared no steps", started=started)

    try:
        status, detail = decide(entry.rules, response)
    except Exception as exc:
        # A malformed rule is a defect in the definition, not a fact about the
        # site -- and run_entry promises never to raise.
        return _result(entry, Status.PARSE_FAILED,
                       f"rule evaluation failed: {type(exc).__name__}: {exc}",
                       http_code=response.status_code, started=started)
    extras = _harvest(entry, response) if status is Status.REGISTERED else {}
    return _result(entry, status, detail, http_code=response.status_code,
                   started=started, **extras)
