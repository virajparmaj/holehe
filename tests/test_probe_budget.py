"""The per-site budget: what actually bounds how long a scan takes.

Measured on the live catalogue, a scan's wall clock is set by its single slowest
site and by nothing else. 142 sites with a median of 224ms took 11.75s, because
one site took 10.14s -- and that site answered `indeterminate`. `-T/--timeout` is
httpx's per-operation timeout, so it never bounded a site: a multi-step entry may
spend it once per step, and a response that keeps trickling never trips it at all.
"""

import asyncio
import time

import httpx
import pytest
import respx

from offlist.catalogue.schema import parse_entry
from offlist.core.email import EmailAddress
from offlist.core.models import Status
from offlist.core.status_map import status_for_exception
from offlist.sources.base import RunContext
from offlist.sources.probe import run_probes

EMAIL = EmailAddress("a@b.com")


def entry(site_id: str, host: str = "slow.test"):
    return parse_entry({
        "id": site_id, "domain": host,
        "steps": [{"id": "c", "url": f"https://{host}/api"}],
        "rules": [{"when": {"status": {"eq": 200}}, "then": "registered"}],
    }, "t.yaml")


def slow(seconds: float):
    async def responder(request):
        await asyncio.sleep(seconds)
        return httpx.Response(200, text="ok")
    return responder


def probe(entries, **ctx_kw):
    @respx.mock
    async def go():
        respx.get("https://slow.test/api").mock(side_effect=slow(ctx_kw.pop("delay", 5.0)))
        started = time.monotonic()
        results = await run_probes(EMAIL, RunContext(**ctx_kw), entries)
        return results, time.monotonic() - started
    return asyncio.run(go())


# ── the cut itself ─────────────────────────────────────────────────────────

def test_a_slow_site_is_cut_at_the_budget():
    results, wall = probe([entry("dawdler")], site_budget=0.2, timeout=30.0)
    assert results[0].status is Status.TIMED_OUT
    assert wall < 2.0, f"budget of 0.2s did not bound the run (took {wall:.2f}s)"


def test_the_cut_names_the_budget_rather_than_blaming_the_host():
    """UNREACHABLE says "the host may be dead". A host we hung up on has not
    earned that, and PARSE_FAILED would blame a definition that is fine."""
    results, _ = probe([entry("dawdler")], site_budget=0.2, timeout=30.0)
    assert results[0].status is not Status.UNREACHABLE
    assert results[0].status is not Status.PARSE_FAILED
    assert "0.2s per-site budget" in results[0].detail


def test_a_cut_site_records_how_long_it_was_given():
    results, _ = probe([entry("dawdler")], site_budget=0.2, timeout=30.0)
    assert results[0].elapsed_ms is not None
    assert 150 <= results[0].elapsed_ms < 2000


def test_a_timeout_is_never_reported_as_an_answer():
    results, _ = probe([entry("dawdler")], site_budget=0.2, timeout=30.0)
    assert not results[0].status.is_answer


# ── wall clock is the point ────────────────────────────────────────────────

def test_wall_clock_is_the_budget_not_the_number_of_slow_sites():
    """Eight sites that would each take 5s finish inside one budget, because
    they are cut concurrently. Without a budget this run is 5s at best."""
    results, wall = probe([entry(f"s{i}") for i in range(8)],
                          site_budget=0.3, timeout=30.0, concurrency=16)
    assert all(r.status is Status.TIMED_OUT for r in results)
    assert wall < 2.5, f"eight cuts took {wall:.2f}s; they should overlap"


def test_timeout_flag_alone_does_not_bound_a_site():
    """-T is httpx's per-operation timeout. Here it is generous and the budget
    is what stops the run -- which is exactly the confusion the flag caused."""
    _, wall = probe([entry("dawdler")], site_budget=0.2, timeout=30.0)
    assert wall < 2.0


# ── what the budget must not charge for ────────────────────────────────────

def test_queueing_behind_the_same_host_is_not_charged_to_the_site():
    """HostLimiter serialises requests to one host two at a time. The third
    entry waits for a slot; spending that wait out of its own budget would cut
    a fast site for being unlucky in the queue."""
    results, _ = probe([entry("q1"), entry("q2"), entry("q3")],
                       delay=0.3, site_budget=0.8, timeout=30.0)
    assert [r.status for r in results] == [Status.REGISTERED] * 3


def test_budget_of_none_waits_as_long_as_it_takes():
    results, _ = probe([entry("patient")], delay=0.3, site_budget=None, timeout=30.0)
    assert results[0].status is Status.REGISTERED


def test_a_fast_site_is_untouched_by_the_budget():
    results, _ = probe([entry("brisk")], delay=0.0, site_budget=0.5, timeout=30.0)
    assert results[0].status is Status.REGISTERED


# ── the taxonomy stays honest ──────────────────────────────────────────────

@pytest.mark.parametrize("exc, expected", [
    (httpx.ReadTimeout("slow"), Status.TIMED_OUT),
    (httpx.WriteTimeout("slow"), Status.TIMED_OUT),
    (httpx.PoolTimeout("slow"), Status.TIMED_OUT),
    (asyncio.TimeoutError(), Status.TIMED_OUT),
    # Nothing ever answered, so "the host may be dead" is the accurate reading.
    (httpx.ConnectTimeout("no route"), Status.UNREACHABLE),
    (httpx.ConnectError("no route"), Status.UNREACHABLE),
])
def test_slowness_and_deadness_are_different_statuses(exc, expected):
    assert status_for_exception(exc)[0] is expected


def test_a_timeout_is_a_failure_but_not_one_of_ours():
    """`doctor` reports how many failures are this repo's fault. Filing timeouts
    under parse_failed would inflate that number with other people's latency."""
    assert Status.TIMED_OUT.is_failure
    assert not Status.TIMED_OUT.is_actionable_by_us
