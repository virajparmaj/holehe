"""Regressions for bugs found in the final review pass.

Each of these was live in the code and reachable from ordinary use.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx

from offlist.catalogue.schema import parse_entry, parse_extractor
from offlist.core.email import EmailAddress
from offlist.core.models import Status
from offlist.engine.decide import evaluate_when
from offlist.engine.executor import run_entry
from offlist.engine.extract import extract

NOW = datetime.now(timezone.utc)


def resp(body="", code=200):
    return httpx.Response(code, text=body,
                          request=httpx.Request("GET", "https://x.test/"))


# ── string operators against non-string JSON values ────────────────────────
# `"taken" not in 5` raised TypeError straight out of the rule evaluator, so a
# plausible-looking rule against a numeric field killed the probe.

@pytest.mark.parametrize("body,clause,expected", [
    ('{"code": 5}',   {"json": {"path": "code", "contains": "5"}}, True),
    ('{"code": 5}',   {"json": {"path": "code", "contains": "taken"}}, False),
    ('{"a": true}',   {"json": {"path": "a", "contains": "true"}}, True),
    ('{"a": false}',  {"json": {"path": "a", "contains": "true"}}, False),
    ('{"a": 1.5}',    {"json": {"path": "a", "startswith": "1."}}, True),
    ('{"a": [1,2]}',  {"json": {"path": "a", "contains": "1"}}, True),
    ('{"a": null}',   {"json": {"path": "a", "contains": "x"}}, False),
    ('{"a": 42}',     {"json": {"path": "a", "matches": r"\d+"}}, True),
    ('{"a": 5}',      {"json": {"path": "a", "not_contains": "9"}}, True),
])
def test_string_operators_survive_non_string_values(body, clause, expected):
    assert evaluate_when(clause, resp(body)) is expected


def test_booleans_render_as_json_spelling_not_python():
    """`True` would match "True" in Python but the wire format says "true"."""
    assert evaluate_when({"json": {"path": "a", "contains": "true"}}, resp('{"a": true}'))
    assert not evaluate_when({"json": {"path": "a", "contains": "True"}}, resp('{"a": true}'))


# ── run_entry's "never raises" contract ────────────────────────────────────

def test_run_entry_never_raises_on_a_malformed_rule():
    """Its docstring promises this; it used to be false, and a single bad
    definition took down any caller without a guard of its own."""
    entry = parse_entry({
        "id": "boom", "domain": "boom.test",
        "steps": [{"id": "c", "url": "https://boom.test/api"}],
        "rules": [{"when": {"json": {"path": "code", "matches": "[unclosed"}},
                   "then": "registered"}],
    }, "t.yaml")

    @respx.mock
    async def go():
        respx.get("https://boom.test/api").mock(
            return_value=httpx.Response(200, text='{"code": 5}'))
        async with httpx.AsyncClient() as client:
            return await run_entry(entry, EmailAddress("a@b.com"), client)

    result = asyncio.run(go())
    assert result.status is Status.PARSE_FAILED
    assert "rule evaluation failed" in result.detail


# ── multi-valued HTML attributes ───────────────────────────────────────────

def test_css_extractor_returns_a_string_for_multi_valued_attributes():
    """BeautifulSoup hands back a list for class; interpolating that into a
    request would have sent the literal text "['a', 'b']"."""
    spec = parse_extractor("t", {"via": "css", "selector": "div", "attr": "class"}, "t")
    got = extract(spec, resp('<div class="a b">x</div>'))
    assert isinstance(got, str)
    assert got == "a b"


def test_css_extractor_still_returns_single_valued_attributes_plainly():
    spec = parse_extractor("t", {"via": "css", "selector": "meta", "attr": "content"}, "t")
    assert extract(spec, resp('<meta content="tok">')) == "tok"


# ── the leaked client ──────────────────────────────────────────────────────

def test_probe_does_not_construct_a_client_just_to_read_headers():
    source = Path("offlist/sources/probe.py").read_text(encoding="utf-8")
    assert "build_client()" not in source, (
        "build_client() here creates an AsyncClient purely for its headers and "
        "never closes it")


def test_dead_helper_is_gone():
    source = Path("offlist/core/http.py").read_text(encoding="utf-8")
    assert "gather_bounded" not in source


# ── dormancy ───────────────────────────────────────────────────────────────

def test_dormant_fires_on_an_old_credential_scanned_today(tmp_path):
    """It never could: dormancy was measured from when *we looked*, which on a
    fresh import is always now."""
    from offlist.sources.vault_csv import collect_sync
    from offlist.worklist import merge, triage

    csv_path = tmp_path / "vault.csv"
    csv_path.write_text(
        "name,url,username,password,last used\n"
        "Old,https://old.test/,me@example.com,x,2019-01-04\n"
        "New,https://new.test/,me@example.com,x,2026-08-01\n",
        encoding="utf-8")

    evidence = collect_sync(EmailAddress("me@example.com"), [csv_path])
    records = {r.service: r for r in triage.triage(
        merge.merge(evidence, vault_domains={"old.test", "new.test"}),
        now=datetime(2026, 8, 18, tzinfo=timezone.utc))}

    assert "dormant" in records["old.test"].why_flagged
    assert "dormant" not in records["new.test"].why_flagged


def test_dormant_needs_a_real_date_not_the_observation_time(tmp_path):
    """A vault with no usable date must not be guessed at either way."""
    from offlist.sources.vault_csv import collect_sync
    from offlist.worklist import merge, triage

    csv_path = tmp_path / "vault.csv"
    csv_path.write_text("name,url,username,password\n"
                        "X,https://x.test/,me@example.com,x\n", encoding="utf-8")
    evidence = collect_sync(EmailAddress("me@example.com"), [csv_path])
    records = triage.triage(merge.merge(evidence, vault_domains={"x.test"}),
                            now=NOW + timedelta(days=365 * 10))
    assert "dormant" not in records[0].why_flagged


@pytest.mark.parametrize("raw,expected_year", [
    ("2019-01-04", 2019),
    ("2019-01-04T10:00:00Z", 2019),
    ("2019-01-04T10:00:00+00:00", 2019),
    ("1546600000", 2019),          # unix seconds
    ("1546600000000", 2019),       # unix milliseconds (Firefox)
    ("04/01/2019", 2019),
])
def test_vault_timestamps_parse_across_exporter_formats(raw, expected_year):
    from offlist.sources.vault_csv import parse_timestamp
    parsed = parse_timestamp(raw)
    assert parsed is not None and parsed.year == expected_year


@pytest.mark.parametrize("raw", ["garbage", "", "   ", "not-a-date", "99999999999999999999"])
def test_unparseable_timestamps_return_none_rather_than_a_guess(raw):
    from offlist.sources.vault_csv import parse_timestamp
    assert parse_timestamp(raw) is None


# ── canary provenance ──────────────────────────────────────────────────────

def test_a_committed_public_positive_is_recorded_as_tier_b_not_tier_a():
    """Tier A means "from your own vault". Labelling a shared public positive as
    tier A overstates how much the canary proved."""
    from offlist.catalogue.canary import judge
    from offlist.core.models import Discriminating, ProbeResult

    entry = parse_entry({"id": "s", "domain": "s.test", "plugin": "legacy",
                         "canary": {"tier": "c"}}, "t.yaml")
    negative = ProbeResult(site_id="s", domain="s.test", status=Status.NOT_REGISTERED)
    positive = ProbeResult(site_id="s", domain="s.test", status=Status.REGISTERED)

    outcome = judge(entry, negative, positive)
    assert outcome.tier == "b"
    assert outcome.discriminating is Discriminating.YES

    assert judge(entry, negative, None).tier == "c"


# ── files containing personal data are written owner-only ──────────────────
# The worklist store took care over this from the start; the CSV, JSON and
# letter writers did not, so the same class of data landed in the working
# directory with whatever the umask allowed. CodeQL flagged it and it was right.

def _mode(path) -> str:
    import os
    return oct(os.stat(path).st_mode)[-3:]


def test_csv_export_is_owner_only(tmp_path):
    from offlist.cli import render_csv
    from offlist.core.models import ProbeResult, Status

    path = render_csv.write(
        [ProbeResult(site_id="a", domain="a.test", status=Status.REGISTERED)],
        tmp_path / "out.csv")
    assert _mode(path) == "600"


def test_json_export_is_owner_only(tmp_path):
    from offlist.cli import render_json
    from offlist.core.models import ProbeResult, Status

    path = render_json.write(
        [ProbeResult(site_id="a", domain="a.test", status=Status.REGISTERED)],
        "you@example.com", 1.0, tmp_path / "out.json")
    assert _mode(path) == "600"


def test_generated_letters_are_owner_only(tmp_path):
    from offlist.act import letters
    from offlist.core.email import EmailAddress
    from offlist.core.models import ServiceRecord

    record = ServiceRecord(service="s", display_name="S", domains=["s.test"])
    record.remediation = {"kind": "email_request"}
    path = letters.write(record, EmailAddress("you@example.com"), tmp_path / "letters")
    assert _mode(path) == "600"
    assert oct(path.parent.stat().st_mode)[-3:] == "700"


def test_private_write_does_not_leave_a_world_readable_window(tmp_path):
    """Created with 0600 rather than written and chmod-ed afterwards."""
    import os

    from offlist.core.paths import open_private

    path = tmp_path / "x.txt"
    with open_private(path) as handle:
        # the file exists now, mid-write -- check the mode before it closes
        assert oct(os.stat(path).st_mode)[-3:] == "600"
        handle.write("secret")
    assert _mode(path) == "600"


def test_an_existing_permissive_file_is_tightened_on_rewrite(tmp_path):
    import os

    from offlist.core.paths import write_private_text

    path = tmp_path / "x.txt"
    path.write_text("old")
    os.chmod(path, 0o644)
    write_private_text(path, "new")
    assert _mode(path) == "600"
