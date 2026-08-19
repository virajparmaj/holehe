"""Output shapes that downstream tooling depends on."""

import csv
import json

from offlist.cli import render_csv, render_json, render_terminal
from offlist.core.models import Discriminating, ProbeResult, Status


def results():
    return [
        ProbeResult(site_id="a", domain="a.test", status=Status.REGISTERED,
                    discriminating=Discriminating.YES, http_code=200),
        ProbeResult(site_id="b", domain="b.test", status=Status.BLOCKED,
                    detail="HTTP 403", http_code=403),
        ProbeResult(site_id="c", domain="c.test", status=Status.INDETERMINATE),
    ]


def test_csv_header_is_fixed_regardless_of_rows(tmp_path):
    for rows in (results(), []):
        path = render_csv.write(rows, tmp_path / "out.csv")
        with path.open(encoding="utf-8") as fh:
            assert next(csv.reader(fh)) == list(render_csv.FIELDNAMES)


def test_csv_round_trips_every_row(tmp_path):
    path = render_csv.write(results(), tmp_path / "out.csv")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert [r["status"] for r in rows] == ["registered", "blocked", "indeterminate"]


def test_json_is_versioned(tmp_path):
    path = render_json.write(results(), "e@x.test", 1.5, tmp_path / "out.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["summary"] == {"blocked": 1, "indeterminate": 1, "registered": 1}
    assert len(payload["results"]) == 3


def test_terminal_groups_by_status_and_never_calls_a_block_a_rate_limit():
    text = render_terminal.render(results(), "e@x.test", 1.0, color=False)
    assert "account found" in text
    assert "blocked by bot protection" in text
    assert "b.test" in text
    # The whole point: a 403 must not be reported under the rate-limit heading.
    limit_line = [ln for ln in text.splitlines() if "rate limited" in ln]
    assert not limit_line


def test_terminal_reports_how_many_answers_are_actually_trustworthy():
    text = render_terminal.render(results(), "e@x.test", 1.0, color=False)
    assert "1 answered (1 from sites proven to discriminate)" in text


def test_only_found_suppresses_everything_else():
    text = render_terminal.render(results(), "e@x.test", 1.0, color=False, only_found=True)
    assert "a.test" in text
    assert "b.test" not in text
