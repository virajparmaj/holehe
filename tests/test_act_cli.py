"""End-to-end `offlist act`, including the paths that must refuse."""

from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from offlist.cli.main import main
from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, ServiceRecord, Status
from offlist.worklist import remediation, store, triage
from tests.dkim_fixtures import build_message, sign, unsigned

EMAIL = "you@example.com"
NOW = datetime.now(timezone.utc)


def seed(tmp_path, monkeypatch, services):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    records = []
    for service, domain, kind, url in services:
        rec = ServiceRecord(service=service, display_name=service, domains=[domain])
        rec.evidence = [Evidence("probe", domain, Status.REGISTERED,
                                 Confidence.HIGH, "mails me", observed_at=NOW)]
        rec.remediation = {"kind": kind, "url": url}
        records.append(rec)
    records = remediation.attach(triage.triage(records), jurisdiction="EU")
    for rec, (service, domain, kind, url) in zip(records, services):
        rec.remediation = {"kind": kind, "url": url, "legal_basis": []}
    store.save(EmailAddress(EMAIL), records)
    return records


def write_mail(tmp_path, fixture) -> Path:
    path = tmp_path / "mail"
    path.mkdir(exist_ok=True)
    (path / "m.eml").write_bytes(fixture.raw)
    return path


def test_dry_run_is_the_default_and_sends_nothing(tmp_path, monkeypatch, capsys):
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None)])
    mail = write_mail(tmp_path, sign(build_message()))

    with respx.mock:
        route = respx.post("https://unsub.shop.test/u/abc").mock(
            return_value=httpx.Response(200))
        assert main(["act", EMAIL, "--mail", str(mail)]) == 0
        assert not route.called

    out = capsys.readouterr().out
    assert "Nothing has been sent. This is a dry run." in out


def test_bulk_consent_flags_are_refused_with_an_explanation(tmp_path, monkeypatch,
                                                            capsys):
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None)])
    for flag in ("--yes", "-y", "--yes-to-all", "--all", "--force"):
        with pytest.raises(SystemExit) as exit_info:
            main(["act", EMAIL, flag])
        assert "no bulk-consent flag" in str(exit_info.value)


def test_execute_refuses_without_a_terminal(tmp_path, monkeypatch):
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None)])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(SystemExit) as exit_info:
        main(["act", EMAIL, "--execute"])
    assert "interactive terminal" in str(exit_info.value)


def test_act_without_a_worklist_says_what_to_run_first(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "empty"))
    with pytest.raises(SystemExit) as exit_info:
        main(["act", EMAIL])
    assert "offlist worklist" in str(exit_info.value)


@respx.mock
def test_execute_sends_only_what_was_approved(tmp_path, monkeypatch, capsys):
    """Two sendable items, one approved. Exactly one request must go out."""
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None),
                                 ("other", "other.test", "none_known", None)])

    shop = sign(build_message())
    other = sign(build_message(sender="news@mail.other.test",
                               unsubscribe="<https://unsub.other.test/u/z>"),
                 domain="mail.other.test")

    mail = tmp_path / "mail"
    mail.mkdir()
    (mail / "a.eml").write_bytes(shop.raw)
    (mail / "b.eml").write_bytes(other.raw)

    def dnsfunc(name, timeout=5):
        key = name.decode() if isinstance(name, bytes) else name
        return (shop.dnsfunc(name) if "shop.test" in key else other.dnsfunc(name))

    monkeypatch.setattr("offlist.act.dkim_check._verify",
                        lambda raw, fn=None, signature="": (True, "signature verified"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    # Records come back sorted by service name, so approve by identity rather
    # than by prompt order.
    import offlist.act.confirm as confirm_mod
    monkeypatch.setattr(confirm_mod, "ask",
                        lambda action, i, n, **kw: "shop.test" in (action.url or ""))

    shop_route = respx.post("https://unsub.shop.test/u/abc").mock(
        return_value=httpx.Response(200))
    other_route = respx.post("https://unsub.other.test/u/z").mock(
        return_value=httpx.Response(200))

    assert main(["act", EMAIL, "--mail", str(mail), "--execute"]) == 0

    assert shop_route.called, "the approved item should have been sent"
    assert not other_route.called, "the declined item must not have been sent"

    out = capsys.readouterr().out
    assert "1 sent, 1 declined" in out


@respx.mock
def test_a_refused_item_is_never_offered_for_approval(tmp_path, monkeypatch, capsys):
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None)])
    mail = write_mail(tmp_path, unsigned())

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    def refuse(_):
        raise AssertionError("a refused action must never reach the prompt")

    monkeypatch.setattr("builtins.input", refuse)
    route = respx.post("https://unsub.shop.test/u/abc").mock(
        return_value=httpx.Response(200))

    assert main(["act", EMAIL, "--execute", "--mail", str(mail)]) == 0
    assert not route.called
    assert "Nothing is eligible to be sent automatically." in capsys.readouterr().out


def test_letters_are_written_and_recorded_but_not_sent(tmp_path, monkeypatch, capsys):
    seed(tmp_path, monkeypatch, [("mylife", "mylife.test", "email_request", None)])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    letters_dir = tmp_path / "letters"
    assert main(["act", EMAIL, "--execute", "--jurisdiction", "EU",
                 "--letters-dir", str(letters_dir), "--name", "A Person"]) == 0

    written = list(letters_dir.glob("*.txt"))
    assert len(written) == 1
    text = written[0].read_text(encoding="utf-8")
    assert "Articles 15 and 17" in text
    assert "A Person" in text

    out = capsys.readouterr().out
    assert "offlist has no mail client" in out

    records = store.load(EmailAddress(EMAIL))
    actions = records[0].actions_taken
    assert actions and actions[0]["outcome"] == "written"
    assert records[0].state == "actioned"


def test_only_restricts_to_one_service(tmp_path, monkeypatch, capsys):
    seed(tmp_path, monkeypatch, [("shop", "shop.test", "none_known", None),
                                 ("other", "other.test", "none_known", None)])
    assert main(["act", EMAIL, "--only", "shop"]) == 0
    out = capsys.readouterr().out
    assert "shop" in out
    assert "other" not in out.replace("other people's forms", "")
