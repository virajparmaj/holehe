"""Turning a worklist into inspectable actions."""

from datetime import datetime, timezone
from pathlib import Path

from offlist.act import plan
from offlist.act.message import parse_message
from offlist.act.models import ActionKind, Blocked
from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, ServiceRecord, Status
from tests.dkim_fixtures import build_message, sign, unsigned

EMAIL = EmailAddress("you@example.com")
NOW = datetime(2026, 8, 18, tzinfo=timezone.utc)


def record(service, domains, remediation, display=None):
    rec = ServiceRecord(service=service, display_name=display or service,
                        domains=domains)
    rec.evidence = [Evidence("probe", domains[0], Status.REGISTERED,
                             Confidence.HIGH, "found", observed_at=NOW)]
    rec.remediation = remediation
    return rec


def test_opt_out_forms_are_offered_as_urls_never_driven():
    """Broker forms carry identity checks and captchas by design; automating them
    is fragile and rude, so the tool hands over the URL."""
    actions = plan.build([record("spokeo", ["spokeo.com"],
                                 {"kind": "opt_out_form",
                                  "url": "https://www.spokeo.com/optout"})], EMAIL)
    assert actions[0].kind is ActionKind.OPEN_URL
    assert not actions[0].executable
    assert actions[0].url == "https://www.spokeo.com/optout"


def test_email_request_becomes_a_letter_not_a_send():
    actions = plan.build([record("mylife", ["mylife.com"],
                                 {"kind": "email_request",
                                  "contact_email": "privacy@mylife.com"})],
                         EMAIL, letters_dir=Path("/tmp/letters"), jurisdiction="EU")
    action = actions[0]
    assert action.kind is ActionKind.WRITE_LETTER
    assert not action.executable
    assert "Articles 15 and 17" in action.letter_text
    assert "Send it yourself" in action.notes


def test_a_signed_message_upgrades_a_service_to_one_click():
    fixture = sign(build_message())
    actions = plan.build(
        [record("shop", ["shop.test"], {"kind": "opt_out_form", "url": "https://x"})],
        EMAIL, messages=[parse_message(fixture.raw)], dnsfunc=fixture.dnsfunc)
    assert actions[0].kind is ActionKind.UNSUBSCRIBE_ONECLICK
    assert actions[0].executable


def test_an_unsigned_message_downgrades_to_a_refusal_with_a_reason():
    fixture = unsigned()
    actions = plan.build(
        [record("shop", ["shop.test"], {"kind": "opt_out_form", "url": "https://x"})],
        EMAIL, messages=[parse_message(fixture.raw)], dnsfunc=fixture.dnsfunc)
    assert actions[0].blocked is Blocked.DKIM_MISSING
    assert not actions[0].executable


def test_a_catalogue_one_click_without_a_message_is_refused_not_guessed():
    actions = plan.build([record("shop", ["shop.test"],
                                 {"kind": "unsubscribe_oneclick"})], EMAIL)
    assert actions[0].blocked is Blocked.NO_MESSAGE
    assert "--mail" in actions[0].notes


def test_an_unknown_route_is_reported_as_a_catalogue_todo():
    actions = plan.build([record("mystery", ["mystery.test"],
                                 {"kind": "none_known"})], EMAIL)
    assert actions[0].kind is ActionKind.NOTHING
    assert "remediation.yaml" in actions[0].notes


def test_mail_from_a_subdomain_still_matches_the_service():
    fixture = sign(build_message(sender="news@mail.shop.test"))
    actions = plan.build([record("shop", ["shop.test"], {"kind": "none_known"})],
                         EMAIL, messages=[parse_message(fixture.raw)],
                         dnsfunc=fixture.dnsfunc)
    assert actions[0].kind is ActionKind.UNSUBSCRIBE_ONECLICK


def test_summary_counts_each_action_once():
    fixture = sign(build_message())
    actions = plan.build([
        record("shop", ["shop.test"], {"kind": "none_known"}),
        record("spokeo", ["spokeo.com"], {"kind": "opt_out_form", "url": "https://s"}),
        record("mylife", ["mylife.com"], {"kind": "email_request"}),
        record("mystery", ["mystery.test"], {"kind": "none_known"}),
    ], EMAIL, messages=[parse_message(fixture.raw)], dnsfunc=fixture.dnsfunc)
    counts = plan.summarise(actions)
    assert sum(counts.values()) == len(actions)
    assert counts["ready to execute"] == 1
