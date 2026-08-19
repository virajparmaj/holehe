"""The gate that decides whether a one-click unsubscribe may be automated.

POSTing to an unsubscribe URL tells whoever runs it that the address is live and
read. For a legitimate sender that is fine. For a spammer it is a favour. The
difference is a DKIM signature that actually covers the headers carrying the URL
and comes from a domain that owns the endpoint -- so every one of these cases is
tested against a real signature.
"""

import pytest

from offlist.act.message import parse_message
from offlist.act.models import Blocked
from offlist.act.unsubscribe import evaluate
from tests.dkim_fixtures import build_message, sign, unsigned


def evaluate_fixture(fixture):
    return evaluate(parse_message(fixture.raw), dnsfunc=fixture.dnsfunc)


def test_properly_signed_one_click_is_allowed():
    blocked, verdict = evaluate_fixture(sign(build_message()))
    assert blocked is None
    assert verdict.trustworthy
    assert verdict.signing_domain == "mail.shop.test"


def test_unsigned_message_is_refused():
    blocked, _ = evaluate_fixture(unsigned())
    assert blocked is Blocked.DKIM_MISSING


def test_signature_that_does_not_cover_the_unsubscribe_headers_is_refused():
    """A signature over From/Subject says nothing about the unsubscribe URL --
    an attacker can append their own List-Unsubscribe and keep it valid."""
    fixture = sign(build_message(), include_headers=[b"from", b"to", b"subject"])
    blocked, verdict = evaluate_fixture(fixture)
    assert blocked is Blocked.DKIM_NOT_COVERING
    assert "list-unsubscribe" in verdict.detail


def test_forged_signature_is_refused():
    blocked, verdict = evaluate_fixture(sign(build_message(), wrong_key=True))
    assert blocked is Blocked.DKIM_INVALID
    assert verdict.signature_valid is False


def test_signing_domain_must_own_the_unsubscribe_endpoint():
    """The spam shape: a validly signed message pointing somewhere unrelated."""
    raw = build_message(unsubscribe="<https://pharma-deals.test/u/abc>")
    blocked, verdict = evaluate_fixture(sign(raw, domain="bulk-sender.test"))
    assert blocked is Blocked.DKIM_UNALIGNED
    assert verdict.signature_valid is True


def test_subdomain_of_the_signing_domain_is_aligned():
    raw = build_message(unsubscribe="<https://unsub.shop.test/u/abc>")
    blocked, _ = evaluate_fixture(sign(raw, domain="shop.test"))
    assert blocked is None


def test_message_without_one_click_header_is_refused():
    blocked, _ = evaluate_fixture(sign(build_message(one_click=False)))
    assert blocked is Blocked.NOT_ONE_CLICK


def test_mailto_only_cannot_be_automated():
    raw = build_message(unsubscribe="<mailto:unsub@shop.test>")
    blocked, _ = evaluate_fixture(sign(raw))
    assert blocked is Blocked.NO_HTTPS_URI


def test_an_uncheckable_signature_is_refused_as_unchecked_not_as_invalid():
    """"Could not check" and "checked and failed" are different problems."""
    import offlist.act.dkim_check as dkim_check

    original = dkim_check._verify
    dkim_check._verify = lambda raw, fn=None, signature="": (None, "no dkimpy")
    try:
        blocked, verdict = evaluate_fixture(sign(build_message()))
    finally:
        dkim_check._verify = original
    assert blocked is Blocked.DKIM_UNCHECKED
    assert verdict.signature_valid is None


def test_unverified_signature_is_not_treated_as_a_pass():
    """`signature_valid is None` means 'not checked', which must not count."""
    from offlist.act.dkim_check import check

    fixture = sign(build_message())
    verdict = check(parse_message(fixture.raw), cryptographic=False)
    assert verdict.covers_unsubscribe
    assert verdict.signature_valid is None
    assert not verdict.trustworthy


@pytest.mark.parametrize("blocked", list(Blocked))
def test_every_refusal_reason_has_a_human_explanation(blocked):
    assert len(blocked.value) > 20
