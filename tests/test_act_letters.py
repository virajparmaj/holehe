"""Deletion letters. Generated, never sent."""

from datetime import date, datetime, timezone


from offlist.act import letters
from offlist.core.email import EmailAddress
from offlist.core.models import Confidence, Evidence, ServiceRecord, Status

TODAY = date(2026, 8, 18)
EMAIL = EmailAddress("you@example.com")


def a_record(**kw):
    rec = ServiceRecord(service="mylife", display_name="MyLife",
                        domains=["mylife.com"], category="data_broker")
    rec.evidence = [Evidence("broker_registry", "mylife.com", Status.REGISTERED,
                             Confidence.MEDIUM, "registered data broker",
                             observed_at=datetime(2026, 8, 18, tzinfo=timezone.utc))]
    rec.remediation = {"kind": "email_request", "contact_email": "privacy@mylife.com"}
    for k, v in kw.items():
        setattr(rec, k, v)
    return rec


def test_gdpr_letter_cites_the_right_articles_and_deadline():
    text = letters.compose(a_record(), EMAIL, jurisdiction="EU", today=TODAY)
    assert "Articles 15 and 17" in text
    assert "2016/679" in text
    assert "2026-09-17" in text          # one month, per Art.12(3)
    assert "Article 12(3)" in text


def test_ccpa_letter_uses_the_45_day_window():
    text = letters.compose(a_record(), EMAIL, jurisdiction="CA", today=TODAY)
    assert "1798.105" in text
    assert "2026-10-02" in text          # 45 days
    assert "1798.130(a)(2)" in text


def test_uk_letter_cites_uk_gdpr():
    text = letters.compose(a_record(), EMAIL, jurisdiction="UK", today=TODAY)
    assert "UK GDPR" in text
    assert "Data Protection Act 2018" in text


def test_without_a_jurisdiction_the_letter_says_it_is_voluntary():
    """A large share of voluntary requests are ignored; overclaiming a statutory
    right the user does not have would set them up for a pointless fight."""
    text = letters.compose(a_record(), EMAIL, today=TODAY)
    assert "not asserting a statutory right" in text
    assert "you may decline" in text
    assert "GDPR" not in text


def test_the_letter_carries_the_evidence_and_the_address():
    text = letters.compose(a_record(), EMAIL, jurisdiction="EU", today=TODAY)
    assert "you@example.com" in text
    assert "registered data broker" in text
    assert "2026-08-18" in text


def test_the_letter_says_it_was_not_sent():
    text = letters.compose(a_record(), EMAIL, today=TODAY)
    assert "has not been sent by any" in text


def test_a_name_is_used_when_given():
    text = letters.compose(a_record(), EMAIL, full_name="A Person", today=TODAY)
    assert "My name is A Person." in text
    assert text.rstrip().endswith("automated system.")


def test_writing_produces_a_file_and_nothing_else(tmp_path):
    path = letters.write(a_record(), EMAIL, tmp_path, jurisdiction="CA", today=TODAY)
    assert path.exists()
    assert path.name == "mylife-deletion-request.txt"
    assert "1798.105" in path.read_text(encoding="utf-8")
    assert list(tmp_path.iterdir()) == [path]


def test_service_names_are_slugged_safely(tmp_path):
    rec = a_record(service="weird/name..with spaces")
    path = letters.write(rec, EMAIL, tmp_path, today=TODAY)
    assert path.parent == tmp_path
    assert "/" not in path.name.replace("-deletion-request.txt", "")
