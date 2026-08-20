"""The mailbox source: read your own mail, never overclaim from it."""

from datetime import datetime, timezone

from offlist.core.email import EmailAddress
from offlist.sources.base import RunContext
from offlist.sources.mailbox import classify, collect_sync

EMAIL = EmailAddress("alice@example.com")


def eml(*, sender, subject, body="", date="Tue, 19 Aug 2014 10:00:00 +0000",
        to="alice@example.com") -> bytes:
    return (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Date: {date}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


def collect(raws, email=EMAIL):
    ctx = RunContext(extras={"mail_raw_messages": list(raws)})
    return collect_sync(email, ctx)


def test_classify_prefers_the_strongest_marker():
    # "welcome" is present, but a verification phrase outranks it.
    subtype, conf = classify("Welcome! Please verify your email", "")
    assert subtype == "email_verification"
    assert conf.value == "high"


def test_classify_falls_back_to_marketing_not_silence():
    subtype, conf = classify("20% off this weekend only", "shop now")
    assert subtype == "marketing"
    assert conf.value == "low"


def test_verification_mail_is_high_confidence_registered_evidence():
    out = collect([eml(sender="no-reply@myspace.com",
                       subject="Verify your email address")])
    assert len(out) == 1
    ev = out[0]
    assert ev.domain == "myspace.com"
    assert ev.is_positive
    assert ev.confidence.value == "high"
    assert ev.payload["subtype"] == "email_verification"
    assert ev.payload["account_signal"] is True


def test_observed_at_is_the_message_date_not_now():
    out = collect([eml(sender="hi@oldforum.test",
                       subject="Your account is ready",
                       date="Fri, 04 Mar 2011 08:00:00 +0000")])
    assert out[0].observed_at.year == 2011
    assert out[0].payload["first_seen"] == "2011-03-04"


def test_sender_subdomains_collapse_to_the_registrable_domain():
    out = collect([eml(sender="notifications@mail.notify.myspace.com",
                       subject="Reset your password")])
    assert out[0].domain == "mail.notify.myspace.com"  # observed form kept
    # ...but the group key reduced it, so a second subdomain merges:
    out2 = collect([
        eml(sender="a@mail.myspace.com", subject="Reset your password"),
        eml(sender="b@notify.myspace.com", subject="Reset your password"),
    ])
    assert len(out2) == 1
    assert out2[0].payload["message_count"] == 2


def test_multiple_messages_group_by_subtype_with_a_count():
    out = collect([
        eml(sender="x@shop.test", subject="Verify your email"),
        eml(sender="x@shop.test", subject="Password reset requested",
            date="Tue, 01 Jan 2019 10:00:00 +0000"),
        eml(sender="x@shop.test", subject="Reset your password again",
            date="Wed, 02 Jan 2019 10:00:00 +0000"),
    ])
    by_subtype = {e.payload["subtype"]: e for e in out}
    assert set(by_subtype) == {"email_verification", "password_reset"}
    assert by_subtype["password_reset"].payload["message_count"] == 2


def test_body_keywords_are_matched_when_the_subject_is_bland():
    out = collect([eml(sender="team@saas.test", subject="Hello",
                       body="Please confirm your email address to continue.")])
    assert out[0].payload["subtype"] == "email_verification"


def test_marketing_only_mail_is_low_confidence():
    out = collect([eml(sender="deals@store.test",
                       subject="Weekend sale inside")])
    assert out[0].confidence.value == "low"
    assert out[0].payload["account_signal"] is False


def test_reads_eml_files_from_disk(tmp_path):
    (tmp_path / "m.eml").write_bytes(
        eml(sender="no-reply@service.test", subject="Welcome to Service"))
    ctx = RunContext(extras={"mail_paths": (str(tmp_path),)})
    out = collect_sync(EMAIL, ctx)
    assert len(out) == 1
    assert out[0].domain == "service.test"


def test_addressed_to_target_is_recorded():
    hit = collect([eml(sender="a@svc.test", subject="Verify your email",
                       to="alice@example.com")])
    miss = collect([eml(sender="a@svc.test", subject="Verify your email",
                        to="bob@example.com")])
    assert hit[0].payload["addressed_to_target"] is True
    assert miss[0].payload["addressed_to_target"] is False
