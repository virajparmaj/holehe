"""The discrimination downgrade -- the fix for the 26 always-negative modules."""

from offlist.core.models import (Confidence, Discriminating, Evidence,
                                 ProbeResult, ServiceRecord, Status)


def result(status, discriminating):
    return ProbeResult(site_id="s", domain="s.test", status=status,
                       discriminating=discriminating)


def test_negative_from_an_unproven_site_becomes_indeterminate():
    out = result(Status.NOT_REGISTERED, Discriminating.UNVERIFIED).downgraded()
    assert out.status is Status.INDETERMINATE
    assert out.confidence is Confidence.LOW


def test_negative_from_a_proven_site_survives():
    out = result(Status.NOT_REGISTERED, Discriminating.YES).downgraded()
    assert out.status is Status.NOT_REGISTERED


def test_positives_are_never_downgraded():
    for d in Discriminating:
        assert result(Status.REGISTERED, d).downgraded().status is Status.REGISTERED


def test_failures_pass_through_untouched():
    for s in (Status.BLOCKED, Status.RATE_LIMITED, Status.PARSE_FAILED):
        assert result(s, Discriminating.UNVERIFIED).downgraded().status is s


def test_downgrade_returns_a_new_object():
    original = result(Status.NOT_REGISTERED, Discriminating.UNVERIFIED)
    assert original.downgraded() is not original
    assert original.status is Status.NOT_REGISTERED


def test_status_groupings():
    assert Status.REGISTERED.is_answer
    assert not Status.BLOCKED.is_answer
    assert Status.BLOCKED.is_failure
    assert Status.PARSE_FAILED.is_actionable_by_us
    assert Status.ENDPOINT_GONE.is_actionable_by_us
    assert not Status.BLOCKED.is_actionable_by_us


def test_service_record_takes_the_best_confidence():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    rec = ServiceRecord(service="s", display_name="S", evidence=[
        Evidence("a", "s.test", Status.REGISTERED, Confidence.LOW, observed_at=now),
        Evidence("b", "s.test", Status.REGISTERED, Confidence.HIGH, observed_at=now),
    ])
    assert rec.confidence is Confidence.HIGH
    assert rec.sources() == ["a", "b"]
