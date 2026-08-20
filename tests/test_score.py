"""The deterministic confidence scoring engine."""

from datetime import datetime, timezone

from offlist.core.models import Confidence, Evidence, ServiceRecord, Status
from offlist.worklist import merge, triage
from offlist.worklist.score import score_evidence

NOW = datetime.now(timezone.utc)


def ev(source, *, status=Status.REGISTERED, confidence=Confidence.HIGH,
       payload=None, domain="svc.test"):
    return Evidence(source=source, domain=domain, status=status,
                    confidence=confidence, detail="", payload=payload or {},
                    observed_at=NOW)


def test_no_evidence_is_unknown_never_no_account():
    score, association = score_evidence([])
    assert score == 0
    assert association == "unknown"


def test_a_negative_probe_does_not_lower_the_score():
    """`indeterminate`/`not_registered` are 'we could not tell', worth 0 points,
    and must not pull a real positive down."""
    score, association = score_evidence([
        ev("vault_csv"),
        ev("probe", status=Status.INDETERMINATE, confidence=Confidence.LOW),
    ])
    assert score == 95
    assert association == "confirmed"


def test_stored_credential_is_confirmed():
    assert score_evidence([ev("vault_csv")]) == (95, "confirmed")


def test_mailbox_verification_is_confirmed():
    score, association = score_evidence(
        [ev("mailbox", payload={"account_signal": True, "message_count": 1})])
    assert association == "confirmed"
    assert score == 90


def test_repeated_account_mail_scores_higher_than_a_single_message():
    one = score_evidence(
        [ev("mailbox", payload={"account_signal": True, "message_count": 1})])[0]
    many = score_evidence(
        [ev("mailbox", payload={"account_signal": True, "message_count": 4})])[0]
    assert many > one


def test_marketing_only_mail_is_exposure_not_signup():
    score, association = score_evidence(
        [ev("mailbox", confidence=Confidence.LOW,
            payload={"account_signal": False})])
    assert association == "exposure"
    assert score == 30


def test_breach_alone_is_exposure_not_an_account():
    assert score_evidence([ev("hibp")]) == (50, "exposure")


def test_broker_registry_aggregate_is_the_weakest_signal():
    aggregate = score_evidence([ev("broker_registry", payload={"broker_count": 500})])
    curated = score_evidence([ev("broker_registry", payload={"name": "Spokeo"})])
    assert aggregate[0] < curated[0]
    assert aggregate[1] == curated[1] == "exposure"


def test_the_strongest_evidence_wins():
    # A breach (exposure) plus a stored credential (account) -> confirmed account.
    score, association = score_evidence([ev("hibp"), ev("vault_csv")])
    assert association == "confirmed"
    assert score == 95


def test_triage_sets_score_and_association_on_the_record():
    records = triage.triage(merge.merge([ev("vault_csv", domain="stored.test")],
                                        vault_domains={"stored.test"}))
    assert records[0].score == 95
    assert records[0].association == "confirmed"
