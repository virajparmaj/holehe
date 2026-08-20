"""Merging evidence into a removal plan."""

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from offlist.core.models import Confidence, Evidence, Status
from offlist.worklist import merge, remediation, triage

NOW = datetime.now(timezone.utc)


def ev(source, domain, detail="", payload=None, when=None):
    return Evidence(source=source, domain=domain, status=Status.REGISTERED,
                    confidence=Confidence.HIGH, detail=detail,
                    payload=payload or {}, observed_at=when or NOW)


def test_subdomains_and_aliases_collapse_to_one_service():
    records = merge.merge([ev("probe", "en.gravatar.com"), ev("probe", "gravatar.com")])
    assert len(records) == 1
    assert records[0].service == "gravatar"


def test_identical_evidence_is_not_counted_twice():
    records = merge.merge([ev("broker_registry", "acxiom.com", "same"),
                           ev("broker_registry", "liveramp.com", "same")])
    assert len(records) == 1
    assert len(records[0].evidence) == 1


def test_observed_domains_are_preserved_not_truncated():
    records = merge.merge([ev("probe", "en.gravatar.com")])
    assert records[0].domains == ["en.gravatar.com"]


def test_never_signed_up_is_the_headline_signal():
    records = triage.triage(merge.merge([ev("probe", "somewhere.test")],
                                        vault_domains=set()))
    assert "never_signed_up" in records[0].why_flagged


def test_a_service_in_your_vault_is_not_flagged_never_signed_up():
    records = triage.triage(merge.merge([ev("probe", "somewhere.test")],
                                        vault_domains={"somewhere.test"}))
    assert "never_signed_up" not in records[0].why_flagged


def test_registry_membership_alone_is_medium_not_high():
    """Registration proves what the company does, not that it holds your address."""
    records = triage.triage(merge.merge([ev("broker_registry", "spokeo.com")]))
    assert records[0].why_flagged == ["data_broker"]
    assert records[0].severity == "medium"


def test_a_broker_corroborated_by_another_source_becomes_high():
    records = triage.triage(merge.merge([ev("broker_registry", "spokeo.com"),
                                         ev("hibp", "spokeo.com")]))
    assert records[0].severity == "high"


def test_a_leaked_recovery_identifier_is_always_high():
    records = triage.triage(merge.merge(
        [ev("probe", "leaky.test", payload={"emailrecovery": "a***@b.com"})]))
    assert "recovery_leak" in records[0].why_flagged
    assert records[0].severity == "high"


def test_dormant_reads_the_vault_date_not_when_we_looked():
    """This test previously asserted the bug: it passed an old `observed_at` and
    expected dormancy, which is what "when we last looked" would mean. Dormancy
    is a fact about the account, so it comes from the vault's own last-used date.
    """
    old = (NOW - timedelta(days=365 * 5)).isoformat()
    records = triage.triage(
        merge.merge([ev("vault_csv", "old.test", payload={"last_used_at": old})],
                    vault_domains={"old.test"}), now=NOW)
    assert "dormant" in records[0].why_flagged


def test_dormant_ignores_a_stale_observation_time():
    """An old observation of a recently-used account is not dormancy."""
    seen_long_ago = NOW - timedelta(days=365 * 5)
    recent_use = (NOW - timedelta(days=10)).isoformat()
    records = triage.triage(
        merge.merge([ev("vault_csv", "fresh.test", when=seen_long_ago,
                        payload={"last_used_at": recent_use})],
                    vault_domains={"fresh.test"}), now=NOW)
    assert "dormant" not in records[0].why_flagged


def test_dormant_needs_a_vault_entry_at_all():
    old = (NOW - timedelta(days=365 * 5)).isoformat()
    records = triage.triage(
        merge.merge([ev("probe", "notmine.test", payload={"last_used_at": old})],
                    vault_domains=set()), now=NOW)
    assert "dormant" not in records[0].why_flagged


def test_a_known_broker_gets_its_curated_opt_out():
    records = remediation.attach(triage.triage(
        merge.merge([ev("broker_registry", "spokeo.com")])), jurisdiction="CA")
    rem = records[0].remediation
    assert rem["kind"] == "opt_out_form"
    assert "spokeo.com/optout" in rem["url"]
    assert rem["drop_covered"] is True


def test_an_unknown_broker_falls_back_to_the_statutory_route():
    records = remediation.attach(triage.triage(
        merge.merge([ev("broker_registry", "obscure-broker.test")])))
    rem = records[0].remediation
    assert rem["kind"] == "drop_covered_only"
    # Check the host, not a substring: "https://evil.test/?x=privacy.ca.gov"
    # would satisfy a substring test.
    assert urlsplit(rem["url"]).hostname == "privacy.ca.gov"


def test_no_statutory_right_is_stated_plainly():
    records = remediation.attach(triage.triage(merge.merge([ev("probe", "x.test")])))
    assert "voluntary" in records[0].remediation["legal_basis_note"]


def test_jurisdiction_selects_the_legal_basis():
    for code, needle in (("CA", "CCPA"), ("EU", "GDPR"), ("UK", "UK GDPR")):
        records = remediation.attach(
            triage.triage(merge.merge([ev("probe", "x.test")])), jurisdiction=code)
        assert any(needle in b for b in records[0].remediation["legal_basis"])


def test_evidence_is_appended_across_runs_not_replaced(tmp_path, monkeypatch):
    from offlist.core.email import EmailAddress
    from offlist.worklist import store

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    email = EmailAddress("someone@example.com")

    first = triage.triage(merge.merge([ev("probe", "x.test", "run one")]))
    store.save(email, first)

    later = ev("hibp", "x.test", "run two", when=NOW + timedelta(days=1))
    second = triage.triage(merge.merge([later]))
    combined = store.merge_with_history(email, second)

    details = {e.detail for e in combined[0].evidence}
    assert details == {"run one", "run two"}
    assert combined[0].first_seen == NOW


def test_stored_worklist_is_not_world_readable(tmp_path, monkeypatch):
    from offlist.core.email import EmailAddress
    from offlist.worklist import store

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    email = EmailAddress("someone@example.com")
    path = store.save(email, triage.triage(merge.merge([ev("probe", "x.test")])))
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert "someone" not in str(path), "the address must not appear in the path"


def test_a_signup_email_is_account_on_record_not_never_signed_up():
    """A verification/welcome message proves you signed up, so it must not be
    labelled 'you did not sign up here'."""
    records = triage.triage(merge.merge(
        [ev("mailbox", "myspace.com", payload={"account_signal": True})],
        vault_domains=set()))
    flags = records[0].why_flagged
    assert "account_on_record" in flags
    assert "never_signed_up" not in flags


def test_marketing_only_mail_still_reads_as_never_signed_up():
    """Marketing mail is not a signup record, so the headline flag still fires."""
    records = triage.triage(merge.merge(
        [ev("mailbox", "store.test", payload={"account_signal": False})],
        vault_domains=set()))
    flags = records[0].why_flagged
    assert "never_signed_up" in flags
    assert "account_on_record" not in flags
