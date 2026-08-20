"""How strongly the evidence ties you to a service, on a deterministic scale.

The report this implements makes one point worth keeping front and centre: a
score of 0 means *insufficient evidence*, never "you have no account here". A
signup form that stays silent, a breach API that returns nothing, a mailbox with
no matching mail -- none of those prove absence. So the low end of the scale is
"unknown", not "no", and the four association states are worded to say exactly
what is and is not known.

The scale is a lookup table, not a model. It is meant to be legible: a user can
read *why* a service scored what it did, and two runs over the same evidence
always agree. Only positive evidence contributes -- a negative or indeterminate
observation scores nothing rather than pushing the total down, because "we could
not tell" is not the same as "not here".
"""

from __future__ import annotations

from typing import Iterable

from offlist.core.models import Evidence, ServiceRecord

# Association states, strongest first. The wording is the product: it is the
# difference between "you signed up" and "your data is here, signup unknown".
CONFIRMED = "confirmed"    # you deliberately have/had an account here
LIKELY = "likely"          # you probably had an account here
EXPOSURE = "exposure"      # your data is here; whether you signed up is unknown
UNKNOWN = "unknown"        # no evidence either way -- not "no account"

# Points and kind per piece of positive evidence. `account` evidence speaks to a
# deliberate signup; `exposure` evidence speaks only to your data being present.
_ACCOUNT = "account"
_EXPOSURE = "exposure"


def _points(ev: Evidence) -> tuple[int, str]:
    """Score one positive observation as (points, kind). Non-positives score 0."""
    if not ev.is_positive:
        return 0, _EXPOSURE

    source = ev.source
    payload = ev.payload or {}

    if source == "vault_csv":
        # You stored a credential: about as direct as offline evidence of a
        # deliberate signup gets.
        return 95, _ACCOUNT

    if source == "mailbox":
        if payload.get("account_signal"):
            base = 90 if str(ev.confidence.value) == "high" else 70
            if int(payload.get("message_count", 1)) >= 2:
                base = min(95, base + 5)
            return base, _ACCOUNT
        return 30, _EXPOSURE          # marketing only: a possible association

    if source == "public_exposure":
        # A served Gravatar profile or authored public commits: a real account,
        # kept just under `confirmed` because it can be created indirectly.
        return 85, _ACCOUNT

    if source == "probe":
        proven = str(payload.get("discriminating", "")) == "yes"
        return (75 if proven else 65), _ACCOUNT

    if source == "hibp":
        return 50, _EXPOSURE          # your address was lost here; signup unknown

    if source == "broker_registry":
        # The aggregate row stands for many brokers at once, so it is the weakest
        # single signal; a curated broker naming your data is a little stronger.
        return (25 if payload.get("broker_count") else 40), _EXPOSURE

    # An unrecognised positive source still counts for something, as exposure.
    return 40, _EXPOSURE


def score_evidence(evidence: Iterable[Evidence]) -> tuple[int, str]:
    """Return (score, association) for a bag of evidence."""
    best_account = 0
    best_exposure = 0
    for ev in evidence:
        points, kind = _points(ev)
        if kind == _ACCOUNT:
            best_account = max(best_account, points)
        else:
            best_exposure = max(best_exposure, points)

    score = max(best_account, best_exposure)
    if best_account >= 90:
        association = CONFIRMED
    elif best_account >= 60:
        association = LIKELY
    elif best_exposure > 0:
        association = EXPOSURE
    elif best_account > 0:
        association = LIKELY
    else:
        association = UNKNOWN
    return score, association


def score_for(record: ServiceRecord) -> tuple[int, str]:
    return score_evidence(record.evidence)


#: One line per state, for rendering. Deliberately phrased so `unknown` and a
#: bare `exposure` are never mistaken for "no account".
ASSOCIATION_DESCRIPTIONS = {
    CONFIRMED: "you deliberately had an account here",
    LIKELY: "you probably had an account here",
    EXPOSURE: "your data is held here; whether you signed up is unknown",
    UNKNOWN: "no evidence either way -- not a finding of 'no account'",
}
