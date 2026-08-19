"""Decision rules, and the default that matters most."""

import httpx

from offlist.catalogue.schema import parse_rule
from offlist.core.models import Status
from offlist.engine.decide import decide, evaluate_when


def resp(body="", code=200, headers=None):
    return httpx.Response(code, text=body, headers=headers or {},
                          request=httpx.Request("GET", "https://example.test/"))


def rules(*raw):
    return [parse_rule(r, "test") for r in raw]


def test_falling_off_the_end_is_parse_failed_not_not_registered():
    """The single most consequential default in the rewrite.

    The original treated an unrecognised response as "no account here", which is
    how sites quietly degraded into always answering no.
    """
    status, _ = decide(rules({"when": {"body": {"contains": "taken"}},
                              "then": "registered"}),
                       resp("something entirely new"))
    assert status is Status.PARSE_FAILED


def test_explicit_else_is_required_to_claim_a_negative():
    status, _ = decide(rules({"when": {"body": {"contains": "taken"}}, "then": "registered"},
                             {"else": "not_registered"}),
                       resp("all clear"))
    assert status is Status.NOT_REGISTERED


def test_first_matching_rule_wins():
    status, _ = decide(rules({"when": {"status": {"eq": 200}}, "then": "registered"},
                             {"when": {"status": {"eq": 200}}, "then": "not_registered"}),
                       resp("x"))
    assert status is Status.REGISTERED


def test_from_status_defers_to_the_status_map():
    status, _ = decide(rules({"when": {"status": {"eq": 429}}, "then": "from_status"}),
                       resp("slow down", 429))
    assert status is Status.RATE_LIMITED


def test_mapping_of_clauses_is_an_and():
    assert evaluate_when({"status": {"eq": 200}, "body": {"contains": "yes"}}, resp("yes"))
    assert not evaluate_when({"status": {"eq": 200}, "body": {"contains": "no"}}, resp("yes"))


def test_any_and_all_nesting():
    r = resp("beta")
    assert evaluate_when({"any": [{"body": {"contains": "alpha"}},
                                  {"body": {"contains": "beta"}}]}, r)
    assert not evaluate_when({"all": [{"body": {"contains": "alpha"}},
                                      {"body": {"contains": "beta"}}]}, r)


def test_json_path_with_array_index():
    r = resp('{"errors":{"email":[{"code":"email_is_taken"}]}}')
    assert evaluate_when({"json": {"path": "errors.email[0].code",
                                   "equals": "email_is_taken"}}, r)


def test_json_key_exists():
    r = resp('{"errors":{"email":["x"]}}')
    assert evaluate_when({"json": {"path": "errors", "key_exists": "email"}}, r)
    assert not evaluate_when({"json": {"path": "errors", "key_exists": "phone"}}, r)


def test_invalid_json_does_not_match_a_json_clause():
    assert not evaluate_when({"json": {"path": "a", "equals": 1}}, resp("<html>"))
