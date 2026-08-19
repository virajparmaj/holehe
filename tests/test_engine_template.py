"""Placeholder expansion.

mail_ru shipped `data = 'email={email}&...'` with no f-prefix and posted the
literal text `{email}` for years. A closed placeholder set makes that a raised
error rather than a silent wrong request.
"""

import pytest

from offlist.core.email import EmailAddress
from offlist.engine.template import TemplateError, render


@pytest.fixture
def email():
    return EmailAddress("Someone.Else@Example.COM")


def test_email_derivations(email):
    assert render("{email}", email) == "Someone.Else@Example.COM"
    assert render("{email_local}", email) == "Someone.Else"
    assert render("{email_domain}", email) == "Example.COM"
    assert render("{email_urlencoded}", email) == "Someone.Else%40Example.COM"
    assert render("{email_normalized}", email) == "someone.else@example.com"


def test_md5_matches_gravatar_convention(email):
    import hashlib
    expected = hashlib.md5(b"someone.else@example.com").hexdigest()
    assert render("{md5}", email) == expected


def test_unknown_placeholder_raises_rather_than_passing_through(email):
    with pytest.raises(TemplateError, match="unknown placeholder"):
        render("{emial}", email)


def test_missing_capture_raises(email):
    with pytest.raises(TemplateError, match="nothing captured"):
        render("{captured.csrf}", email, {})


def test_captures_interpolate(email):
    assert render("tok={captured.csrf}", email, {"csrf": "abc"}) == "tok=abc"


def test_random_helpers_respect_length(email):
    assert len(render("{random_alpha(12)}", email)) == 12
    assert len(render("{random_digits(5)}", email)) == 5
    assert 6 <= len(render("{random_alnum_lower(6,30)}", email)) <= 30
    assert 1 <= int(render("{random_int(1,3)}", email)) <= 3


def test_render_recurses_into_structures(email):
    out = render({"a": ["{email}", {"b": "{email_local}"}]}, email)
    assert out == {"a": ["Someone.Else@Example.COM", {"b": "Someone.Else"}]}


def test_non_placeholder_braces_are_left_alone(email):
    # A literal JSON body must survive untouched.
    assert render('{"k": 1}', email) == '{"k": 1}'
