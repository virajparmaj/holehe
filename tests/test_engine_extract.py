"""Token extraction, including the empty-value case that MyBB depends on."""

import httpx

from offlist.catalogue.schema import parse_extractor
from offlist.engine.extract import MISSING, extract, form_replay, json_path


def resp(body="", code=200, headers=None):
    return httpx.Response(code, text=body, headers=headers or {},
                          request=httpx.Request("GET", "https://example.test/"))


def spec(name, **kw):
    return parse_extractor(name, kw, "test")


def test_between_extracts_and_misses_cleanly():
    body = 'var my_post_key = "abc123";'
    assert extract(spec("k", start='var my_post_key = "', end='"'), resp(body)) == "abc123"
    assert extract(spec("k", start="nope", end='"'), resp(body)) is None


def test_between_returns_empty_string_for_an_empty_token():
    """MyBB serves my_post_key="" to guests; "" is a value, not a miss."""
    got = extract(spec("k", start='var my_post_key = "', end='"'),
                  resp('var my_post_key = "";'))
    assert got == ""
    assert got is not None


def test_regex_group():
    s = spec("t", **{"via": "regex", "pattern": r'value="([^"]+)"', "group": 1})
    assert extract(s, resp('<input value="tok">')) == "tok"


def test_css_attribute():
    s = spec("t", **{"via": "css", "selector": "meta[name=csrf-token]", "attr": "content"})
    assert extract(s, resp('<meta name="csrf-token" content="xyz">')) == "xyz"


def test_header_and_cookie_sources():
    r = resp("", headers={"X-Csrf": "h1", "set-cookie": "sid=c1; Path=/"})
    assert extract(spec("t", **{"from": "header", "header": "X-Csrf"}), r) == "h1"
    assert extract(spec("t", **{"from": "cookie", "cookie": "sid"}), r) == "c1"


def test_json_source():
    s = spec("t", **{"from": "json", "via": "json_path", "path": "a.b"})
    assert extract(s, resp('{"a":{"b":7}}')) == 7
    assert extract(s, resp('{"a":{}}')) is None


def test_json_path_distinguishes_absent_from_null():
    assert json_path({"a": None}, "a") is None
    assert json_path({"a": None}, "b") is MISSING


def test_form_replay_harvests_hidden_inputs():
    html = ('<form><input name="a" value="1"><input name="b" value="2">'
            '<input value="ignored"></form>')
    assert form_replay(html, "form input") == {"a": "1", "b": "2"}
