"""Catalogue loading, engine expansion, and schema validation."""

import pytest
import yaml

from offlist.catalogue.loader import (expand_engine, load_catalogue, load_engines,
                                      selectable, substitute_vars)
from offlist.catalogue.schema import CatalogueError, parse_entry


def test_every_shipped_entry_validates():
    entries = load_catalogue(include_disabled=True)
    assert len(entries) > 100
    assert len({e.id for e in entries}) == len(entries), "duplicate site ids"
    for e in entries:
        assert e.domain, e.id
        assert e.steps or e.plugin, f"{e.id} has neither steps nor a plugin"


def test_mybb_engine_expands_into_full_entries():
    """25 byte-identical modules become one engine plus one line each."""
    entries = {e.id: e for e in load_catalogue(include_disabled=True)}
    forum = [e for e in entries.values() if e.category == "forum" and e.steps]
    assert len(forum) >= 20

    biosmods = entries["biosmods"]
    assert biosmods.steps[0].url == "https://bios-mods.com/forum/member.php"
    assert biosmods.steps[1].url == "https://bios-mods.com/forum/xmlhttp.php"
    assert biosmods.steps[1].body_value["email"] == "{email}"
    assert biosmods.steps[1].body_value["my_post_key"] == "{captured.post_key}"


def test_engine_vars_do_not_eat_runtime_placeholders():
    """Load-time substitution must leave {email} and {captured.x} alone."""
    out = substitute_vars({"u": "{base}/x?e={email}&t={captured.tok}"}, {"base": "https://s"})
    assert out["u"] == "https://s/x?e={email}&t={captured.tok}"


def test_row_overrides_beat_engine_defaults():
    engines = load_engines()
    merged = expand_engine({"id": "x", "domain": "x.test", "engine": "mybb",
                            "vars": {"base_url": "https://x.test"},
                            "timeout": 1, "frequent_rate_limit": True}, engines)
    assert merged["timeout"] == 1
    assert merged["frequent_rate_limit"] is True


def test_unknown_engine_is_an_error_not_a_silent_skip():
    with pytest.raises(CatalogueError, match="unknown engine"):
        expand_engine({"id": "x", "domain": "x.test", "engine": "nope"}, {})


@pytest.mark.parametrize("raw,match", [
    ({"domain": "a.test", "steps": [{"url": "u"}]}, "needs an `id`"),
    ({"id": "a", "steps": [{"url": "u"}]}, "needs a `domain`"),
    ({"id": "a", "domain": "a.test"}, "needs either `steps` or `plugin`"),
    ({"id": "a", "domain": "a.test", "method": "wat",
      "steps": [{"url": "u"}]}, "unknown `method"),
    ({"id": "a", "domain": "a.test", "steps": [{"method": "GET"}]}, "needs a `url`"),
])
def test_schema_rejects_malformed_entries(raw, match):
    with pytest.raises(CatalogueError, match=match):
        parse_entry(raw, "test.yaml")


def test_else_must_be_last():
    with pytest.raises(CatalogueError, match="`else` must be the last rule"):
        parse_entry({"id": "a", "domain": "a.test", "steps": [{"url": "u"}],
                     "rules": [{"else": "not_registered"},
                               {"when": {"status": {"eq": 200}}, "then": "registered"}]},
                    "test.yaml")


def test_body_needs_exactly_one_kind():
    with pytest.raises(CatalogueError, match="exactly one of"):
        parse_entry({"id": "a", "domain": "a.test",
                     "steps": [{"url": "u", "body": {"form": {}, "json": {}}}]},
                    "test.yaml")


def test_yaml_bare_yes_is_not_read_as_a_boolean():
    """YAML 1.1 turns `discriminating: yes` into True; the schema must cope."""
    raw = yaml.safe_load("id: a\ndomain: a.test\nplugin: legacy\n"
                         "canary: {discriminating: yes}\n")
    assert raw["canary"]["discriminating"] is True
    assert parse_entry(raw, "t.yaml").canary.discriminating.value == "yes"


def test_side_effect_gates_are_closed_by_default():
    entries = load_catalogue(include_disabled=True)
    allowed = selectable(entries)
    assert not [e for e in allowed if e.side_effect != "none"]

    with_login = selectable(entries, allow_login_probe=True)
    assert len(with_login) >= len(allowed)


def test_account_creating_probes_are_never_selectable():
    entries = load_catalogue(include_disabled=True)
    everything = selectable(entries, allow_login_probe=True, allow_email_sending=True)
    assert not [e for e in everything if e.side_effect == "creates_account"]


def test_disabled_entries_record_a_measured_reason():
    disabled = [e for e in load_catalogue(include_disabled=True) if not e.enabled]
    assert disabled, "expected the measured failures to be recorded"
    for e in disabled:
        assert e.disabled is not None, e.id
        assert e.disabled.status, e.id
        assert e.disabled.measured, e.id
