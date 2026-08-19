"""The consent gate. These tests are the safeguard, so they are the strict ones."""

import pytest

from offlist.act import confirm
from offlist.act.models import Action, ActionKind


def an_action():
    return Action(service="s", display_name="Shop", kind=ActionKind.UNSUBSCRIBE_ONECLICK,
                  summary="one-click unsubscribe", preview="POST https://x.test\n\nBODY",
                  url="https://x.test")


def test_execution_refuses_without_a_terminal(monkeypatch):
    """Otherwise `--execute` in cron sails through every prompt on empty input."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(confirm.ConsentUnavailable, match="interactive terminal"):
        confirm.require_interactive()


def test_execution_allowed_with_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    confirm.require_interactive()


@pytest.mark.parametrize("answer,expected", [
    ("y", True), ("Y", True), ("yes", True), ("YES", True),
    ("", False), ("n", False), ("no", False), ("maybe", False),
    ("all", False), ("a", False), ("*", False), (" ", False),
])
def test_only_an_explicit_yes_counts(answer, expected, capsys):
    assert confirm.ask(an_action(), 1, 1, prompter=lambda _: answer) is expected


def test_default_on_bare_enter_is_no(capsys):
    assert confirm.ask(an_action(), 1, 1, prompter=lambda _: "") is False


def test_interrupting_the_prompt_declines(capsys):
    def interrupt(_):
        raise KeyboardInterrupt

    assert confirm.ask(an_action(), 1, 1, prompter=interrupt) is False


def test_eof_declines(capsys):
    def eof(_):
        raise EOFError

    assert confirm.ask(an_action(), 1, 1, prompter=eof) is False


def test_the_prompt_shows_the_exact_request(capsys):
    confirm.ask(an_action(), 2, 5, prompter=lambda _: "n")
    out = capsys.readouterr().out
    assert "[2/5]" in out
    assert "this is exactly what would be sent" in out
    assert "POST https://x.test" in out


def test_there_is_no_bulk_consent_flag():
    """A flag that skips reading removes the only safeguard, so it must not exist."""
    from offlist.cli.main import build_parser

    parser = build_parser()
    act = parser._subparsers._group_actions[0].choices["act"]
    for flag in ("--yes", "-y", "--yes-to-all", "--all", "--force"):
        option = act._option_string_actions.get(flag)
        assert option is not None, f"{flag} should be caught explicitly, not ignored"
        assert option.dest == "bulk_consent", f"{flag} must route to the refusal path"
