"""What actually goes on the wire, and what refuses to."""

import httpx
import pytest
import respx

from offlist.act.message import load_messages, parse_message
from offlist.act.models import Action, ActionKind, Blocked
from offlist.act.unsubscribe import BODY, build_action, execute
from tests.dkim_fixtures import build_message, sign, unsigned


def action_for(fixture):
    return build_action("shop", "Shop", parse_message(fixture.raw),
                        dnsfunc=fixture.dnsfunc)


@respx.mock
@pytest.mark.asyncio
async def test_executes_exactly_the_rfc_8058_request():
    route = respx.post("https://unsub.shop.test/u/abc").mock(
        return_value=httpx.Response(200))
    result = await execute(action_for(sign(build_message())))

    assert result.outcome == "executed"
    assert route.called
    request = route.calls[0].request
    assert request.method == "POST"
    assert request.content == BODY.encode()
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"


@respx.mock
@pytest.mark.asyncio
async def test_a_refused_action_never_reaches_the_network():
    route = respx.post("https://unsub.shop.test/u/abc").mock(
        return_value=httpx.Response(200))
    result = await execute(action_for(unsigned()))

    assert result.outcome == "refused"
    assert not route.called, "an unsigned message must not be POSTed"


@respx.mock
@pytest.mark.asyncio
async def test_a_server_error_is_reported_not_swallowed():
    respx.post("https://unsub.shop.test/u/abc").mock(
        return_value=httpx.Response(500))
    result = await execute(action_for(sign(build_message())))
    assert result.outcome == "failed"
    assert result.http_code == 500


@respx.mock
@pytest.mark.asyncio
async def test_a_transport_failure_is_reported_not_raised():
    respx.post("https://unsub.shop.test/u/abc").mock(
        side_effect=httpx.ConnectError("down"))
    result = await execute(action_for(sign(build_message())))
    assert result.outcome == "failed"
    assert "ConnectError" in result.detail


def test_the_preview_shows_the_literal_request_and_the_dkim_verdict():
    action = action_for(sign(build_message()))
    assert "POST https://unsub.shop.test/u/abc" in action.preview
    assert BODY in action.preview
    assert "DKIM signed by  : mail.shop.test" in action.preview
    assert "signature valid : True" in action.preview


def test_a_refused_action_explains_the_actual_risk():
    action = action_for(unsigned())
    assert action.blocked is Blocked.DKIM_MISSING
    assert "confirm to the sender that this address is live" in action.notes


def test_only_a_verified_one_click_is_ever_executable():
    assert action_for(sign(build_message())).executable
    for kind in (ActionKind.WRITE_LETTER, ActionKind.OPEN_URL, ActionKind.NOTHING):
        assert not Action(service="s", display_name="S", kind=kind,
                          summary="x").executable


def test_eml_and_mbox_are_both_readable(tmp_path):
    eml = tmp_path / "one.eml"
    eml.write_bytes(sign(build_message()).raw)

    mbox = tmp_path / "box.mbox"
    mbox.write_bytes(b"From sender Thu Jan  1 00:00:00 2026\r\n"
                     + build_message(subject="Second") + b"\r\n")

    messages = load_messages([eml, mbox])
    assert len(messages) == 2
    assert {m.from_domain for m in messages} == {"mail.shop.test"}


def test_a_directory_of_eml_files_is_read(tmp_path):
    for i in range(3):
        (tmp_path / f"m{i}.eml").write_bytes(build_message(subject=f"n{i}"))
    assert len(load_messages([tmp_path])) == 3


def test_headers_without_angle_brackets_still_parse():
    raw = build_message(unsubscribe="https://unsub.shop.test/u/abc")
    msg = parse_message(raw)
    assert msg.https_uri == "https://unsub.shop.test/u/abc"


def test_no_smtp_client_exists_anywhere_in_the_act_package():
    """Letters are generated, never sent. Keep it structurally impossible."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "offlist" / "act"
    offenders = [
        p.name for p in root.rglob("*.py")
        if re.search(r"^\s*(import|from)\s+(smtplib|aiosmtplib|sendgrid)", 
                     p.read_text(encoding="utf-8"), re.M)
    ]
    assert not offenders, f"outbound mail capability crept in: {offenders}"
