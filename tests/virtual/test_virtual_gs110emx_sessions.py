"""The virtual GS110EMX holds web sessions the way the real one does.

MEASURED 2026-10-14 on gs110emx1 (10.1.5.25, firmware 1.0.2.8):

* every login takes a session slot until it is logged out (or idles out);
* with no slot left, a login with the right password gets the login page back
  saying "Maximum number of sessions reached... Try After Some Time";
* a GET of the logout page with the session's token frees the slot;
* any request whose token the switch does not hold -- and the logout itself --
  is answered with a 298-byte page that redirects to /wmi/login.

The library used to close its connection and leave the session on the switch,
so a few short-lived clients (each MCP tool call was one) locked the web UI.
The size of the real table was not isolated, so these tests set the limit.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from netgear_switch.errors import HttpAuthError
from netgear_switch.http_read import HttpReader
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import Backend, get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.filterwarnings(
    "error::ResourceWarning",
    "error::RuntimeWarning",
    "error::pytest.PytestUnraisableExceptionWarning",
)

_FIX = Path(__file__).parent.parent / "fixtures" / "http"
_MODEL = get_model("gs110emx")
_SPEC = http_spec(_MODEL)
_SYSINFO = "/iss/specific/sysInfo.html"
_FULL = "Maximum number of sessions reached... Try After Some Time"


@pytest.fixture
def emx() -> Iterator[VirtualSwitch]:
    sw = VirtualSwitch(model="gs110emx")
    sw.state.http_max_sessions = 2
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


def _client(sw: VirtualSwitch) -> HttpClient:
    return HttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)


def test_a_full_table_refuses_the_next_login_in_the_switchs_words(
    emx: VirtualSwitch,
) -> None:
    first, second, third = _client(emx), _client(emx), _client(emx)
    try:
        first.login()
        second.login()
        with pytest.raises(HttpAuthError) as exc:
            third.login()
        assert _FULL in str(exc.value)
        assert "check password" not in str(exc.value)
    finally:
        for client in (first, second, third):
            client.close()


def test_every_session_gets_its_own_token(emx: VirtualSwitch) -> None:
    first, second = _client(emx), _client(emx)
    try:
        first.login()
        second.login()
        assert first._token != second._token
        # ...and each one's pages carry ITS token back.
        assert f'value="{first._token}"' in first.get_page(_SYSINFO)
        assert f'value="{second._token}"' in second.get_page(_SYSINFO)
    finally:
        first.close()
        second.close()


def test_closing_a_client_frees_its_slot(emx: VirtualSwitch) -> None:
    """The fix itself: far more clients than slots, one after another, each
    closed when done. Before, the third of these could not log in."""
    for _ in range(6):
        client = _client(emx)
        try:
            assert HttpReader(client, _MODEL).get_mgmt_ip().address == "10.1.5.25"
        finally:
            client.close()
    assert emx._http_face is not None
    assert emx._http_face._sessions == []


def test_closing_a_syncswitch_frees_its_slot(emx: VirtualSwitch) -> None:
    """Through the facade, which is what the CLI and the MCP server close."""
    for _ in range(6):
        with SyncSwitch(
            _MODEL, f"127.0.0.1:{emx.http_port}", http_password="password"
        ) as switch:
            assert len(switch.get_pvids(backend=Backend.HTTP)) == 10
    assert emx._http_face is not None
    assert emx._http_face._sessions == []


def test_a_logged_out_token_gets_the_real_redirect_page(emx: VirtualSwitch) -> None:
    client = _client(emx)
    client.login()
    token = client._token
    raw = client._client
    lost = (_FIX / "gs110emx_fw1028_session_lost.html").read_text()
    # The logout itself is answered with the redirect page...
    assert raw.get(_SPEC.logout_path, params={"Gambit": token}).text == lost
    # ...and so is everything that token asks for afterwards, GET or POST.
    assert raw.get(_SYSINFO, params={"Gambit": token}).text == lost
    assert (
        raw.post("/iss/specific/vlan_pvidsetting.html", data={"Gambit": token}).text
        == lost
    )
    raw.close()


def test_a_dead_session_is_reported_as_one(emx: VirtualSwitch) -> None:
    """What an idled-out session looks like to a caller: the switch has dropped
    the token, and the read must say so rather than fail to parse a page."""
    client = _client(emx)
    client.login()
    assert emx._http_face is not None
    emx._http_face._sessions.clear()  # the switch forgets it, as an idle-out does
    with pytest.raises(HttpAuthError, match="session lost fetching"):
        HttpReader(client, _MODEL).get_mgmt_ip()
    with pytest.raises(HttpAuthError, match="NOT applied and NOT re-sent"):
        client.post_form("/iss/specific/vlan_pvidsetting.html", {"PORT_NO": "2;"})
    client.close()


def test_the_refused_login_page_is_the_real_one(emx: VirtualSwitch) -> None:
    """Byte-for-byte the page captured from gs110emx1 with its table full."""
    import re

    from netgear_switch.virtual import web_gs110emx

    real = (_FIX / "gs110emx_fw1028_login_sessions_full.html").read_text()
    rand = re.search(r"id='rand' value=\"(\d+)\"", real)
    assert rand is not None
    assert web_gs110emx.render_login(rand.group(1), _FULL) == real
