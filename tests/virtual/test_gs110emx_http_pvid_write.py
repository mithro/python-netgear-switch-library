"""HttpWriter.set_pvid on the GS110EMX, against a mock that answers like one.

Everything asserted about the device was MEASURED on gs110emx1 (10.1.5.25,
firmware 1.0.2.8) on 2026-10-14, on link-down undescribed ports 2 and 3 and
throwaway VLAN 4001:

    PORT_NO=2;  PORT_PVID=1     ACTION=Apply -> applied, errMsg ''
    PORT_NO=2   PORT_PVID=4001  ACTION=Apply -> applied too (no ';' needed)
    PORT_NO=3;  PORT_PVID=4001  ACTION=Apply -> 'Port 3 is not a member of VLAN 4001!'
    PORT_NO=2;  PORT_PVID=4094  ACTION=Apply -> 'VLAN 4094 does not exist.'

A refusal is an HTTP 200 with the page unchanged and the reason in ``errMsg``.
Before this the GS110EMX fell through to the gs305ep/gs105pe PVID form, which
needs a CSRF ``hash`` this page does not carry, so set_pvid could not work.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from netgear_switch.errors import (
    HttpError,
    HttpUnexpectedPageError,
    ProtectedPortError,
)
from netgear_switch.http_read import HttpReader
from netgear_switch.http_write import AsyncHttpWriter, HttpWriter
from netgear_switch.protocols.http import parse
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import AsyncHttpClient, HttpClient
from netgear_switch.virtual.seed import seed_gs110emx_fw1028
from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.filterwarnings(
    "error::ResourceWarning", "error::pytest.PytestUnraisableExceptionWarning"
)

_FIX = Path(__file__).parent.parent / "fixtures" / "http"
_MODEL = get_model("gs110emx")
_SPEC = http_spec(_MODEL)
_PAGE = "/iss/specific/vlan_pvidsetting.html"


class _Recording:
    """Wraps a real session and records every POST body it carries."""

    def __init__(self, inner: HttpClient) -> None:
        self._inner = inner
        self.posts: list[tuple[str, dict[str, str]]] = []

    def login(self) -> None:
        self._inner.login()

    def get_page(self, path: str) -> str:
        return self._inner.get_page(path)

    def post_form(self, path: str, data: dict[str, str]) -> str:
        self.posts.append((path, dict(data)))
        return self._inner.post_form(path, data)


def _seeded() -> VirtualSwitch:
    sw = VirtualSwitch(model="gs110emx")
    sw.state = seed_gs110emx_fw1028()
    # Port 3 leaves VLAN 90, so there is a VLAN a port is NOT a member of.
    sw.state.vlans[90].member.discard(3)
    return sw


@pytest.fixture
def emx() -> Iterator[tuple[VirtualSwitch, HttpClient, _Recording]]:
    sw = _seeded()
    sw.start()
    client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
    client.login()
    try:
        yield sw, client, _Recording(client)
    finally:
        client.close()
        sw.stop()


def test_page_is_the_real_one_byte_for_byte(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    """The seed's PVIDs (all 1, port 6 on 4) are that switch's, so the mock's
    page must equal its capture."""
    _, client, _ = emx
    real = (_FIX / "gs110emx_fw1028_pvid.html").read_text()
    assert client.get_page(_PAGE) == real.replace("GAMBITTOKEN", client._token)


def test_set_pvid_applies_and_reads_back(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    sw, client, session = emx
    HttpWriter(session, _MODEL).set_pvid(2, 90)
    assert sw.state.pvids == {**dict.fromkeys(range(1, 11), 1), 2: 90, 6: 4}
    assert dict(HttpReader(client, _MODEL).get_pvids())[2] == 90
    # What the page's own submitPortPVID() posts: the selected-ports list
    # ("2;"), the PVID, and ACTION=Apply.
    assert session.posts == [
        (_PAGE, {"PORT_NO": "2;", "PORT_PVID": "90", "ACTION": "Apply"})
    ]


def test_port_not_in_the_vlan_is_refused_in_the_firmwares_words(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    sw, _, session = emx
    before = dict(sw.state.pvids)
    with pytest.raises(HttpError) as exc:
        HttpWriter(session, _MODEL).set_pvid(3, 90)
    message = str(exc.value)
    assert "Port 3 is not a member of VLAN 90!" in message
    assert "vlan_pvidsetting.html" in message
    assert sw.state.pvids == before


def test_unknown_vlan_is_refused_before_anything_is_posted(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    sw, _, session = emx
    before = dict(sw.state.pvids)
    with pytest.raises(HttpUnexpectedPageError, match="VLAN 4094 does not exist"):
        HttpWriter(session, _MODEL).set_pvid(2, 4094)
    assert session.posts == []
    assert sw.state.pvids == before


def test_port_outside_the_switch_is_refused_before_anything_is_posted(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    _, _, session = emx
    with pytest.raises(ValueError, match="port 11"):
        HttpWriter(session, _MODEL).set_pvid(11, 90)
    assert session.posts == []


def test_protected_port_needs_force(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    _, _, session = emx
    writer = HttpWriter(session, _MODEL, protected_ports=frozenset({10}))
    with pytest.raises(ProtectedPortError):
        writer.set_pvid(10, 90)
    assert session.posts == []


def test_mock_answers_the_device_way_to_raw_posts(
    emx: tuple[VirtualSwitch, HttpClient, _Recording],
) -> None:
    """The mock's own refusals and its tolerance of a bare ``PORT_NO``, driven
    directly so the writer's guards cannot stand in for them."""
    sw, client, _ = emx

    def post(port_no: str, pvid: str) -> str:
        return parse.parse_gs110emx_err_msg(
            client.post_form(
                _PAGE, {"PORT_NO": port_no, "PORT_PVID": pvid, "ACTION": "Apply"}
            )
        )

    assert post("2;", "4094") == "VLAN 4094 does not exist."
    assert post("3;", "90") == "Port 3 is not a member of VLAN 90!"
    assert (sw.state.pvids[2], sw.state.pvids[3]) == (1, 1)
    assert post("2", "90") == ""  # no trailing ';' -- applied all the same
    assert sw.state.pvids[2] == 90
    assert post("2;", "1") == ""
    assert sw.state.pvids[2] == 1


def test_async_writer_matches_sync() -> None:
    async def go() -> None:
        sw = _seeded()
        sw.start()
        client = AsyncHttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
        try:
            await client.login()
            writer = AsyncHttpWriter(client, _MODEL)
            await writer.set_pvid(2, 90)
            assert sw.state.pvids[2] == 90
            with pytest.raises(HttpError, match="Port 3 is not a member of VLAN 90!"):
                await writer.set_pvid(3, 90)
            with pytest.raises(HttpUnexpectedPageError, match="does not exist"):
                await writer.set_pvid(2, 4094)
            assert sw.state.pvids[3] == 1
        finally:
            await client.aclose()
            sw.stop()

    asyncio.run(go())
