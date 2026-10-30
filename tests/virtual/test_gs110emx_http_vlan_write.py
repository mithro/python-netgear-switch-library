"""HttpWriter.set_vlan_membership on the GS110EMX, against the faithful mock.

The apply shape, its single-VLAN scope and its refusal were MEASURED on
gs110emx1 (10.1.5.25, firmware 1.0.2.8) on 2026-10-14 against throwaway VLAN
4001 and link-down port 2 -- see ``web_gs110emx.handle_vlan_membership``.
Before this, the GS110EMX fell through to the gs305ep/gs105pe flow, which
selects with ``VLAN_ID`` alone and needs a CSRF ``hash`` this page does not have.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from netgear_switch.errors import (
    HttpError,
    HttpUnexpectedPageError,
    ProtectedPortError,
)
from netgear_switch.http_write import AsyncHttpWriter, HttpWriter
from netgear_switch.models import VlanMode
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

_MODEL = get_model("gs110emx")
_SPEC = http_spec(_MODEL)
_PAGE = "/iss/specific/vlanMembership.html"


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


@pytest.fixture
def emx() -> Iterator[tuple[VirtualSwitch, _Recording]]:
    sw = VirtualSwitch(model="gs110emx")
    sw.state = seed_gs110emx_fw1028()
    sw.state.vlans[4].untagged = {6}  # as the web UI shows it; port 6's PVID is 4
    sw.start()
    client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
    client.login()
    try:
        yield sw, _Recording(client)
    finally:
        client.close()
        sw.stop()


def _snapshot(sw: VirtualSwitch) -> dict[int, tuple[frozenset[int], frozenset[int]]]:
    return {
        vid: (frozenset(v.member), frozenset(v.untagged))
        for vid, v in sw.state.vlans.items()
    }


def test_sets_one_port_through_all_three_modes(
    emx: tuple[VirtualSwitch, _Recording],
) -> None:
    sw, session = emx
    writer = HttpWriter(session, _MODEL)
    before, pvids = _snapshot(sw), dict(sw.state.pvids)

    writer.set_vlan_membership(90, 2, VlanMode.EXCLUDED)
    assert sw.state.vlans[90].member == set(range(1, 11)) - {2}
    writer.set_vlan_membership(90, 2, VlanMode.UNTAGGED)
    assert sw.state.vlans[90].member == set(range(1, 11))
    assert sw.state.vlans[90].untagged == {2}
    writer.set_vlan_membership(90, 2, VlanMode.TAGGED)

    # Back where it started, and nothing else ever moved.
    assert _snapshot(sw) == before
    assert sw.state.pvids == pvids


def test_wire_shape_is_the_browsers(emx: tuple[VirtualSwitch, _Recording]) -> None:
    """Select from the shown VLAN, then the Apply: ``vlanIdSel == VLAN_ID`` with
    the device's own ``hiddenMem`` changed in ONE position and ``ACTION`` empty
    (the page's ``submitForm()`` never sets it)."""
    _, session = emx
    HttpWriter(session, _MODEL).set_vlan_membership(90, 2, VlanMode.EXCLUDED)
    select = {"VLAN_ID": "90", "vlanIdSel": "1"}
    assert session.posts == [
        (_PAGE, select),
        (
            _PAGE,
            {
                "VLAN_ID": "90",
                "vlanIdSel": "90",
                "hiddenMem": "2322222222",
                "ACTION": "",
            },
        ),
        (_PAGE, select),
    ]


def test_first_vlan_is_read_with_the_get_not_a_select(
    emx: tuple[VirtualSwitch, _Recording],
) -> None:
    """VLAN 1 is what the GET already shows; "selecting" it from itself would be
    the Apply shape. Only the apply itself may be posted."""
    sw, session = emx
    HttpWriter(session, _MODEL).set_vlan_membership(1, 2, VlanMode.TAGGED)
    assert [data for _, data in session.posts] == [
        {"VLAN_ID": "1", "vlanIdSel": "1", "hiddenMem": "1211121122", "ACTION": ""}
    ]
    assert 2 not in sw.state.vlans[1].untagged


def test_device_refusal_is_raised_with_the_firmwares_own_words(
    emx: tuple[VirtualSwitch, _Recording],
) -> None:
    """Excluding a port from the VLAN its PVID names is refused by the switch;
    the caller must be told why, not handed a bare read-back mismatch."""
    sw, session = emx
    before = _snapshot(sw)
    with pytest.raises(HttpError) as exc:
        HttpWriter(session, _MODEL).set_vlan_membership(4, 6, VlanMode.EXCLUDED)
    message = str(exc.value)
    assert "You can not remove port 6 from this VLAN. Change its PVID first!" in message
    assert "vlanMembership.html" in message
    assert "VLAN 4" in message
    assert _snapshot(sw) == before


def test_unknown_vlan_is_refused_before_anything_is_posted(
    emx: tuple[VirtualSwitch, _Recording],
) -> None:
    """The page renders a VLAN the switch lacks as all-excluded, so only the
    VLAN list can say it does not exist."""
    sw, session = emx
    before = _snapshot(sw)
    with pytest.raises(HttpUnexpectedPageError, match="VLAN 4094 does not exist"):
        HttpWriter(session, _MODEL).set_vlan_membership(4094, 2, VlanMode.TAGGED)
    assert session.posts == []
    assert _snapshot(sw) == before


def test_port_outside_the_switch_is_refused_before_anything_is_posted(
    emx: tuple[VirtualSwitch, _Recording],
) -> None:
    _, session = emx
    with pytest.raises(ValueError, match="port 11"):
        HttpWriter(session, _MODEL).set_vlan_membership(90, 11, VlanMode.TAGGED)
    assert [d for _, d in session.posts if "hiddenMem" in d] == []


def test_protected_port_needs_force(emx: tuple[VirtualSwitch, _Recording]) -> None:
    _, session = emx
    writer = HttpWriter(session, _MODEL, protected_ports=frozenset({10}))
    with pytest.raises(ProtectedPortError):
        writer.set_vlan_membership(90, 10, VlanMode.EXCLUDED)
    assert session.posts == []


def test_async_writer_matches_sync() -> None:
    async def go() -> None:
        sw = VirtualSwitch(model="gs110emx")
        sw.state = seed_gs110emx_fw1028()
        sw.state.vlans[4].untagged = {6}
        sw.start()
        client = AsyncHttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
        try:
            await client.login()
            writer = AsyncHttpWriter(client, _MODEL)
            await writer.set_vlan_membership(90, 2, VlanMode.EXCLUDED)
            assert sw.state.vlans[90].member == set(range(1, 11)) - {2}
            await writer.set_vlan_membership(90, 2, VlanMode.UNTAGGED)
            assert sw.state.vlans[90].untagged == {2}
            with pytest.raises(HttpError, match="Change its PVID first"):
                await writer.set_vlan_membership(4, 6, VlanMode.EXCLUDED)
            with pytest.raises(HttpUnexpectedPageError, match="does not exist"):
                await writer.set_vlan_membership(4094, 2, VlanMode.TAGGED)
        finally:
            await client.aclose()
            sw.stop()

    asyncio.run(go())
