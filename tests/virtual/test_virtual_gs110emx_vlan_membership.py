"""The virtual GS110EMX's vlanMembership.html must answer like the real one.

Everything asserted here was MEASURED on real hardware on 2026-10-14, firmware
1.0.2.8: the request rule on gs110emx1/2/3 (10.1.5.25-27), the apply and its
refusal on gs110emx1 against throwaway VLAN 4001 and link-down port 2. The mock
used to answer ANY ``VLAN_ID`` POST with a full page, which is how a select the
real switch answers with nothing (issue #16) stayed green here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from netgear_switch.http_read import AsyncHttpReader, HttpReader
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
_PAGE = "/iss/specific/vlanMembership.html"
_VIDS = (1, 4, 5, 6, 7, 10, 20, 21, 41, 90, 99, 121)


@pytest.fixture
def emx() -> Iterator[tuple[VirtualSwitch, HttpClient]]:
    sw = VirtualSwitch(model="gs110emx")
    sw.state = seed_gs110emx_fw1028()
    # The seed's VLAN table was read over NSDP, which reports port 6 TAGGED in
    # VLAN 4. That switch's own web UI shows it UNTAGGED there (hiddenMem
    # "2222212222", and port 6's PVID is 4), and these tests compare against
    # web-UI captures, so the web UI's answer is used here.
    sw.state.vlans[4].untagged = {6}
    sw.start()
    client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
    client.login()
    try:
        yield sw, client
    finally:
        client.close()
        sw.stop()


def _capture(vid: int, token: str) -> str:
    text = (_FIX / f"gs110emx_fw1028_vlanmembership_vlan{vid}.html").read_text()
    return text.replace("GAMBITTOKEN", token)


def _post(client: HttpClient, **fields: str) -> str:
    return client.post_form(_PAGE, fields)


def test_get_renders_the_first_vlan_byte_for_byte(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    _, client = emx
    assert client.get_page(_PAGE) == _capture(1, client._token)


@pytest.mark.parametrize("vid", _VIDS[1:])
def test_select_renders_each_vlan_byte_for_byte(
    emx: tuple[VirtualSwitch, HttpClient], vid: int
) -> None:
    """``vlanIdSel`` = the VLAN the page was showing (the browser's dropdown
    change) renders the requested VLAN, identically to the real capture."""
    _, client = emx
    assert _post(client, VLAN_ID=str(vid), vlanIdSel="1") == _capture(
        vid, client._token
    )


def test_select_is_not_remembered_by_the_next_get(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    _, client = emx
    _post(client, VLAN_ID="90", vlanIdSel="1")
    assert parse.parse_gs110emx_shown_vlan(client.get_page(_PAGE)) == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"VLAN_ID": "4", "vlanIdSel": "4"},  # the Apply shape, nothing to apply
        {"VLAN_ID": "1", "vlanIdSel": "1"},  # ...even for the VLAN a GET shows
        {"VLAN_ID": "4", "vlanIdSel": "0"},
        {"VLAN_ID": "4", "vlanIdSel": ""},
        {"VLAN_ID": "4"},
    ],
)
def test_refused_request_shapes_answer_an_empty_body(
    emx: tuple[VirtualSwitch, HttpClient], fields: dict[str, str]
) -> None:
    _, client = emx
    assert _post(client, **fields) == ""


def test_select_from_any_other_vlan_works(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    """``vlanIdSel`` need not be the VLAN a GET shows -- only a real id that is
    not ``VLAN_ID`` (measured: VLAN_ID=4 vlanIdSel=5, and VLAN_ID=1 vlanIdSel=4)."""
    _, client = emx
    assert (
        parse.parse_gs110emx_shown_vlan(_post(client, VLAN_ID="4", vlanIdSel="5")) == 4
    )
    assert (
        parse.parse_gs110emx_shown_vlan(_post(client, VLAN_ID="1", vlanIdSel="4")) == 1
    )


def test_selecting_a_vlan_the_switch_lacks_renders_all_excluded(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    """Measured with VLAN 4094: a full page, ``vlanIdSel`` echoing the request,
    every port excluded. The page alone therefore cannot tell a caller the VLAN
    does not exist."""
    _, client = emx
    page = _post(client, VLAN_ID="4094", vlanIdSel="1")
    assert parse.parse_gs110emx_shown_vlan(page) == 4094
    assert parse.parse_hidden_mem(page, page="vlanMembership.html") == "3333333333"


def test_select_carrying_hiddenmem_applies_nothing(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    """The browser's dropdown change posts the whole form, ``hiddenMem`` of the
    VLAN it was showing included. Measured: VLAN 1's codes posted at VLAN 4001
    left VLAN 4001 untouched."""
    sw, client = emx
    before = {
        vid: (set(v.member), set(v.untagged)) for vid, v in sw.state.vlans.items()
    }
    page = _post(client, VLAN_ID="90", vlanIdSel="1", hiddenMem="1111121122", ACTION="")
    assert page == _capture(90, client._token)
    assert before == {
        vid: (set(v.member), set(v.untagged)) for vid, v in sw.state.vlans.items()
    }


def test_apply_changes_only_that_vlan(emx: tuple[VirtualSwitch, HttpClient]) -> None:
    sw, client = emx
    others = {
        vid: (set(v.member), set(v.untagged))
        for vid, v in sw.state.vlans.items()
        if vid != 90
    }
    pvids = dict(sw.state.pvids)
    page = _post(
        client, VLAN_ID="90", vlanIdSel="90", hiddenMem="2322222222", ACTION=""
    )
    assert parse.parse_gs110emx_err_msg(page) == ""
    assert parse.parse_hidden_mem(page, page="vlanMembership.html") == "2322222222"
    assert 2 not in sw.state.vlans[90].member
    page = _post(
        client, VLAN_ID="90", vlanIdSel="90", hiddenMem="2122222222", ACTION=""
    )
    assert parse.parse_hidden_mem(page, page="vlanMembership.html") == "2122222222"
    assert sw.state.vlans[90].untagged == {2}
    assert sw.state.pvids == pvids
    assert others == {
        vid: (set(v.member), set(v.untagged))
        for vid, v in sw.state.vlans.items()
        if vid != 90
    }


def test_apply_refuses_to_exclude_a_port_from_its_pvid_vlan(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    """Measured on gs110emx1 with port 2's PVID at 4001: excluding it from 4001
    left the membership alone and set ``errMsg``; making it TAGGED instead was
    accepted. Port 6's PVID is 4 on this seed."""
    sw, client = emx
    page = _post(client, VLAN_ID="4", vlanIdSel="4", hiddenMem="2222232222", ACTION="")
    assert parse.parse_gs110emx_err_msg(page) == (
        "You can not remove port 6 from this VLAN. Change its PVID first!"
    )
    assert parse.parse_hidden_mem(page, page="vlanMembership.html") == "2222212222"
    assert sw.state.vlans[4].untagged == {6}
    page = _post(client, VLAN_ID="4", vlanIdSel="4", hiddenMem="2222222222", ACTION="")
    assert parse.parse_gs110emx_err_msg(page) == ""
    assert sw.state.vlans[4].untagged == set()


def test_reader_get_vlans_end_to_end(emx: tuple[VirtualSwitch, HttpClient]) -> None:
    """The reader against the faithful mock: every VLAN, each with its own
    membership -- the read issue #16 reported as failing on real switches."""
    _, client = emx
    vlans = {v.vlan_id: v for v in HttpReader(client, _MODEL).get_vlans()}
    assert set(vlans) == set(_VIDS)
    assert vlans[1].untagged_ports == frozenset({1, 2, 3, 4, 5, 7, 8})
    assert vlans[1].tagged_ports == frozenset({6, 9, 10})
    assert vlans[4].untagged_ports == frozenset({6})
    assert vlans[90].tagged_ports == frozenset(range(1, 11))


def test_async_reader_get_vlans_matches_sync(
    emx: tuple[VirtualSwitch, HttpClient],
) -> None:
    sw, client = emx
    expected = HttpReader(client, _MODEL).get_vlans()

    async def go() -> list[object]:
        aclient = AsyncHttpClient(f"127.0.0.1:{sw.http_port}", "password", _SPEC)
        try:
            await aclient.login()
            return list(await AsyncHttpReader(aclient, _MODEL).get_vlans())
        finally:
            await aclient.aclose()

    assert asyncio.run(go()) == expected
