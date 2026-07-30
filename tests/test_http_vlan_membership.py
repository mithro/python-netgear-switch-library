"""FASTPATH VLAN-Membership page: fixture-grounded parsing + mock round trips.

Two independent kinds of evidence, deliberately kept apart:

* ``test_fixture_*`` parse the REAL captures taken 2026-07-30 from the four
  managed switches (gsm7252ps 10.1.5.22, gsm7228ps/S3300-52X 10.1.5.11,
  m4300-24x 10.1.5.13, m4300-16x 10.1.5.20:49152). Every expected value below was
  read off the live switch, and the tagged/untagged sets were cross-checked
  against that switch's own ``show vlan <id>`` output over SSH.
* ``test_mock_*`` drive the library's HTTP reader/writer against the virtual
  switch's HTTP face, which serves the same page from ``VirtualSwitchState``.
  These prove the read/write flow (including the apply flag and the
  wrong-VLAN guard), not the byte shape.

Both matter: the fixtures pin the wire format the firmware actually emits, and
the mock pins that this library's own reader and writer agree with a device that
behaves like it.
"""

from __future__ import annotations

import pathlib

import pytest

from netgear_switch.errors import HttpUnexpectedPageError, WriteVerificationError
from netgear_switch.http_read import HttpReader
from netgear_switch.http_write import HttpWriter
from netgear_switch.models import VlanMode
from netgear_switch.protocols.http import forms, parse
from netgear_switch.protocols.http.endpoints import HTTP_SPECS, http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.virtual.faces.http import VirtualHttpFace
from netgear_switch.virtual.seed import (
    seed_gsm7228ps,
    seed_gsm7252ps,
    seed_m4300_16x,
    seed_m4300_24x,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"

# The four managed models and the seed that mirrors each one.
_SEEDS = {
    "gsm7252ps": seed_gsm7252ps,
    "gsm7228ps": seed_gsm7228ps,
    "m4300-24x": seed_m4300_24x,
    "m4300-16x": seed_m4300_16x,
}


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def _needs_general_mode(state, port: int) -> bool:
    """True when this switch refuses an explicit membership apply on ``port``.

    The M4300-24X's ports are all access/trunk on the real device, so the
    write-path tests below cannot use it -- its refusal is asserted on its own in
    ``test_mock_m4300_24x_refusal_is_surfaced_verbatim``, and the identical code
    path IS exercised end to end on the 16X, gsm7252ps and gsm7228ps.
    """
    return port in state.vlan_membership_locked_ports


def _top_port(model, state) -> int:
    """The highest PHYSICAL port this switch has.

    Deliberately not ``model.port_count``: the registry gives the M4300-24X 28
    while the real switch has 24 (and its membership grid renders 24 cells), so
    port_count would address a port that does not exist.
    """
    return max(p for p in state.ports if p <= model.port_count)


# ---------------------------------------------------------------------------
# Real captures
# ---------------------------------------------------------------------------

# fixture -> (model, VLAN shown, tagged, untagged, physical ports on the grid,
#             hiddenMem slots, configured-tagged, configured-untagged)
_CAPTURES = {
    # GSM7252PS VLAN 1. `show vlan 1` on 10.1.5.22 reported 1/0/6 Tagged and
    # 1/0/8..1/0/52 Untagged as Current: Include -- exactly the tagged/untagged
    # below. Ports 1/0/50 and 1/0/51 are Current: Exclude / Configured: Include,
    # which is why they appear ONLY in the configured column.
    "gsm7252ps_vlanPortCfg_vlan1.html": (
        "gsm7252ps",
        1,
        {6},
        {8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49, 52},
        52,
        116,
        {6},
        {8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49, 50, 51, 52},
    ),
    # Same switch, VLAN 141: tagged ports 46/47/49 PLUS lag 1 and lag 2, which the
    # page writes as 0/3/1 and 0/3/2 -- those must NOT become "ports 1 and 2".
    "gsm7252ps_vlanPortCfg_vlan141.html": (
        "gsm7252ps",
        141,
        {46, 47, 49},
        set(),
        52,
        116,
        {46, 47, 49},
        {50, 51},
    ),
    # S3300-52X VLAN 5 ("net"): the Smart firmware HTML-escapes the ifName lists
    # (1&#x2F;0&#x2F;49) and its grid names ports 1/gN / 1/xgN.
    "gsm7228ps_vlanPortCfg_vlan5.html": (
        "gsm7228ps",
        5,
        {49, 50, 51, 52},
        {41},
        52,
        78,
        {49, 50, 51, 52},
        {41},
    ),
    # M4300-24X VLAN 1: hiddenTagged has this firmware's TRAILING comma
    # ("1&#x2F;0&#x2F;5,") and the LAG ifNames use slot 13 (0/13/N).
    "m4300_vlanportcfg_vlan1.html": (
        "m4300-24x",
        1,
        {5},
        {1, 2, 7, 8},
        24,
        153,
        {5},
        {1, 2, 7, 8},
    ),
    # M4300-16X VLAN 4: only this SKU's firmware carries a per-page CSRFToken.
    "m4300_16x_vlanportcfg_vlan4.html": (
        "m4300-16x",
        4,
        {9, 10, 12, 13, 14, 15, 16},
        {11},
        16,
        145,
        {9, 10, 12, 13, 14, 15, 16},
        {11},
    ),
}


@pytest.mark.parametrize("name", sorted(_CAPTURES))
def test_fixture_parses_to_the_live_values(name: str) -> None:
    (
        model_key,
        vid,
        tagged,
        untagged,
        grid_ports,
        slots,
        cfg_tagged,
        cfg_untagged,
    ) = _CAPTURES[name]
    page = parse.parse_fastpath_membership(_fixture(name))
    assert page.vlan_id == vid
    assert page.tagged_ports == frozenset(tagged)
    assert page.untagged_ports == frozenset(untagged)
    assert len(page.port_slots) == grid_ports
    assert len(page.hidden_mem.split(",")) == slots
    by_mode = {
        mode: {p for p, m in page.configured.items() if m is mode} for mode in VlanMode
    }
    assert by_mode[VlanMode.TAGGED] == set(cfg_tagged)
    assert by_mode[VlanMode.UNTAGGED] == set(cfg_untagged)
    # Every port on the grid has a code, and nothing outside the physical range.
    assert set(page.port_slots) == set(range(1, grid_ports + 1))
    # The page's own form ACTION must be the path the spec POSTs to -- otherwise
    # the writer would apply to a URL the device never advertised.
    assert page.action == HTTP_SPECS[model_key].vlan_membership_post_path


def test_fixture_lag_ifnames_are_not_mistaken_for_ports() -> None:
    """VLAN 141's tagged list is ``1/0/46,1/0/47,1/0/49,0/3/1,0/3/2``.

    ``0/3/1``/``0/3/2`` are lag 1 and lag 2. A parser matching a bare
    ``\\d+/\\d+/\\d+`` would report phantom ports 1 and 2 -- the same class of bug
    that once expanded ``lag 1 - lag 128`` into 128 ports.
    """
    page = parse.parse_fastpath_membership(
        _fixture("gsm7252ps_vlanPortCfg_vlan141.html")
    )
    assert page.tagged_ports == frozenset({46, 47, 49})
    assert 1 not in page.tagged_ports
    assert 2 not in page.tagged_ports


def test_fixture_current_and_configured_views_differ_on_real_hardware() -> None:
    """The one measured divergence, pinned so a "simplification" cannot erase it.

    GSM7252PS VLAN 1: ``show vlan 1`` lists 1/0/50 and 1/0/51 as
    ``Current: Exclude / Configured: Include``, so the page's hiddenMem grid
    includes them while its hiddenUnTagged list does not.
    """
    page = parse.parse_fastpath_membership(_fixture("gsm7252ps_vlanPortCfg_vlan1.html"))
    assert {50, 51}.isdisjoint(page.untagged_ports)
    assert page.configured[50] is VlanMode.UNTAGGED
    assert page.configured[51] is VlanMode.UNTAGGED


def test_fixture_union_of_tagged_and_untagged_is_the_member_list() -> None:
    """tagged | untagged from the membership page == vlanStatus.html's members.

    Both cells are the CURRENT view, so they must agree; this is what makes
    ``get_vlans`` internally consistent (member_ports comes from vlanStatus).
    """
    members = {
        v.vlan_id: v.member_ports
        for v in parse.parse_xe_vlans(_fixture("gsm7252ps_vlanStatus.html"))
    }
    for name in (
        "gsm7252ps_vlanPortCfg_vlan1.html",
        "gsm7252ps_vlanPortCfg_vlan141.html",
    ):
        page = parse.parse_fastpath_membership(_fixture(name))
        assert page.vlan_id is not None
        assert page.tagged_ports | page.untagged_ports == members[page.vlan_id]


def test_hidden_mem_edit_touches_exactly_one_slot() -> None:
    """A membership write must preserve every other slot verbatim -- including
    the LAG pseudo-interfaces the library does not model. (The SNMP twin of this
    rule is preserving the device's PortList width; issue #3.)"""
    page = parse.parse_fastpath_membership(_fixture("gsm7252ps_vlanPortCfg_vlan1.html"))
    edited = parse.fastpath_hidden_mem_with(page, 7, VlanMode.TAGGED)
    old = page.hidden_mem.split(",")
    new = edited.split(",")
    assert len(new) == len(old)
    changed = [i for i, (a, b) in enumerate(zip(old, new, strict=True)) if a != b]
    assert changed == [page.port_slots[7]]
    assert new[page.port_slots[7]] == "1"


def test_hidden_mem_edit_refuses_a_port_the_grid_never_showed() -> None:
    page = parse.parse_fastpath_membership(_fixture("m4300_vlanportcfg_vlan1.html"))
    with pytest.raises(HttpUnexpectedPageError, match="not on this switch"):
        parse.fastpath_hidden_mem_with(page, 99, VlanMode.TAGGED)


def test_read_form_never_carries_the_apply_flag() -> None:
    """The read POST is the browser's ``screen_refresh()``: submt stays 0, and the
    two output ifName lists are cleared. If this ever sent 16, every VLAN the
    reader paged through would be WRITTEN."""
    page = parse.parse_fastpath_membership(_fixture("gsm7252ps_vlanPortCfg_vlan1.html"))
    body = forms.fastpath_membership_form(page, vlan=141)
    assert body["submt"] == "0"
    assert body["vlanId"] == "141"
    assert body["hiddenTagged"] == ""
    assert body["hiddenUnTagged"] == ""
    assert body["hiddenMem"] == page.hidden_mem  # unchanged for a read


def test_apply_form_carries_every_field_the_page_rendered() -> None:
    """The M4300-16X answers 403 to a POST that drops its per-page CSRFToken, so
    the form must be built from the page's own field set, not a curated subset."""
    page = parse.parse_fastpath_membership(_fixture("m4300_16x_vlanportcfg_vlan4.html"))
    body = forms.fastpath_membership_form(
        page, vlan=4, hidden_mem=page.hidden_mem, apply=True
    )
    assert body["submt"] == "16"
    assert body["CSRFToken"] == page.fields["CSRFToken"]
    assert set(page.fields) <= set(body)


def test_every_managed_model_advertises_both_membership_paths() -> None:
    """Parity gate: the managed models must all expose the page, and the M4300
    pair must expose it under their /v1 prefix."""
    for key in _SEEDS:
        spec = HTTP_SPECS[key]
        assert spec.vlan_membership_path is not None, key
        assert spec.vlan_membership_post_path is not None, key
        prefix = "/v1" if key.startswith("m4300") else ""
        assert (
            spec.vlan_membership_path
            == f"{prefix}/switching/dot1q/vlan_port_cfg.html"
        )
        assert (
            spec.vlan_membership_post_path
            == f"{prefix}/switching/dot1q/vlan_port_cfg_rw.html"
        )


# ---------------------------------------------------------------------------
# Mock round trips
# ---------------------------------------------------------------------------


@pytest.fixture(params=sorted(_SEEDS))
def managed(request):
    """A running virtual HTTP face + a logged-in library client, per model."""
    key = request.param
    model = get_model(key)
    state = _SEEDS[key]()
    spec = http_spec(model)
    face = VirtualHttpFace(state, spec, password="password")
    port = face.start()
    client = HttpClient(f"127.0.0.1:{port}", "password", spec)
    try:
        yield key, model, state, client
    finally:
        client.close()
        face.stop()


def test_mock_get_vlans_reports_tagged_and_untagged(managed) -> None:
    """The defect this change closes: ``get_vlans`` used to return
    ``untagged_ports=frozenset()`` for every VLAN on every managed model."""
    key, model, state, client = managed
    vlans = HttpReader(client, model).get_vlans()
    assert vlans, key
    assert any(v.untagged_ports for v in vlans), key
    for v in vlans:
        vsim = state.vlans[v.vlan_id]
        physical = {p for p in vsim.member if p <= model.port_count}
        assert v.tagged_ports | v.untagged_ports == physical, (key, v.vlan_id)
        assert v.untagged_ports == {p for p in physical if p in vsim.untagged}
        assert v.tagged_ports.isdisjoint(v.untagged_ports)


def test_mock_get_vlans_member_ports_equal_the_egress_union(managed) -> None:
    """Internal consistency: vlanStatus's Member Ports cell and the membership
    page's two ifName lists are the same (current) view of the device."""
    key, model, _state, client = managed
    for v in HttpReader(client, model).get_vlans():
        assert v.member_ports == v.tagged_ports | v.untagged_ports, (key, v.vlan_id)


def test_mock_read_does_not_mutate_state(managed) -> None:
    """Reading every VLAN must leave the device untouched -- the read POSTs go to
    the same ``_rw.html`` endpoint an apply does, and only ``submt`` separates
    them. On hardware this was proven by re-reading a VLAN and diffing."""
    _key, model, state, client = managed
    before = {
        vid: (set(v.member), set(v.untagged), set(v.configured_only))
        for vid, v in state.vlans.items()
    }
    HttpReader(client, model).get_vlans()
    after = {
        vid: (set(v.member), set(v.untagged), set(v.configured_only))
        for vid, v in state.vlans.items()
    }
    assert after == before


def test_mock_set_vlan_membership_round_trip(managed) -> None:
    """Write each of the three modes and read it back through the HTTP backend
    only -- no other protocol is consulted."""
    _key, model, state, client = managed
    writer = HttpWriter(client, model)
    reader = HttpReader(client, model)
    vid = max(state.vlans)  # never VLAN 1, so the default VLAN is left alone
    # The HIGHEST port the switch actually has -- not model.port_count, which the
    # registry sets to 28 on the M4300-24X while the device renders 24 cells.
    # Using the top port also pins the slot mapping at the far end of hiddenMem,
    # where an off-by-one would land in the LAG region.
    port = _top_port(model, state)
    if _needs_general_mode(state, port):
        pytest.skip("this switch's ports are access/trunk -- see the refusal test")
    for mode in (VlanMode.TAGGED, VlanMode.UNTAGGED, VlanMode.EXCLUDED):
        writer.set_vlan_membership(vid, port, mode)
        page = reader.read_fastpath_membership(vid)
        assert page.configured[port] is mode
        if mode is VlanMode.EXCLUDED:
            assert port not in state.vlans[vid].member
        else:
            assert port in state.vlans[vid].member
            assert (port in state.vlans[vid].untagged) is (mode is VlanMode.UNTAGGED)


def test_mock_set_vlan_membership_preserves_other_ports(managed) -> None:
    _key, model, state, client = managed
    vid = max(state.vlans)
    port = _top_port(model, state)
    if _needs_general_mode(state, port):
        pytest.skip("this switch's ports are access/trunk -- see the refusal test")
    others = {
        p: (p in state.vlans[vid].member, p in state.vlans[vid].untagged)
        for p in state.ports
        if p != port and p <= model.port_count
    }
    HttpWriter(client, model).set_vlan_membership(vid, port, VlanMode.TAGGED)
    for p, expected in others.items():
        actual = (p in state.vlans[vid].member, p in state.vlans[vid].untagged)
        assert actual == expected, p


def test_mock_set_vlan_membership_preserves_lag_slots(managed) -> None:
    """A LAG that was a VLAN member must still be one after a port write.

    The mock renders the LAG pseudo-interfaces into hiddenMem after the physical
    ports, so a writer that rebuilt the string from the physical ports alone
    would silently drop them here.
    """
    _key, model, state, client = managed
    vid = next(
        (
            v
            for v, sim in sorted(state.vlans.items())
            if any(p > model.port_count for p in sim.member)
        ),
        None,
    )
    if vid is None:
        pytest.skip("this seed has no VLAN with LAG members")
    if _needs_general_mode(state, 1):
        pytest.skip("this switch's ports are access/trunk -- see the refusal test")
    lags_before = {p for p in state.vlans[vid].member if p > model.port_count}
    HttpWriter(client, model).set_vlan_membership(vid, 1, VlanMode.TAGGED)
    assert {
        p for p in state.vlans[vid].member if p > model.port_count
    } == lags_before


def test_mock_writer_verifies_and_raises_when_the_device_ignores_it(
    managed, monkeypatch
) -> None:
    """Verify-after-write must actually fail loudly.

    Simulated by making the apply POST a no-op (the shape of a rejected write:
    HTTP 200 with the page unchanged), which is what a wrong field name or a
    missing token looks like on this firmware.
    """
    _key, model, state, client = managed
    writer = HttpWriter(client, model)
    vid = max(state.vlans)
    port = _top_port(model, state)
    # Ask for a mode this port is NOT already in, or the "write" would be a no-op
    # and verification would pass for the wrong reason.
    if _needs_general_mode(state, port):
        pytest.skip("this switch's ports are access/trunk -- see the refusal test")
    current = HttpReader(client, model).read_fastpath_membership(vid).configured[port]
    target = VlanMode.EXCLUDED if current is not VlanMode.EXCLUDED else VlanMode.TAGGED
    real_post = client.post_form

    def swallow(path: str, data: dict[str, str]) -> str:
        if data.get("submt") == "16":
            return real_post(path, {**data, "submt": "0"})
        return real_post(path, data)

    monkeypatch.setattr(client, "post_form", swallow)
    with pytest.raises(WriteVerificationError, match="did not read back"):
        writer.set_vlan_membership(vid, port, target)


def test_mock_m4300_24x_refusal_is_surfaced_verbatim() -> None:
    """The M4300-24X's real refusal, reproduced by the mock and reported as-is.

    On 10.1.5.13 every port is ``switchport mode access``/``trunk``, and the
    M4300 image only accepts explicit VLAN membership on a ``general``-mode port.
    The web UI answers HTTP 200 with ``err_flag=1`` and
    ``err_msg="Unable to set VLAN membership for VLAN ( 4004 )"``. Before the
    err_flag check the only symptom was a generic verify-after-write failure,
    which hid the reason -- and the reason is what the caller needs.
    """
    from netgear_switch.errors import HttpError

    model = get_model("m4300-24x")
    state = seed_m4300_24x()
    assert 8 in state.vlan_membership_locked_ports
    spec = http_spec(model)
    face = VirtualHttpFace(state, spec, password="password")
    port = face.start()
    client = HttpClient(f"127.0.0.1:{port}", "password", spec)
    try:
        vid = max(state.vlans)
        before = HttpReader(client, model).read_fastpath_membership(vid)
        with pytest.raises(HttpError, match="Unable to set VLAN membership"):
            HttpWriter(client, model).set_vlan_membership(vid, 8, VlanMode.UNTAGGED)
        # A refused apply must leave the device untouched.
        after = HttpReader(client, model).read_fastpath_membership(vid)
        assert after.configured == before.configured
    finally:
        client.close()
        face.stop()


def test_mock_m4300_16x_accepts_what_the_24x_refuses() -> None:
    """Same code path, same page, same firmware family -- different per-port
    switchport mode. Live-proven: the 16X's ports 1-8 carry no ``switchport mode``
    line and the identical apply succeeded on 10.1.5.20:49152."""
    model = get_model("m4300-16x")
    state = seed_m4300_16x()
    assert state.vlan_membership_locked_ports == frozenset()
    spec = http_spec(model)
    face = VirtualHttpFace(state, spec, password="password")
    port = face.start()
    client = HttpClient(f"127.0.0.1:{port}", "password", spec)
    try:
        vid = max(state.vlans)
        HttpWriter(client, model).set_vlan_membership(vid, 1, VlanMode.UNTAGGED)
        page = HttpReader(client, model).read_fastpath_membership(vid)
        assert page.configured[1] is VlanMode.UNTAGGED
    finally:
        client.close()
        face.stop()


def test_mock_reader_refuses_a_page_showing_another_vlan(managed) -> None:
    """The firmware answers a rejected VLAN-select by re-rendering whichever VLAN
    was already showing. Asking for a VLAN the switch does not have exercises
    exactly that path, and the reader must refuse rather than mislabel it."""
    _key, model, state, client = managed
    absent = max(state.vlans) + 1000
    with pytest.raises(HttpUnexpectedPageError, match="refusing to report"):
        HttpReader(client, model).read_fastpath_membership(absent)


def test_mock_configured_only_ports_are_absent_from_the_current_lists() -> None:
    """The seeded GSM7252PS divergence, end to end through the mock's HTTP face.

    Ports 50/51 are ``Configured: Include / Current: Exclude`` on the real
    switch, so the HTTP reader (which reports the CURRENT view) must not list
    them, while the page's configured grid must.
    """
    model = get_model("gsm7252ps")
    state = seed_gsm7252ps()
    assert state.vlans[1].configured_only == {50, 51}
    spec = http_spec(model)
    face = VirtualHttpFace(state, spec, password="password")
    port = face.start()
    client = HttpClient(f"127.0.0.1:{port}", "password", spec)
    try:
        reader = HttpReader(client, model)
        vlan1 = next(v for v in reader.get_vlans() if v.vlan_id == 1)
        assert {50, 51}.isdisjoint(vlan1.untagged_ports)
        assert {50, 51}.isdisjoint(vlan1.member_ports)
        page = reader.read_fastpath_membership(1)
        assert page.configured[50] is VlanMode.UNTAGGED
        assert page.configured[51] is VlanMode.UNTAGGED
    finally:
        client.close()
        face.stop()


def test_mock_snmp_static_egress_keeps_the_configured_ports() -> None:
    """The other half of the same finding: SNMP's dot1qVlanStaticEgressPorts is
    the CONFIGURED table, so it DOES include 50/51 -- which is why HTTP and SNMP
    legitimately disagree here and neither is wrong."""
    from netgear_switch.protocols.snmp import oids
    from netgear_switch.protocols.snmp.parse import decode_port_bitmap

    state = seed_gsm7252ps()
    raw = state.oid_map()[f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.1"][1]
    members = set(decode_port_bitmap(raw.encode("latin-1")))
    assert {50, 51} <= members
