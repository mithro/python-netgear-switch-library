# tests/virtual/test_switchport_vlan_write.py
"""VLAN membership writes on a FASTPATH switchport-dialect model (the M4300s).

Every behaviour asserted here was established on REAL hardware. The original
round came from an M4300-24X @10.1.5.13 (firmware 12.0.13.8) by capturing a full
snmpwalk, changing the VLAN through the switch's own CLI, re-walking and diffing.
The PRECISE semantics below were then measured on 2026-07-30 by writing the vendor
columns over SNMP and re-reading the Q-BRIDGE mirrors after every single step, on
BOTH SKUs -- m4300-24x @10.1.5.13 port 1/0/8 and m4300-16x @10.1.5.20 port 1/0/1
(both link-down, undescribed), using throwaway VLANs 4007/4008 and restoring the
recorded baseline afterwards:

* ``access(1)``  -> untagged member of the access VLAN (col3) and NOTHING else.
* ``trunk(2)``   -> untagged member of the native VLAN (col4) plus a TAGGED member
  of ``(allowed(col6) INTERSECT existing VLANs) - {native}``, and the PVID becomes
  the native VLAN. The native VLAN is an untagged member EVEN WHEN it is not in
  the allowed list.
* ``general(3)`` -> membership is the col7/col8 participation lists, which answer
  notWritable, so general mode cannot be driven over SNMP.
* col4 (native VLAN) IS writable, but only to an EXISTING VLAN in 1..4093: 0, 4094
  and a deleted VLAN id all answered commitFailed -- so "untagged in no VLAN" is
  not expressible on this hardware.
* ``dot1qVlanStaticEgressPorts`` is writable only while NO interface on the switch
  is in access mode; ``dot1qVlanStaticUntaggedPorts`` returns noError and then
  silently discards the write.

The mock emulates all of it, so these are real regression tests rather than
assertions about the mock's own invention.
"""
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import UnsupportedCapabilityError, WriteVerificationError
from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
from netgear_switch.snmp_write import (
    AsyncSnmpWriter,
    SnmpWriter,
    decode_vlan_bitmap,
)
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "m4300-24x"
# Real ifIndexes from the committed m4300-24x capture. Deliberately NOT
# min()/max() of state.ports: that dict also holds the CPU interface, LAG and
# VLAN-interface pseudo-ports (769-771, 898-899), so max() is not a switch port.
_TRUNK_PORT = 1  # 1/0/1, a real uplink trunk: untagged in 1, TAGGED in 12 VLANs
_ACCESS_PORT = 24  # 1/0/24, access VLAN 10, tagged nowhere


def _sync_clients(sw: VirtualSwitch) -> tuple[SnmpReader, SnmpWriter]:
    """SNMP reader+writer driven DIRECTLY -- never through the SyncSwitch facade,
    whose per-backend dispatch would make a pass here prove nothing about SNMP."""
    client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
    model = get_model(_MODEL)
    return SnmpReader(client, model), SnmpWriter(client, model)


def _membership(reader: SnmpReader, port: int) -> tuple[set[int], set[int]]:
    """(tagged, untagged) VLAN ids for ``port``, read from the Q-BRIDGE mirrors."""
    vlans = reader.get_vlans()
    return (
        {v.vlan_id for v in vlans if port in v.tagged_ports},
        {v.vlan_id for v in vlans if port in v.untagged_ports},
    )


def _in_general_mode(
    sw: VirtualSwitch, port: int, *, untagged: set[int], tagged: set[int]
) -> None:
    """Put ``port`` in general mode with an explicit participation config.

    Must run BEFORE ``sw.start()``: the SNMP face's MIB view snapshots the OID map
    at bind time and only rebuilds after a write through the face, so a direct
    state edit afterwards would not be visible to reads. Set directly because
    that is the honest shape of the device -- columns 7/8 answer notWritable, so
    there is deliberately no SNMP path to configure this.
    """
    sw.state.switchport_mode[port] = oids.SWITCHPORT_MODE_GENERAL
    sw.state.switchport_general_untagged[port] = set(untagged)
    sw.state.switchport_general_tagged[port] = set(tagged)
    sw.state._apply_switchport(port)


def test_model_declares_the_switchport_write_dialect() -> None:
    """Both M4300 SKUs run FASTPATH 12.x, whose Q-BRIDGE PortLists cannot carry a
    membership write; every other SNMP model keeps the standard qbridge dialect.

    The -16X is no longer an inference from the -24X: see the registry comment for
    the live A/B/A that settled it.
    """
    assert get_model("m4300-24x").snmp_vlan_write == "fastpath_switchport"
    assert get_model("m4300-16x").snmp_vlan_write == "fastpath_switchport"
    assert get_model("gsm7252ps").snmp_vlan_write == "qbridge"
    assert get_model("gsm7228ps").snmp_vlan_write == "qbridge"


def test_qbridge_egress_write_is_rejected_while_a_port_is_in_access_mode() -> None:
    """The INVALID write: a raw SET of dot1qVlanStaticEgressPorts must fail.

    Live A/B/A on m4300-16x port 1/0/1 (byte-identical writes to a throwaway VLAN,
    flipping only that port's mode) gave general->noError, access->commitFailed,
    general->noError, trunk->noError, access->commitFailed, general->noError. So
    ONE access-mode interface anywhere makes the whole column read-only -- which is
    also why the -24X, 21 of whose 24 ports are access-mode, rejects it always.
    A mock that accepted this would hide exactly the divergence that sent me
    chasing a non-existent bug.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = min(sw.state.vlans)
        rows = client.get([f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"])
        identical = rows[0].value
        assert isinstance(identical, bytes)
        assert sw.state._access_mode_ports, "mock ports default to access mode"
        # Writing back the EXACT bytes the device just reported still fails.
        with pytest.raises(SnmpError):
            client.set(
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", identical, "x")
            )
    finally:
        sw.stop()


def test_qbridge_egress_write_is_accepted_once_no_port_is_in_access_mode() -> None:
    """The other half of the live A/B/A: with every port off access mode the very
    same byte-identical write is ACCEPTED, and a real one is folded back into the
    switchport columns (on the -16X a trunk port's allowed list gained the VLAN)."""
    sw = VirtualSwitch(model=_MODEL)
    vid = max(sw.state.vlans)
    port = _TRUNK_PORT
    for p in sw.state.ports:
        sw.state.switchport_mode[p] = oids.SWITCHPORT_MODE_TRUNK
        sw.state.switchport_native_vlan[p] = min(sw.state.vlans)
        sw.state._apply_switchport(p)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        assert not sw.state._access_mode_ports
        raw = client.get([f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"])[0].value
        assert isinstance(raw, bytes)
        client.set(SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", raw, "x"))
        # And a REAL write reconciles into the vendor allowed-VLAN column.
        from netgear_switch.protocols.snmp.parse import decode_port_bitmap
        from netgear_switch.protocols.snmp.write import encode_port_bitmap

        members = set(decode_port_bitmap(raw)) | {port}
        client.set(
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}",
                encode_port_bitmap(members, len(raw)),
                "x",
            )
        )
        allowed = client.get(
            [f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}"]
        )[0].value
        assert isinstance(allowed, bytes)
        assert vid in decode_vlan_bitmap(allowed)
    finally:
        sw.stop()


def test_qbridge_untagged_write_is_accepted_and_silently_ignored() -> None:
    """PROVEN live on the -24X: SET dot1qVlanStaticUntaggedPorts.4007 := {port 8}
    returned noError while the column still read back [] afterwards -- in the same
    session where the EGRESS column commitFailed. A mock that raised here would
    let the library "succeed" against a device that applied nothing, so it no-ops
    and leaves write verification to catch it."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        from netgear_switch.protocols.snmp.parse import decode_port_bitmap
        from netgear_switch.protocols.snmp.write import encode_port_bitmap

        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = max(sw.state.vlans)
        port = _TRUNK_PORT
        oid = f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"
        raw = client.get([oid])[0].value
        assert isinstance(raw, bytes)
        before = set(decode_port_bitmap(raw))
        assert port not in before
        client.set(SetVarbind(oid, encode_port_bitmap(before | {port}, len(raw)), "x"))
        after = client.get([oid])[0].value
        assert isinstance(after, bytes)
        assert set(decode_port_bitmap(after)) == before, "must be silently discarded"
    finally:
        sw.stop()


def test_per_port_vlan_bitmaps_are_read_only() -> None:
    """The switchport tagged/untagged VLAN bitmaps answer notWritable live -- in
    EVERY mode, general included (re-confirmed on the -24X with the port switched
    to general(3), which is why general mode cannot be driven over SNMP)."""
    for mode in (
        oids.SWITCHPORT_MODE_ACCESS,
        oids.SWITCHPORT_MODE_TRUNK,
        oids.SWITCHPORT_MODE_GENERAL,
    ):
        sw = VirtualSwitch(model=_MODEL)
        port = _ACCESS_PORT
        sw.state.switchport_mode[port] = mode
        sw.start()
        try:
            client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
            for base in (
                oids.FASTPATH_SWITCHPORT_TAGGED_VLANS,
                oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS,
            ):
                rows = client.get([f"{base}.{port}"])
                cur = rows[0].value
                assert isinstance(cur, bytes)
                assert len(cur) == oids.SWITCHPORT_VLAN_BITMAP_BYTES
                with pytest.raises(SnmpError):
                    client.set(SetVarbind(f"{base}.{port}", cur, "x"))
        finally:
            sw.stop()


@pytest.mark.parametrize("model", ["m4300-24x", "m4300-16x"])
def test_seeded_switchport_columns_reproduce_the_captured_membership(
    model: str,
) -> None:
    """MOCK FIDELITY, the independent-source-of-truth check (principle 5).

    The seeds carry TWO separately-measured things: the VLAN membership from the
    committed hardware capture, and the vendor switchport columns read off the real
    switch. Nothing computes one from the other at seed time. So re-deriving
    membership from the columns and getting the captured membership back -- byte for
    byte, PVIDs included, for every physical port on both SKUs -- can only happen if
    ``_apply_switchport``'s rule is the one the hardware actually implements.

    This is what catches a wrong rule: modelling trunk as "tagged in every allowed
    VLAN, untagged nowhere" (the previous version) makes port 1/0/1 untagged nowhere
    and port 1/0/5 a member of VLANs its allowed list excludes, and both show up
    here immediately.
    """
    from netgear_switch.virtual.server import _build_state

    state = _build_state(model)
    before = {v: (set(s.member), set(s.untagged)) for v, s in state.vlans.items()}
    pvids_before = dict(state.pvids)
    physical = sorted(p for p, s in state.ports.items() if s.if_type == 6)
    assert physical, "seed must have physical ports"
    for port in physical:
        state._apply_switchport(port)
    after = {v: (set(s.member), set(s.untagged)) for v, s in state.vlans.items()}
    assert after == before, "derived membership must equal the captured membership"
    assert {p: state.pvids[p] for p in physical} == {
        p: pvids_before[p] for p in physical
    }


def test_live_switchport_columns_derive_the_live_membership() -> None:
    """Replay the two most informative REAL rows the seeds cannot carry.

    m4300-16x ports 1/0/11 and 1/0/12 were re-homed on the live device after the
    committed capture was taken, so the seed keeps the capture's shape. Their live
    columns are replayed here against the membership the switch itself reported for
    them on 2026-07-30 -- port 12 being the case that proves a native VLAN is an
    untagged member even though it is ABSENT from the allowed list.
    """
    from netgear_switch.virtual.seed import seed_m4300_16x

    existing = {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
    others = existing - {1, 4, 5}
    cases = (
        # port, mode, access, native, allowed, want_untagged, want_tagged
        (11, oids.SWITCHPORT_MODE_TRUNK, 4, 4, existing, {4}, existing - {4}),
        (
            12,
            oids.SWITCHPORT_MODE_TRUNK,
            5,
            5,
            existing - {5},  # native 5 deliberately NOT allowed
            {5},
            {1, 4} | others,
        ),
    )
    for port, mode, access, native, allowed, want_u, want_t in cases:
        state = seed_m4300_16x()
        assert set(state.vlans) == existing
        state.switchport_mode[port] = mode
        state.switchport_access_vlan[port] = access
        state.switchport_native_vlan[port] = native
        from netgear_switch.virtual.state import _vlan_bitmap_bytes

        state.switchport_allowed_vlans[port] = _vlan_bitmap_bytes(set(allowed))
        state._apply_switchport(port)
        got_u = {v for v, s in state.vlans.items() if port in s.untagged}
        got_t = {
            v
            for v, s in state.vlans.items()
            if port in s.member and port not in s.untagged
        }
        assert got_u == want_u, f"port {port} untagged"
        assert got_t == want_t, f"port {port} tagged"
        assert state.pvids[port] == native


def test_switchport_columns_serve_the_values_read_off_the_real_switch() -> None:
    """The vendor columns the mock answers ARE the ones walked off 10.1.5.13.

    Port 1/0/24: access(1) on VLAN 10, native VLAN 10, all 4093 VLANs allowed,
    participation columns untagged=[1] / tagged=[]. Port 1/0/5 is the interesting
    row -- a trunk whose access VLAN (90) differs from its native VLAN (5) with a
    genuinely sparse allowed list, which is what proves trunk membership follows
    col4 and col6 rather than col3.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")

        def col(base: str, port: int) -> object:
            return client.get([f"{base}.{port}"])[0].value

        assert col(oids.FASTPATH_SWITCHPORT_MODE, 24) == oids.SWITCHPORT_MODE_ACCESS
        assert col(oids.FASTPATH_SWITCHPORT_ACCESS_VLAN, 24) == 10
        assert col(oids.FASTPATH_SWITCHPORT_NATIVE_VLAN, 24) == 10
        allowed = col(oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS, 24)
        assert isinstance(allowed, bytes)
        assert decode_vlan_bitmap(allowed) == frozenset(range(1, 4094))
        col7 = col(oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS, 24)
        col8 = col(oids.FASTPATH_SWITCHPORT_TAGGED_VLANS, 24)
        assert isinstance(col7, bytes)
        assert isinstance(col8, bytes)
        assert decode_vlan_bitmap(col7) == frozenset({1})
        assert decode_vlan_bitmap(col8) == frozenset()

        # 1/0/5: access VLAN 90 but NATIVE VLAN 5, sparse allowed list.
        assert col(oids.FASTPATH_SWITCHPORT_MODE, 5) == oids.SWITCHPORT_MODE_TRUNK
        assert col(oids.FASTPATH_SWITCHPORT_ACCESS_VLAN, 5) == 90
        assert col(oids.FASTPATH_SWITCHPORT_NATIVE_VLAN, 5) == 5
        allowed5 = col(oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS, 5)
        assert isinstance(allowed5, bytes)
        assert decode_vlan_bitmap(allowed5) == frozenset(
            {1, 5, 6, 7, 10, 20, 41, 90, 99, 121, 141}
        )
        # ...and the membership that follows is untagged in 5 (the native), NOT 90.
        reader, _ = _sync_clients(sw)
        tagged, untagged = _membership(reader, 5)
        assert untagged == {5}
        assert tagged == {1, 6, 7, 10, 20, 41, 90, 99, 121, 141}
    finally:
        sw.stop()


def test_switchport_columns_are_not_a_mirror_of_effective_membership() -> None:
    """col7/col8 are the GENERAL-mode config, INDEPENDENT of what the port really
    carries. Live proof: m4300-24x port 1/0/15 is an access port on VLAN 10 (so
    untagged in 10) while its column 7 still read VLAN 1."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = max(sw.state.vlans)
        port = _ACCESS_PORT
        writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
        _, untagged = _membership(reader, port)
        assert untagged == {vid}
        col7 = client.get(
            [f"{oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS}.{port}"]
        )[0].value
        assert isinstance(col7, bytes)
        assert decode_vlan_bitmap(col7) == frozenset({1}) != untagged
    finally:
        sw.stop()


def test_trunk_untags_the_native_vlan_even_when_it_is_not_allowed() -> None:
    """VERIFIED live: with native = 1, removing VLAN 1 from the allowed list left
    the port an UNTAGGED member of VLAN 1 regardless."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, _ = _sync_clients(sw)
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        port = _ACCESS_PORT
        native = min(sw.state.vlans)
        other = max(sw.state.vlans)
        from netgear_switch.snmp_write import _vlan_bitmap

        client.set(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}",
                _vlan_bitmap({other}),  # native deliberately NOT allowed
                "x",
            )
        )
        client.set(
            SetVarbind(f"{oids.FASTPATH_SWITCHPORT_NATIVE_VLAN}.{port}", native, "u")
        )
        client.set(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}",
                oids.SWITCHPORT_MODE_TRUNK,
                "i",
            )
        )
        tagged, untagged = _membership(reader, port)
        assert untagged == {native}
        assert tagged == {other}
        assert dict(reader.get_pvids())[port] == native
    finally:
        sw.stop()


def test_native_vlan_must_be_an_existing_vlan() -> None:
    """col4 := 0, := 4094 and := a non-existent VLAN ALL commitFailed live, which
    is why "untagged in no VLAN" is unreachable on this hardware."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        port = _TRUNK_PORT
        absent = 4007
        assert absent not in sw.state.vlans
        for bad in (0, 4094, absent):
            with pytest.raises(SnmpError):
                client.set(
                    SetVarbind(
                        f"{oids.FASTPATH_SWITCHPORT_NATIVE_VLAN}.{port}", bad, "u"
                    )
                )
    finally:
        sw.stop()


def test_set_vlan_membership_untagged_via_switchport() -> None:
    """The library drives the vendor columns and the Q-BRIDGE mirrors follow.

    The seeded port 1 is a real captured trunk (tagged in 12 VLANs), so making it
    UNTAGGED somewhere must PRESERVE those -- which is only expressible as trunk
    mode with the requested VLAN as native, not as access mode.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)  # a VLAN the target port is not already in
        port = _TRUNK_PORT
        was_tagged, _ = _membership(reader, port)
        assert len(was_tagged) > 1, "seed should give this port real tagged VLANs"
        writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)

        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port in vlan.untagged_ports
        # The other memberships SURVIVED (the old access-mode recipe destroyed them).
        tagged, untagged = _membership(reader, port)
        assert untagged == {vid}
        assert tagged == was_tagged - {vid}
        # An untagged VLAN also becomes the PVID, exactly as observed live.
        assert dict(reader.get_pvids())[port] == vid
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        mode = client.get([f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"])[0].value
        native = client.get(
            [f"{oids.FASTPATH_SWITCHPORT_NATIVE_VLAN}.{port}"]
        )[0].value
        assert mode == oids.SWITCHPORT_MODE_TRUNK
        assert native == vid
    finally:
        sw.stop()


def test_untagged_on_a_port_with_nothing_tagged_uses_access_mode() -> None:
    """When no tagged VLAN needs preserving, one untagged VLAN IS access mode --
    the idiomatic form, and what the switch's own CLI produces."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = max(sw.state.vlans)
        port = _ACCESS_PORT
        assert _membership(reader, port)[0] == set(), "no tagged VLANs to preserve"
        writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
        assert _membership(reader, port) == (set(), {vid})
        assert (
            client.get([f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"])[0].value
            == oids.SWITCHPORT_MODE_ACCESS
        )
        assert (
            client.get([f"{oids.FASTPATH_SWITCHPORT_ACCESS_VLAN}.{port}"])[0].value
            == vid
        )
    finally:
        sw.stop()


def test_tagged_grants_membership_in_the_requested_vlan_only() -> None:
    """The bug this replaces: TAGGED used to flip the port to trunk while the
    factory allowed list still held all 4093 VLANs, making it a tagged member of
    EVERY VLAN on the switch. Membership must grow by exactly one VLAN."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        port = _ACCESS_PORT
        vid = max(sw.state.vlans)
        before_tagged, before_untagged = _membership(reader, port)
        all_vlans = {v.vlan_id for v in reader.get_vlans()}
        assert len(all_vlans) > 3, "seed must have several VLANs for this to bite"

        writer.set_vlan_membership(vid, port, VlanMode.TAGGED, force=True)

        tagged, untagged = _membership(reader, port)
        assert tagged == before_tagged | {vid}
        assert untagged == before_untagged
        # The whole point: NOT a member of everything else.
        assert all_vlans - tagged - untagged, "must not have joined every VLAN"
        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port not in vlan.untagged_ports
    finally:
        sw.stop()


def test_tagged_preserves_every_other_membership() -> None:
    """Adding a second tagged VLAN must not disturb the first (read-modify-write
    of the allowed-VLAN column, verified live in this exact sequence)."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        port = _ACCESS_PORT
        first, second = sorted(sw.state.vlans)[-2:]
        before_tagged, before_untagged = _membership(reader, port)
        writer.set_vlan_membership(first, port, VlanMode.TAGGED, force=True)
        writer.set_vlan_membership(second, port, VlanMode.TAGGED, force=True)
        tagged, untagged = _membership(reader, port)
        assert tagged == before_tagged | {first, second}
        assert untagged == before_untagged
    finally:
        sw.stop()


def test_excluded_removes_only_the_named_vlan() -> None:
    """THE regression this whole change exists for.

    EXCLUDED used to be implemented as "access mode on VLAN 1", which destroyed
    every other membership the port had. Verified live on both SKUs: removing one
    VLAN from the allowed list dropped exactly that VLAN and left the rest alone.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        port = _ACCESS_PORT
        first, second = sorted(sw.state.vlans)[-2:]
        writer.set_vlan_membership(first, port, VlanMode.TAGGED, force=True)
        writer.set_vlan_membership(second, port, VlanMode.TAGGED, force=True)
        tagged_before, untagged_before = _membership(reader, port)
        assert {first, second} <= tagged_before

        writer.set_vlan_membership(first, port, VlanMode.EXCLUDED, force=True)

        tagged, untagged = _membership(reader, port)
        assert first not in tagged
        assert first not in untagged
        assert tagged == tagged_before - {first}, "other tagged VLANs must survive"
        assert untagged == untagged_before, "the untagged VLAN must survive"
    finally:
        sw.stop()


def test_excluding_the_untagged_vlan_keeps_the_tagged_ones() -> None:
    """Excluding a port from its ONLY untagged VLAN has to put it somewhere -- the
    hardware has no "untagged nowhere" state (col4 := 0 commitFails) -- so it falls
    back to VLAN 1. That fallback is the one unrequested membership this can
    produce, and it must NOT cost the port its tagged VLANs."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        port = _ACCESS_PORT
        keep, drop = sorted(sw.state.vlans)[-2:]
        writer.set_vlan_membership(keep, port, VlanMode.TAGGED, force=True)
        writer.set_vlan_membership(drop, port, VlanMode.UNTAGGED, force=True)
        assert _membership(reader, port) == ({keep}, {drop})

        writer.set_vlan_membership(drop, port, VlanMode.EXCLUDED, force=True)

        tagged, untagged = _membership(reader, port)
        assert drop not in tagged
        assert drop not in untagged
        assert tagged == {keep}, "tagged membership must survive the fallback"
        assert untagged == {1}
        assert dict(reader.get_pvids())[port] == 1
    finally:
        sw.stop()


def test_excluded_returns_a_plain_access_port_to_the_default_vlan() -> None:
    """With nothing tagged to preserve, EXCLUDED still lands on access/VLAN 1 --
    the pre-existing behaviour, now DERIVED rather than hardcoded."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = _ACCESS_PORT
        writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
        assert port in next(
            v for v in reader.get_vlans() if v.vlan_id == vid
        ).member_ports

        writer.set_vlan_membership(vid, port, VlanMode.EXCLUDED, force=True)
        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port not in vlan.member_ports
        assert port not in vlan.untagged_ports
        assert dict(reader.get_pvids())[port] == 1
    finally:
        sw.stop()


def test_excluded_refuses_when_the_fallback_would_demote_a_tagged_vlan() -> None:
    """If the port is a TAGGED member of the fallback VLAN, honouring the request
    would silently flip THAT VLAN to untagged -- a change nobody asked for. Refused
    as a precondition failure (no SET attempted) instead of approximated."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        port = _ACCESS_PORT
        drop = max(sw.state.vlans)
        writer.set_vlan_membership(1, port, VlanMode.TAGGED, force=True)
        writer.set_vlan_membership(drop, port, VlanMode.UNTAGGED, force=True)
        assert _membership(reader, port) == ({1}, {drop})
        with pytest.raises(UnsupportedCapabilityError, match="untagged in no VLAN"):
            writer.set_vlan_membership(drop, port, VlanMode.EXCLUDED, force=True)
        # Nothing changed -- the refusal happened before any SET.
        assert _membership(reader, port) == ({1}, {drop})
    finally:
        sw.stop()


def test_refuses_a_request_needing_two_untagged_vlans() -> None:
    """A general-mode port really can be untagged in several VLANs (observed live
    on m4300-16x 1/0/1, untagged in both 1 and 4007), and access/trunk mode hold
    exactly one. Refuse rather than silently drop the extras."""
    sw = VirtualSwitch(model=_MODEL)
    port = _TRUNK_PORT
    first, second = sorted(sw.state.vlans)[:2]
    # Untagged in TWO VLANs -- a state only the notWritable participation columns
    # can express, so it is set before the face binds (see _in_general_mode).
    _in_general_mode(sw, port, untagged={first, second}, tagged=set())
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        assert _membership(reader, port)[1] == {first, second}

        with pytest.raises(UnsupportedCapabilityError, match="at most ONE untagged"):
            writer.set_vlan_membership(
                max(sw.state.vlans), port, VlanMode.TAGGED, force=True
            )
        # But EXCLUDING one of them gets back to an expressible state.
        writer.set_vlan_membership(first, port, VlanMode.EXCLUDED, force=True)
        assert _membership(reader, port)[1] == {second}
    finally:
        sw.stop()


def test_allowed_vlan_write_preserves_allowances_for_absent_vlans() -> None:
    """The read-modify-write must only touch bits for VLANs that EXIST: a
    factory-default port allows all 4093, and rebuilding the map from current
    membership would silently revoke "allow future VLANs too"."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        _, writer = _sync_clients(sw)
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        port = _ACCESS_PORT
        keep, drop = sorted(sw.state.vlans)[-2:]
        # Two tagged VLANs, so excluding one leaves the port a TRUNK and the
        # allowed-VLAN column genuinely has to be read-modify-written.
        writer.set_vlan_membership(keep, port, VlanMode.TAGGED, force=True)
        writer.set_vlan_membership(drop, port, VlanMode.TAGGED, force=True)
        allowed0 = client.get(
            [f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}"]
        )[0].value
        assert isinstance(allowed0, bytes)
        from netgear_switch.snmp_write import _edit_vlan_bits

        client.set(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}",
                _edit_vlan_bits(allowed0, add={4007, 4008}),  # VLANs that don't exist
                "x",
            )
        )
        writer.set_vlan_membership(drop, port, VlanMode.EXCLUDED, force=True)
        allowed1 = client.get(
            [f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}"]
        )[0].value
        assert isinstance(allowed1, bytes)
        kept = decode_vlan_bitmap(allowed1)
        assert {4007, 4008} <= kept, "allowances for absent VLANs must survive"
        assert drop not in kept, "the excluded VLAN's bit must be cleared"
        assert keep in kept, "the surviving tagged VLAN must stay allowed"
    finally:
        sw.stop()


def test_mock_reproduces_the_live_hardware_transcript_step_for_step() -> None:
    """The recorded LIVE transcript, replayed against the mock (principle 5).

    On 2026-07-30 this exact five-step sequence was driven by this exact
    ``SnmpWriter`` against m4300-24x @10.1.5.13 (FASTPATH 12.0.13.8) on ifIndex 8
    ('1/0/8', link down, ifAlias 'empty') with throwaway VLANs 4007/4008, and the
    switch's own Q-BRIDGE mirrors reported the membership on the right after each
    step. The identical sequence ran on m4300-16x @10.1.5.20 (fw 12.0.19.15,
    ifIndex 1) and produced the SAME five results, from a general-mode start.
    Both switches were restored to their recorded baseline and the restore proved
    by re-reading.

    Note the mock's 1/0/8 starts in the same state the real port was in (access,
    access VLAN 1, native VLAN 1) because the seed carries the columns read off
    that switch -- so this is a like-for-like replay, not a coincidence.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        port = 8  # the exact ifIndex used on the real switch
        assert _membership(reader, port) == (set(), {1}), "same start as the device"
        for vid, name in ((4007, "AGENT-4007"), (4008, "AGENT-4008")):
            client.set_many(
                [
                    SetVarbind(
                        f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vid}",
                        oids.ROW_STATUS_CREATE_AND_GO,
                        "i",
                    ),
                    SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}", name, "s"),
                ]
            )
        transcript = (
            # request                      -> (tagged, untagged) the DEVICE reported
            ((4007, VlanMode.TAGGED), ({4007}, {1})),
            ((4008, VlanMode.TAGGED), ({4007, 4008}, {1})),
            ((4007, VlanMode.EXCLUDED), ({4008}, {1})),
            ((4008, VlanMode.UNTAGGED), (set(), {4008})),
            ((4008, VlanMode.EXCLUDED), (set(), {1})),
        )
        for (vid, mode), want in transcript:
            writer.set_vlan_membership(vid, port, mode, force=True)
            assert _membership(reader, port) == want, f"{mode} {vid} diverged"
    finally:
        sw.stop()


def test_membership_write_verification_catches_a_no_op_device() -> None:
    """A device that ACKs the switchport write without changing membership must
    raise WriteVerificationError, not report success."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        _, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = _TRUNK_PORT
        # Neuter the mock's derivation so the SET is ACKed but nothing changes.
        sw.state._apply_switchport = lambda _port: None  # type: ignore[method-assign]
        with pytest.raises(WriteVerificationError):
            writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
    finally:
        sw.stop()


def test_verification_catches_membership_gained_in_an_unrequested_vlan() -> None:
    """Verification covers the port's FULL membership, not just the requested VLAN
    -- so a device that grants extra VLANs (the old all-4093 trunk over-grant) is
    caught and named."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        _, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = _ACCESS_PORT
        extra = min(v for v in sw.state.vlans if v != vid)
        real_apply = sw.state._apply_switchport

        def sneaky(p: int) -> None:
            real_apply(p)
            if p == port:  # a device that quietly adds one more VLAN
                sw.state.vlans[extra].member.add(p)
                sw.state.vlans[extra].untagged.discard(p)

        sw.state._apply_switchport = sneaky  # type: ignore[method-assign]
        with pytest.raises(WriteVerificationError, match="UNREQUESTED"):
            writer.set_vlan_membership(vid, port, VlanMode.TAGGED, force=True)
    finally:
        sw.stop()


def test_async_switchport_write_matches_sync() -> None:
    """Sync/async parity for the switchport path (Task 16's invariant)."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        model = get_model(_MODEL)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        vid = max(sw.state.vlans)
        port = _TRUNK_PORT
        vlans0 = asyncio.run(reader.get_vlans())
        was_tagged = {v.vlan_id for v in vlans0 if port in v.tagged_ports}
        asyncio.run(
            writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
        )
        vlans = asyncio.run(reader.get_vlans())
        vlan = next(v for v in vlans if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port in vlan.untagged_ports
        # Same non-destructiveness as the sync path.
        assert {v.vlan_id for v in vlans if port in v.tagged_ports} == was_tagged - {
            vid
        }
        assert {v.vlan_id for v in vlans if port in v.untagged_ports} == {vid}
    finally:
        sw.stop()


def test_async_excluded_removes_only_the_named_vlan() -> None:
    """The async twin must be non-destructive too (shared pure planner)."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        model = get_model(_MODEL)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        port = _ACCESS_PORT
        first, second = sorted(sw.state.vlans)[-2:]
        asyncio.run(
            writer.set_vlan_membership(first, port, VlanMode.TAGGED, force=True)
        )
        asyncio.run(
            writer.set_vlan_membership(second, port, VlanMode.TAGGED, force=True)
        )
        asyncio.run(
            writer.set_vlan_membership(first, port, VlanMode.EXCLUDED, force=True)
        )
        vlans = asyncio.run(reader.get_vlans())
        tagged = {v.vlan_id for v in vlans if port in v.tagged_ports}
        assert first not in tagged
        assert second in tagged
    finally:
        sw.stop()


# --- S3300 (gsm7228ps) same-PDU auto-untag ordering quirk -------------------
#
# VERIFIED live on 10.1.5.11 (Smart firmware, community "public" is Read/Write):
#   one PDU  (egress + untagged together): egress=[1] untagged=[1]  <- WRONG
#   two PDUs (egress first, then untagged): egress=[1] untagged=[]  <- correct,
#   and the CLI witness showed "1/g1  Include  Include  Tagged".
# Setting a port's egress bit auto-untags it, and that side effect beats an
# untagged varbind in the same PDU. The mock reproduces it so the writer's
# split-PDU fix stays regression-tested.


def test_s3300_declares_the_split_membership_write_quirk() -> None:
    assert get_model("gsm7228ps").snmp_vlan_split_membership_writes is True
    # The switches that apply a combined PDU correctly must NOT opt in.
    assert get_model("gsm7252ps").snmp_vlan_split_membership_writes is False
    assert get_model("m4300-24x").snmp_vlan_split_membership_writes is False


def test_mock_reproduces_same_pdu_untagged_clobber() -> None:
    """A single combined PDU loses the untagged intent, exactly like hardware."""
    from netgear_switch.protocols.snmp.parse import decode_port_bitmap
    from netgear_switch.protocols.snmp.write import encode_port_bitmap

    sw = VirtualSwitch(model="gsm7228ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = max(sw.state.vlans)
        port = min(sw.state.ports)
        egress = client.get([f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"])[0].value
        untagged = client.get([f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"])[0].value
        assert isinstance(egress, bytes)
        assert isinstance(untagged, bytes)
        want_egress = encode_port_bitmap(
            set(decode_port_bitmap(egress)) | {port}, width_bytes=len(egress)
        )
        want_untagged = encode_port_bitmap(
            set(decode_port_bitmap(untagged)) - {port}, width_bytes=len(untagged)
        )
        # ONE PDU: the egress side effect wins, so the port stays untagged.
        client.set_many(
            [
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", want_egress, "x"),
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}", want_untagged, "x"
                ),
            ]
        )
        after_u = client.get([f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"])[0].value
        assert port in decode_port_bitmap(after_u), "mock must clobber like the S3300"

        # TWO PDUs, egress first: the untagged write sticks.
        client.set(
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", want_egress, "x")
        )
        client.set(
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}", want_untagged, "x")
        )
        after_u2 = client.get([f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"])[0].value
        assert port not in decode_port_bitmap(after_u2)
    finally:
        sw.stop()


def test_writer_splits_pdus_so_tagged_membership_survives_on_s3300() -> None:
    """The library's TAGGED write now succeeds on the quirky model."""
    sw = VirtualSwitch(model="gsm7228ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        model = get_model("gsm7228ps")
        reader, writer = SnmpReader(client, model), SnmpWriter(client, model)
        vid = max(sw.state.vlans)
        port = min(sw.state.ports)
        writer.set_vlan_membership(vid, port, VlanMode.TAGGED, force=True)
        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port not in vlan.untagged_ports  # the whole point of the fix
    finally:
        sw.stop()
