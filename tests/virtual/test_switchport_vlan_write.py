# tests/virtual/test_switchport_vlan_write.py
"""VLAN membership writes on a FASTPATH switchport-dialect model (the M4300s).

Every behaviour asserted here was established on REAL hardware -- an M4300-24X
@10.1.5.13, firmware 12.0.13.8 -- by capturing a full snmpwalk, changing the
VLAN through the switch's own CLI, re-walking, and diffing the two walks:

* the standard Q-BRIDGE dot1qVlanStaticEgress/UntaggedPorts columns are READ-ONLY
  MIRRORS: a SET returns commitFailed even when writing back byte-identical
  octets, and dot1qVlanStaticRowStatus := notInService commitFails too;
* VLAN membership is owned by the per-port SWITCHPORT MODE. Writing mode=access
  plus the access-VLAN column DID move the port into
  dot1qVlanStaticEgressPorts.<vid> and ...UntaggedPorts.<vid> and set its PVID;
* the per-port tagged/untagged VLAN bitmaps answer notWritable.

The mock emulates all of it, so these are real regression tests rather than
assertions about the mock's own invention.
"""
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import WriteVerificationError
from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
from netgear_switch.snmp_write import AsyncSnmpWriter, SnmpWriter
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "m4300-24x"


def _sync_clients(sw: VirtualSwitch) -> tuple[SnmpReader, SnmpWriter]:
    client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
    model = get_model(_MODEL)
    return SnmpReader(client, model), SnmpWriter(client, model)


def test_model_declares_the_switchport_write_dialect() -> None:
    """Both M4300 SKUs run the FASTPATH 12.x firmware whose Q-BRIDGE PortLists
    are read-only; every other SNMP model keeps the standard qbridge dialect."""
    assert get_model("m4300-24x").snmp_vlan_write == "fastpath_switchport"
    assert get_model("m4300-16x").snmp_vlan_write == "fastpath_switchport"
    assert get_model("gsm7252ps").snmp_vlan_write == "qbridge"
    assert get_model("gsm7228ps").snmp_vlan_write == "qbridge"


def test_qbridge_portlist_write_is_rejected_like_real_hardware() -> None:
    """The INVALID write: a raw SET of dot1qVlanStaticEgressPorts must fail.

    On the real M4300 this is commitFailed even for byte-identical octets. A mock
    that accepted it would hide exactly the divergence that sent me chasing a
    non-existent bug, so the mock refuses it too.
    """
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vid = min(sw.state.vlans)
        rows = client.get([f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"])
        identical = rows[0].value
        assert isinstance(identical, bytes)
        # Writing back the EXACT bytes the device just reported still fails.
        with pytest.raises(SnmpError):
            client.set(
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}", identical, "x"
                )
            )
        with pytest.raises(SnmpError):
            client.set(
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}", identical, "x"
                )
            )
    finally:
        sw.stop()


def test_per_port_vlan_bitmaps_are_read_only() -> None:
    """The switchport tagged/untagged VLAN bitmaps answer notWritable live."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        port = min(sw.state.ports)
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


def test_set_vlan_membership_untagged_via_switchport() -> None:
    """The library drives mode+access-VLAN and the Q-BRIDGE mirrors follow."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)  # a VLAN the target port is not already in
        port = min(sw.state.ports)
        writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)

        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port in vlan.untagged_ports
        # An access port's VLAN also becomes its PVID, exactly as observed live.
        assert dict(reader.get_pvids())[port] == vid
        # And the vendor columns really carry the new configuration.
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        mode = client.get([f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"])[0].value
        access = client.get([f"{oids.FASTPATH_SWITCHPORT_ACCESS_VLAN}.{port}"])[0].value
        assert mode == oids.SWITCHPORT_MODE_ACCESS
        assert access == vid
    finally:
        sw.stop()


def test_set_vlan_membership_tagged_via_trunk() -> None:
    """TAGGED -> trunk mode: egress member, but NOT in the untagged set."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = min(sw.state.ports)
        writer.set_vlan_membership(vid, port, VlanMode.TAGGED, force=True)

        vlan = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port not in vlan.untagged_ports
    finally:
        sw.stop()


def test_set_vlan_membership_excluded_returns_port_to_default_vlan() -> None:
    """EXCLUDED is expressible only as "access port back on the default VLAN"."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        reader, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = min(sw.state.ports)
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


def test_membership_write_verification_catches_a_no_op_device() -> None:
    """A device that ACKs the switchport write without changing membership must
    raise WriteVerificationError, not report success."""
    sw = VirtualSwitch(model=_MODEL)
    sw.start()
    try:
        _, writer = _sync_clients(sw)
        vid = max(sw.state.vlans)
        port = min(sw.state.ports)
        # Neuter the mock's derivation so the SET is ACKed but nothing changes.
        sw.state._apply_switchport = lambda _port: None  # type: ignore[method-assign]
        with pytest.raises(WriteVerificationError):
            writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
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
        port = min(sw.state.ports)
        asyncio.run(
            writer.set_vlan_membership(vid, port, VlanMode.UNTAGGED, force=True)
        )
        vlan = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert port in vlan.member_ports
        assert port in vlan.untagged_ports
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
