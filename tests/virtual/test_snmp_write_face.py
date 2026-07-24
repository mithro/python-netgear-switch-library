# tests/virtual/test_snmp_write_face.py
"""End-to-end SET->mutate->read against a live ``VirtualSwitch`` mock.

``tests/virtual/test_mutable_state.py`` covers ``apply_write``/coherence
purely at the state layer (no network). This file drives the same mutation
through the real SNMP SET path (``SetCommandResponder`` -> ``write_variables``
-> ``StateMibView.apply_write``) using both real transport clients, then
reads the new value back over the wire -- proving the whole SET->mutate->read
loop, not just the state layer in isolation.
"""
from __future__ import annotations

import asyncio
import gc
import warnings

import pytest

from netgear_switch.errors import ProtectedPortError
from netgear_switch.models import IpMode, PoEDetect, VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind, encode_port_bitmap
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
from netgear_switch.snmp_write import AsyncSnmpWriter, PoeCycleTimeouts, SnmpWriter
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch


def test_set_via_pysnmp_client_then_read_back_ifadmin():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        oid = f"{oids.IF_ADMIN_STATUS}.3"
        oper_oid = f"{oids.IF_OPER_STATUS}.3"

        # Seed: port 3 starts admin-up (though link-down in the seed).
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, 1, "INTEGER")]

        asyncio.run(client.set(SetVarbind(oid, 2, "i")))  # admin down

        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, 2, "INTEGER")]
        # Coherence: admin-down forces the data link down too.
        rows = asyncio.run(client.get([oper_oid]))
        assert rows == [SnmpRow(oper_oid, 2, "INTEGER")]
        assert sw.state.ports[3].admin is False
        assert sw.state.ports[3].link is False
    finally:
        sw.stop()


def test_set_via_pysnmp_client_poe_admin_cycles_detect_coherence():
    """Drives the exact coherence ``cycle_poe``/``clear_poe_fault`` rely on:
    admin off -> detect=unused(1) + link down; admin on -> detect=delivering(3).
    """
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        admin_oid = f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
        detect_oid = f"{oids.PETH_PSE_PORT_TABLE}.6.1.1"
        oper_oid = f"{oids.IF_OPER_STATUS}.1"

        assert sw.state.poe[1].admin is True
        assert sw.state.poe[1].detect == 3

        asyncio.run(client.set(SetVarbind(admin_oid, 2, "i")))  # admin off
        detect_rows = asyncio.run(client.get([detect_oid]))
        assert detect_rows == [SnmpRow(detect_oid, 1, "INTEGER")]
        oper_rows = asyncio.run(client.get([oper_oid]))
        assert oper_rows == [SnmpRow(oper_oid, 2, "INTEGER")]

        asyncio.run(client.set(SetVarbind(admin_oid, 1, "i")))  # admin on
        admin_rows = asyncio.run(client.get([admin_oid]))
        assert admin_rows == [SnmpRow(admin_oid, 1, "INTEGER")]
        detect_rows = asyncio.run(client.get([detect_oid]))
        assert detect_rows == [SnmpRow(detect_oid, 3, "INTEGER")]
    finally:
        sw.stop()


def test_set_via_netsnmp_cli_client_then_read_back_pvid():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        oid = f"{oids.DOT1Q_PVID}.10"

        client.set(SetVarbind(oid, 90, "u"))

        rows = client.get([oid])
        assert rows == [SnmpRow(oid, 90, "Gauge32")]
        assert sw.state.pvids[10] == 90
    finally:
        sw.stop()


def test_set_unknown_oid_raises_snmperror_not_a_timeout():
    """A SET to an OID this mock never recognizes as writable must come back
    as a clean SNMP error (notWritable), not silently succeed and not hang
    the client until timeout (which would make this test flaky)."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port, timeout=2.0, retries=0)
        with pytest.raises(SnmpError):
            asyncio.run(client.set(SetVarbind("1.2.3.4.5", 1, "i")))
    finally:
        sw.stop()


def test_set_read_only_oid_raises_snmperror():
    """ifOperStatus is read-only (device-derived, not admin-settable) in this
    mock -- SETting it must be rejected, not silently accepted."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        with pytest.raises(SnmpError):
            client.set(SetVarbind(f"{oids.IF_OPER_STATUS}.1", 2, "i"))
    finally:
        sw.stop()


def test_set_malformed_value_maps_to_snmperror_not_a_timeout():
    """A structurally-wrong SET value (an OctetString where an integer
    RowStatus is expected) must raise via ``apply_write`` -> the mapped
    pysnmp ``WrongValueError`` -> a clean client-side ``SnmpError``, never
    propagate into the asyncio dispatcher (which would surface as a client
    timeout -- flaky, not a deterministic failure)."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port, timeout=2.0, retries=0)
        oid = f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.300"
        with pytest.raises(SnmpError):
            asyncio.run(client.set(SetVarbind(oid, b"\xff\xfe", "x")))
        # The malformed write must not have partially created the VLAN.
        assert 300 not in sw.state.vlans
    finally:
        sw.stop()


def test_set_many_multi_varbind_pdu_atomic_rollback_on_failure():
    """A single ``set_many`` PDU carrying one VALID varbind followed by one
    INVALID varbind must apply NEITHER: the whole PDU is all-or-nothing,
    matching a real SNMP agent and the ``set_many`` "one PDU (atomic)"
    contract (``protocols/snmp/client.py``) that e.g. ``set_vlan_membership``
    relies on. Proves ``write_variables`` rolls back the earlier,
    individually-valid varbind rather than leaving it applied."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port, timeout=2.0, retries=0)
        assert sw.state.ports[3].admin is True

        valid = SetVarbind(f"{oids.IF_ADMIN_STATUS}.3", 2, "i")  # admin down
        invalid = SetVarbind(  # malformed RowStatus value: not integer-parsable
            f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.300", b"\xff\xfe", "x"
        )
        with pytest.raises(SnmpError):
            asyncio.run(client.set_many([valid, invalid]))

        # Rollback: the earlier valid varbind must NOT have been applied.
        assert sw.state.ports[3].admin is True
        assert 300 not in sw.state.vlans
    finally:
        sw.stop()


def test_set_many_multi_varbind_pdu_applies_all_on_success():
    """The positive counterpart: two valid varbinds in one PDU both apply."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        asyncio.run(client.set_many([
            SetVarbind(f"{oids.IF_ADMIN_STATUS}.6", 2, "i"),
            SetVarbind(f"{oids.IF_ADMIN_STATUS}.7", 2, "i"),
        ]))
        assert sw.state.ports[6].admin is False
        assert sw.state.ports[7].admin is False
    finally:
        sw.stop()


def test_set_many_vlan_egress_and_untagged_bitmaps_reflected_in_get_vlans():
    """The exact multi-varbind shape ``set_vlan_membership`` sends: egress AND
    untagged bitmaps for one VLAN in a single ``set_many`` PDU. Exercises the
    full ``SetCommandResponder`` -> ``write_variables`` -> ``apply_write`` ->
    ``get_vlans`` round trip for the VLAN-membership OID class over the wire."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        vid = 90
        new_member = {1, 2, 10, 25}
        new_untagged = {1, 2}
        asyncio.run(client.set_many([
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}",
                encode_port_bitmap(new_member), "x",
            ),
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}",
                encode_port_bitmap(new_untagged), "x",
            ),
        ]))

        reader = AsyncSnmpReader(client, get_model("gsm7252ps"))
        vlan90 = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert vlan90.member_ports == frozenset(new_member)
        assert vlan90.untagged_ports == frozenset(new_untagged)
    finally:
        sw.stop()


def test_set_vlan_create_name_destroy_via_rowstatus_reflected_in_get_vlans():
    """VLAN lifecycle over the wire: createAndGo(4) + name write, then
    destroy(6), each reflected in ``get_vlans``."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        vid = 250
        row_oid = f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vid}"
        reader = AsyncSnmpReader(client, get_model("gsm7252ps"))

        assert all(v.vlan_id != vid for v in asyncio.run(reader.get_vlans()))

        asyncio.run(
            client.set(SetVarbind(row_oid, oids.ROW_STATUS_CREATE_AND_GO, "i"))
        )
        name_oid = f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}"
        asyncio.run(client.set(SetVarbind(name_oid, b"guests", "x")))
        created = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert created.name == "guests"

        asyncio.run(client.set(SetVarbind(row_oid, oids.ROW_STATUS_DESTROY, "i")))
        assert all(v.vlan_id != vid for v in asyncio.run(reader.get_vlans()))
    finally:
        sw.stop()


def test_set_mgmt_ip_write_oids_reflected_in_get_mgmt_ip():
    """The UNVERIFIED mgmt-IP write OIDs (address/netmask/gateway), all
    written in one ``set_many`` PDU, reflected back through ``get_mgmt_ip``."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        model = get_model("gsm7252ps")
        vo = oids.vendor_oids(model)
        asyncio.run(client.set_many([
            SetVarbind(vo.mgmt_write_addr_unverified, "10.9.9.9", "a"),
            SetVarbind(vo.mgmt_write_netmask_unverified, "255.255.255.0", "a"),
            SetVarbind(vo.mgmt_write_gateway_unverified, "10.9.9.1", "a"),
        ]))

        reader = AsyncSnmpReader(client, model)
        cfg = asyncio.run(reader.get_mgmt_ip())
        assert cfg.address == "10.9.9.9"
        assert cfg.netmask == "255.255.255.0"
        assert cfg.gateway == "10.9.9.1"
    finally:
        sw.stop()


def test_set_dhcp_mode_write_oid_reflected_in_get_mgmt_ip():
    """The UNVERIFIED dhcp-mode write OID, reflected back through
    ``get_mgmt_ip``'s mode field."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        model = get_model("gsm7252ps")
        oid = f"{oids.vendor_oids(model).dhcp_mode_unverified}.0"
        reader = AsyncSnmpReader(client, model)

        assert asyncio.run(reader.get_mgmt_ip()).mode == IpMode.STATIC  # seed default

        asyncio.run(client.set(SetVarbind(oid, 1, "i")))  # 1 = dhcp
        assert asyncio.run(reader.get_mgmt_ip()).mode == IpMode.DHCP

        asyncio.run(client.set(SetVarbind(oid, 2, "i")))  # 2 = static
        assert asyncio.run(reader.get_mgmt_ip()).mode == IpMode.STATIC
    finally:
        sw.stop()


def test_set_get_stop_lifecycle_emits_no_resource_warning():
    """Mirrors the existing GET-only lifecycle check in
    ``test_virtual_snmp_face.py`` for the SET path: a full
    start -> SET -> GET -> stop cycle must not leak the UDP socket/transport."""

    def _lifecycle() -> None:
        sw = VirtualSwitch(model="gsm7252ps")
        sw.start()
        try:
            client = PysnmpClient(sw.host, "public", port=sw.port)
            oid = f"{oids.IF_ADMIN_STATUS}.5"
            asyncio.run(client.set(SetVarbind(oid, 2, "i")))
            asyncio.run(client.get([oid]))
        finally:
            sw.stop()

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        _lifecycle()  # must not raise

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _lifecycle()
        gc.collect()
    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []


def test_snmp_writer_set_vlan_membership_live_preserves_other_ports():
    """Drive ``SnmpWriter.set_vlan_membership`` (RMW + atomic set_many +
    dual-column verify) through the real SET path against a live
    ``VirtualSwitch``, over the sync (net-snmp CLI) transport. Proves port 6
    joins VLAN 90 as a TAGGED member -- added to the egress set and CLEARED from
    the (quirky, capture-transcribed) untagged set -- while every OTHER port's
    membership and untagged status is preserved untouched."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)
        vid = 90

        before = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        # On the captured switch port 6 is a NON-member of VLAN 90, yet it IS
        # in that VLAN's untagged bitmap (the real dot1qVlanStaticUntaggedPorts
        # quirk -- untagged is not a subset of member here).
        assert 6 not in before.member_ports
        assert 6 in before.untagged_ports
        assert before.member_ports

        writer.set_vlan_membership(vid, 6, VlanMode.TAGGED)

        after = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        # 6 joins the egress set and is cleared from untagged (it is now tagged)
        assert after.member_ports == before.member_ports | {6}
        assert after.untagged_ports == before.untagged_ports - {6}
        # RMW preserved every other port in both columns
        assert after.member_ports - {6} == before.member_ports
        assert after.untagged_ports | {6} == before.untagged_ports
    finally:
        sw.stop()


def test_async_snmp_writer_set_vlan_membership_live_preserves_other_ports():
    """Async mirror of the above over the pysnmp transport, proving parity."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = PysnmpClient(sw.host, "public", port=sw.port)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        vid = 90

        before = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert 6 not in before.member_ports  # seeded from the real capture

        asyncio.run(writer.set_vlan_membership(vid, 6, VlanMode.UNTAGGED))

        after = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert after.member_ports == before.member_ports | {6}      # 6 joined
        assert after.untagged_ports == before.untagged_ports | {6}  # 6 untagged too
    finally:
        sw.stop()


def test_snmp_writer_set_pvid_live_preserves_other_ports():
    """Drive ``SnmpWriter.set_pvid`` (Gauge32 SET + verify) against a live
    ``VirtualSwitch``. Proves port 52's PVID moves to the existing VLAN 90
    while the seeded PVIDs for the other ports (transcribed from the real
    capture: 1/0/1 is on VLAN 90, 1/0/49 on VLAN 1) are left untouched."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)

        before = dict(reader.get_pvids())
        assert before[52] == 1
        assert before[49] == 1

        writer.set_pvid(52, 90)

        after = dict(reader.get_pvids())
        assert after[52] == 90         # changed
        assert after[49] == before[49]  # other port preserved
        assert after[1] == before[1]    # other port preserved
    finally:
        sw.stop()


def test_snmp_writer_set_vlan_membership_missing_vlan_raises_snmperror_live():
    """The precondition check (VLAN must exist) surfaces as ``SnmpError``,
    not a ``WriteVerificationError``, and issues no SET at all against the
    live mock."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        with pytest.raises(SnmpError):
            writer.set_vlan_membership(777, 25, VlanMode.TAGGED)
    finally:
        sw.stop()


def test_snmp_writer_create_vlan_then_delete_vlan_live():
    """``SnmpWriter.create_vlan``/``delete_vlan`` (RowStatus createAndGo/destroy
    + verify-after-write) driven against a live ``VirtualSwitch`` over the sync
    (net-snmp CLI) transport: create must show up in ``get_vlans``, and delete
    must make it disappear again."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)
        vid = 210

        assert all(v.vlan_id != vid for v in reader.get_vlans())

        writer.create_vlan(vid, "guests")
        created = next(v for v in reader.get_vlans() if v.vlan_id == vid)
        assert created.name == "guests"

        writer.delete_vlan(vid)
        assert all(v.vlan_id != vid for v in reader.get_vlans())
    finally:
        sw.stop()


def test_async_snmp_writer_create_vlan_then_delete_vlan_live():
    """Async mirror of the above over the pysnmp transport, proving parity."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = PysnmpClient(sw.host, "public", port=sw.port)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        vid = 211

        assert all(v.vlan_id != vid for v in asyncio.run(reader.get_vlans()))

        asyncio.run(writer.create_vlan(vid, "guests"))
        created = next(v for v in asyncio.run(reader.get_vlans()) if v.vlan_id == vid)
        assert created.name == "guests"

        asyncio.run(writer.delete_vlan(vid))
        assert all(v.vlan_id != vid for v in asyncio.run(reader.get_vlans()))
    finally:
        sw.stop()


def test_snmp_writer_delete_vlan_protected_member_requires_force_live():
    """The protected-port guard against a live mock: VLAN 90's seeded members
    include port 1 (marked protected here), so an unforced delete must refuse
    with ``ProtectedPortError`` and issue no SET, while ``force=True`` deletes
    it as usual."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model, protected_ports=frozenset({1}))
        reader = SnmpReader(client, model)
        vid = 90

        with pytest.raises(ProtectedPortError):
            writer.delete_vlan(vid)
        assert any(v.vlan_id == vid for v in reader.get_vlans())  # untouched

        writer.delete_vlan(vid, force=True)
        assert all(v.vlan_id != vid for v in reader.get_vlans())
    finally:
        sw.stop()


def test_snmp_writer_cycle_poe_live_off_then_on():
    """Drives ``SnmpWriter.cycle_poe`` (injectable, tiny timeouts) through the
    real SET path against a live ``VirtualSwitch``: admin off -> poll for
    unused+link-down -> admin on -> poll for delivering. The mock's PoE
    coherence (``test_set_via_pysnmp_client_poe_admin_cycles_detect_coherence``
    above) makes this terminate on the first poll, so tiny timeouts are fast
    and non-flaky."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)
        port = 2

        writer.cycle_poe(
            port, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
        )

        status = next(p for p in reader.get_poe() if p.port == port)
        assert status.delivering
        assert sw.state.poe[port].admin is True
    finally:
        sw.stop()


def test_snmp_writer_clear_poe_fault_live_recovers_detect():
    """``SnmpWriter.clear_poe_fault`` against a live ``VirtualSwitch``: force a
    FAULT directly on the mock's state (detect is device-derived, not
    SNMP-settable), then verify the admin off/on + poll sequence clears it."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)
        port = 4
        sw.state.poe[port].detect = 4  # FAULT

        writer.clear_poe_fault(
            port, force=True,
            timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
        )

        status = next(p for p in reader.get_poe() if p.port == port)
        assert status.detect is not PoEDetect.FAULT
    finally:
        sw.stop()


def test_snmp_writer_cycle_poe_protected_port_requires_force_live():
    """The protected-port guard against a live mock: cycling PoE on a
    protected port is refused without ``force=True`` and issues no SET."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model, protected_ports=frozenset({2}))
        port = 2

        with pytest.raises(ProtectedPortError):
            writer.cycle_poe(port)
        assert sw.state.poe[port].admin is True  # untouched

        writer.cycle_poe(
            port, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
        )
        assert sw.state.poe[port].admin is True  # cycled back on
    finally:
        sw.stop()


def test_async_snmp_writer_cycle_poe_live_off_then_on():
    """Async mirror of ``test_snmp_writer_cycle_poe_live_off_then_on`` over
    the pysnmp transport, proving sync/async parity."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = PysnmpClient(sw.host, "public", port=sw.port)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        port = 6

        asyncio.run(writer.cycle_poe(
            port, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
        ))

        status = next(p for p in asyncio.run(reader.get_poe()) if p.port == port)
        assert status.delivering
    finally:
        sw.stop()


def test_snmp_writer_set_mgmt_ip_live_reflects_all_three_fields():
    """Drives ``SnmpWriter.set_mgmt_ip`` (force-gated, UNVERIFIED write OIDs,
    verify-after-write covering address/netmask/gateway) against a live
    ``VirtualSwitch`` over the sync (net-snmp CLI) transport. Without
    force=True it must refuse and issue no SET; with force=True, all three
    fields must show up in ``get_mgmt_ip``."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        writer = SnmpWriter(client, model)
        reader = SnmpReader(client, model)

        before = reader.get_mgmt_ip()
        assert before.address == "10.1.5.22"

        with pytest.raises(ProtectedPortError):
            writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
        assert reader.get_mgmt_ip().address == before.address  # untouched

        writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)

        after = reader.get_mgmt_ip()
        assert after.address == "10.9.9.9"
        assert after.netmask == "255.255.255.0"
        assert after.gateway == "10.9.9.1"
    finally:
        sw.stop()


def test_async_snmp_writer_set_mgmt_ip_live_reflects_all_three_fields():
    """Async mirror of the above over the pysnmp transport, proving parity."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = PysnmpClient(sw.host, "public", port=sw.port)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)

        before = asyncio.run(reader.get_mgmt_ip())
        assert before.address == "10.1.5.22"

        with pytest.raises(ProtectedPortError):
            asyncio.run(writer.set_mgmt_ip("10.9.9.8", "255.255.255.0", "10.9.9.1"))
        assert asyncio.run(reader.get_mgmt_ip()).address == before.address  # untouched

        asyncio.run(
            writer.set_mgmt_ip("10.9.9.8", "255.255.255.0", "10.9.9.1", force=True)
        )

        after = asyncio.run(reader.get_mgmt_ip())
        assert after.address == "10.9.9.8"
        assert after.netmask == "255.255.255.0"
        assert after.gateway == "10.9.9.1"
    finally:
        sw.stop()


def test_async_snmp_writer_clear_poe_fault_live_recovers_detect():
    """Async mirror of ``test_snmp_writer_clear_poe_fault_live_recovers_detect``
    over the pysnmp transport, proving sync/async parity."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        model = get_model("gsm7252ps")
        client = PysnmpClient(sw.host, "public", port=sw.port)
        writer = AsyncSnmpWriter(client, model)
        reader = AsyncSnmpReader(client, model)
        port = 8
        sw.state.poe[port].detect = 4  # FAULT

        asyncio.run(writer.clear_poe_fault(
            port, force=True,
            timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
        ))

        status = next(p for p in asyncio.run(reader.get_poe()) if p.port == port)
        assert status.detect is not PoEDetect.FAULT
    finally:
        sw.stop()
