# tests/test_snmp_integration.py
"""Capstone integration test: sync (net-snmp CLI) and async (pysnmp) readers
against the same live VirtualSwitch must return byte-for-byte identical model
objects, over real (non-empty) seeded data -- never a vacuous [] == [] pass.
"""
from __future__ import annotations

import asyncio
import gc
from typing import TYPE_CHECKING

from netgear_switch.models import IpMode
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import (
    AsyncSnmpReader,
    SnmpReader,
    async_read_system_info,
    read_system_info,
)
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def _readers(sw: VirtualSwitch) -> tuple[SnmpReader, AsyncSnmpReader]:
    model = get_model("gsm7252ps")
    sync = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
    # PysnmpClient takes host/port separately (unlike the CLI client's
    # "host:port" agent spec).
    aio = AsyncSnmpReader(PysnmpClient(sw.host, "public", port=sw.port), model)
    return sync, aio


def test_sync_and_async_reads_are_identical(virtual_gsm7252ps: VirtualSwitch) -> None:
    sw = virtual_gsm7252ps
    sync, aio = _readers(sw)

    # Prove equivalence over NON-EMPTY data for every read op this slice adds
    # -- otherwise "sync == async" would pass vacuously on empty lists. The
    # seed (Task 13) guarantees stats, macs and lldp are populated.
    sync_ports = sync.get_ports()
    sync_stats = sync.get_stats()
    sync_vlans = sync.get_vlans()
    sync_pvids = sync.get_pvids()
    sync_lldp = sync.get_lldp()
    sync_macs = sync.get_macs()
    sync_poe = sync.get_poe()
    sync_sensors = sync.get_sensors()
    sync_mgmt = sync.get_mgmt_ip()

    assert sync_ports, "ports must be non-empty"
    assert [s for s in sync_stats if s.rx_bytes is not None], "stats must be non-empty"
    assert sync_vlans, "vlans must be non-empty"
    assert sync_pvids, "pvids must be non-empty"
    assert sync_lldp, "lldp must be non-empty"
    assert sync_macs, "macs must be non-empty"
    assert any(p.power_mw for p in sync_poe), "poe must show delivered power"
    assert sync_sensors, "sensors must be non-empty"
    assert sync_mgmt.address, "mgmt-ip must be populated"

    # Content pins -- prove the equivalence is over real, known seed data,
    # not just internally-consistent empty structures.
    port_names = {p.name for p in sync_ports}
    assert "1/0/1" in port_names
    # ifAlias, over a real transport round-trip (not FakeClient): port 1 has
    # an operator-set description, others honestly don't.
    port1 = next(p for p in sync_ports if p.port == 1)
    assert port1.description == "eth0.rpi5-pmod"  # captured ifAlias
    assert any(p.description is None for p in sync_ports)
    # dot1dBaseBridgeAddress, over a real transport round-trip.
    assert sync_mgmt.base_mac == "28:C6:8E:00:00:01"
    vlan_names = {v.vlan_id: v.name for v in sync_vlans}
    assert vlan_names[90] == "iot"
    assert 10 in next(v for v in sync_vlans if v.vlan_id == 90).member_ports
    assert sync_mgmt.address == "10.1.5.20"
    # The seed's dhcp-mode OID is INTEGER 2 (static); pin the mode path
    # end-to-end through the live mock, not just .address (Task 16 Fix 3).
    assert sync_mgmt.mode is IpMode.STATIC
    delivering = [p for p in sync_poe if p.power_mw]
    assert delivering[0].port == 1
    assert delivering[0].power_mw == 12_800

    # MAC/FDB join proof (carry-forward from Task 13): the seed maps
    # bridge_port 10 -> ifIndex 110 (a DELIBERATELY non-identity mapping), so
    # a regression that dropped the dot1dBasePortIfIndex join (or fell back
    # to the bridge port number itself) would surface .port == 10 here
    # instead of the correctly-joined 110.
    joined = next(m for m in sync_macs if m.mac == "C8:00:84:89:71:70")
    assert joined.port == 110
    assert joined.port != 10

    # The equivalence proper: sync (net-snmp CLI) vs async (pysnmp) against
    # the same live face must yield identical model objects for every op.
    assert sync_ports == asyncio.run(aio.get_ports())
    assert sync_stats == asyncio.run(aio.get_stats())
    assert sync_vlans == asyncio.run(aio.get_vlans())
    assert sync_pvids == asyncio.run(aio.get_pvids())
    assert sync_lldp == asyncio.run(aio.get_lldp())
    # remote_port_id (lldpRemPortId) is a distinct field from remote_port_desc
    # (lldpRemPortDesc) -- pinned over real seed data, both transports.
    assert sync_lldp[0].remote_port_id == "1/xg51"
    assert sync_lldp[0].remote_port_id != sync_lldp[0].remote_port_desc
    assert sync_macs == asyncio.run(aio.get_macs())
    assert sync_poe == asyncio.run(aio.get_poe())
    assert sync_sensors == asyncio.run(aio.get_sensors())
    aio_mgmt = asyncio.run(aio.get_mgmt_ip())
    assert sync_mgmt == aio_mgmt
    # Pin the mode path through BOTH transports explicitly, not just via the
    # whole-object equality above (Task 16 Fix 3).
    assert sync_mgmt.mode is IpMode.STATIC
    assert aio_mgmt.mode is IpMode.STATIC

    # No leaked sockets/tasks: force a GC pass so any unreferenced pysnmp
    # transport that only closes on finalization is torn down before the
    # -W error::ResourceWarning run below inspects warnings.
    gc.collect()


def test_reads_return_expected_seed_values(virtual_gsm7252ps: VirtualSwitch) -> None:
    sw = virtual_gsm7252ps
    reader = SnmpReader(
        NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), get_model("gsm7252ps")
    )
    vlans = {v.vlan_id: v.name for v in reader.get_vlans()}
    assert vlans[90] == "iot"
    mgmt = reader.get_mgmt_ip()
    assert mgmt.address == "10.1.5.22"
    assert mgmt.mode is IpMode.STATIC
    assert any(p.power_mw and p.power_mw > 0 for p in reader.get_poe())

    macs = reader.get_macs()
    joined = next(m for m in macs if m.mac == "C8:00:84:89:71:70")
    assert joined.port == 110, "bridge_port 10 must join to ifIndex 110, not itself"


def test_detect_model_end_to_end_sync_and_async_over_real_transport(
    virtual_gsm7252ps: VirtualSwitch,
) -> None:
    """Task 2 capstone: sysDescr-based model detection over BOTH real
    transports (net-snmp CLI + pysnmp) against the seeded gsm7252ps virtual
    switch, matching the same key -- proving detection works end-to-end, not
    just against a FakeClient."""
    sw = virtual_gsm7252ps
    sync_client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
    async_client = PysnmpClient(sw.host, "public", port=sw.port)

    sync_detected = read_system_info(sync_client)
    async_detected = asyncio.run(async_read_system_info(async_client))

    assert sync_detected.key == "gsm7252ps"
    assert sync_detected.matched is True
    # The seed's sysDescr contains the model name; the raw text is carried
    # through untouched.
    assert "GSM7252PS" in (sync_detected.sys_descr or "")
    # sysObjectID is READ (raw signal, kept for the caller/logging) but is a
    # virtual/test placeholder -- NOT a real captured value -- and is never
    # used for matching.
    assert sync_detected.sys_object_id == "1.3.6.1.4.1.4526.10.100.14"

    assert sync_detected == async_detected
