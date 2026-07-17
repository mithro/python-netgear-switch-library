# tests/test_snmp_integration.py
"""Capstone integration test: sync (net-snmp CLI) and async (pysnmp) readers
against the same live VirtualSwitch must return byte-for-byte identical model
objects, over real (non-empty) seeded data -- never a vacuous [] == [] pass.
"""
from __future__ import annotations

import asyncio
import gc
from typing import TYPE_CHECKING

from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
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
    vlan_names = {v.vlan_id: v.name for v in sync_vlans}
    assert vlan_names[90] == "iot"
    assert 10 in next(v for v in sync_vlans if v.vlan_id == 90).member_ports
    assert sync_mgmt.address == "10.1.5.20"
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
    assert sync_macs == asyncio.run(aio.get_macs())
    assert sync_poe == asyncio.run(aio.get_poe())
    assert sync_sensors == asyncio.run(aio.get_sensors())
    assert sync_mgmt == asyncio.run(aio.get_mgmt_ip())

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
    assert reader.get_mgmt_ip().address == "10.1.5.20"
    assert any(p.power_mw and p.power_mw > 0 for p in reader.get_poe())

    macs = reader.get_macs()
    joined = next(m for m in macs if m.mac == "C8:00:84:89:71:70")
    assert joined.port == 110, "bridge_port 10 must join to ifIndex 110, not itself"
