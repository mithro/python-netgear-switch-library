"""Live-mock equivalence: both facades against a seeded VirtualSwitch."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from equivalence import (
    GSM7252PS_PINS,
    M4300_16X_PINS,
    M4300_24X_PINS,
    assert_facades_equivalent,
    assert_m4300_facades_equivalent,
    facades_for,
)

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def test_facades_equivalent_gsm7252ps(virtual_gsm7252ps: VirtualSwitch) -> None:
    assert_facades_equivalent(virtual_gsm7252ps, GSM7252PS_PINS)


def test_facades_equivalent_m4300_24x_no_poe(
    virtual_m4300_24x: VirtualSwitch,
) -> None:
    """m4300-24x (0 PoE ports, verified real capture poe=[]): every OTHER
    read op still round-trips identically sync vs async through a real
    virtual-mock SNMP agent, and get_poe() honestly degrades to [] on BOTH
    transports -- this model was previously covered only by parse.py-level
    tests (tests/virtual/test_m4300_seeds.py) that never touched
    VirtualSnmpFace/SnmpReader/AsyncSnmpReader/SyncSwitch/AsyncSwitch at all."""
    assert_m4300_facades_equivalent(virtual_m4300_24x, M4300_24X_PINS)


def test_facades_equivalent_m4300_16x_with_poe(
    virtual_m4300_16x: VirtualSwitch,
) -> None:
    """m4300-16x (all 16 ports PoE-capable, 2 verified-delivering live):
    first-ever wire-level test coverage for this model (previously ZERO --
    see the Gap A brief) -- every read op, both facades, real delivered PoE
    power included."""
    assert_m4300_facades_equivalent(virtual_m4300_16x, M4300_16X_PINS)


def test_facade_serves_gsm7228ps_snmp_reads(
    virtual_gsm7228ps: VirtualSwitch,
) -> None:
    """Gap C: gsm7228ps is registered ``verified=True`` (SNMP+HTTP) in
    registry.py, yet had NO virtual seed (a blank state) and no SNMP wire
    test at all -- inconsistent with the honest ``verified=False`` blank
    treatment of m7300/xs748t/gs728tpp (those are blank BECAUSE they're
    unverified; gsm7228ps was blank despite claiming verified=True). Prove
    the new ``seed_gsm7228ps()`` (see its own docstring: illustrative/
    structural -- no real capture exists for this model) at least serves
    every SNMP read op non-vacuously, sync and async alike."""
    sync, aio = facades_for(virtual_gsm7228ps)

    ports = sync.get_ports()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    lldp = sync.get_lldp()
    macs = sync.get_macs()
    poe = sync.get_poe()
    sensors = sync.get_sensors()
    mgmt = sync.get_mgmt_ip()

    assert ports, "ports must be non-empty"
    assert vlans, "vlans must be non-empty"
    assert pvids, "pvids must be non-empty"
    assert lldp, "lldp must be non-empty"
    assert macs, "macs must be non-empty"
    assert any(p.power_mw for p in poe), "poe must show delivered power"
    assert sensors, "sensors must be non-empty"
    assert mgmt.address, "mgmt-ip must be populated"

    assert ports == asyncio.run(aio.get_ports())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert lldp == asyncio.run(aio.get_lldp())
    assert macs == asyncio.run(aio.get_macs())
    assert poe == asyncio.run(aio.get_poe())
    assert sensors == asyncio.run(aio.get_sensors())
    assert mgmt == asyncio.run(aio.get_mgmt_ip())
