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
    """m4300-24x (0 PoE ports): every OTHER read op still round-trips
    identically sync vs async through a real virtual-mock SNMP agent, and
    get_poe() honestly RAISES UnsupportedCapabilityError on BOTH transports --
    consistent with the CLI/HTTP backends, never a silent [] (the SNMP reader
    now guards on poe_port_count == 0 before walking). This model was
    previously covered only by parse.py-level tests
    (tests/virtual/test_m4300_seeds.py) that never touched
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
    """gsm7228ps (the S3300-52X-PoE+) is ``verified=True`` as of 2026-07-30:
    its ``seed_gsm7228ps()`` is a literal transcription of the real capture
    (tests/fixtures/captures/gsm7228ps.json), strict-parity-checked in
    tests/virtual/test_gsm7228ps_seed.py. Here we prove both facades serve
    every SNMP read op non-vacuously AND agree byte-for-byte (sync == async)
    over the seeded mock."""
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
