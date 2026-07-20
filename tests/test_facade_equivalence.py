"""Live-mock equivalence: both facades against a seeded VirtualSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

from equivalence import (
    GSM7252PS_PINS,
    M4300_16X_PINS,
    M4300_24X_PINS,
    assert_facades_equivalent,
    assert_m4300_facades_equivalent,
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
