"""Live-mock equivalence: both facades against a seeded VirtualSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

from equivalence import GSM7252PS_PINS, assert_facades_equivalent

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def test_facades_equivalent_gsm7252ps(virtual_gsm7252ps: VirtualSwitch) -> None:
    assert_facades_equivalent(virtual_gsm7252ps, GSM7252PS_PINS)
