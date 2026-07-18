"""Capstone NSDP integration: sync (UdpNsdpClient) and async (AsyncUdpNsdpClient)
facades against the same live NSDP VirtualSwitch face must return identical
model objects, and writes applied via each facade must produce identical device
state -- proving the backend is sync/async symmetric with no hardware.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from equivalence import (
    GS110EMX_PINS,
    assert_nsdp_facades_equivalent,
    assert_write_equivalent,
)
from netgear_switch.models import VlanMode

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def test_nsdp_sync_and_async_reads_are_identical(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    assert_nsdp_facades_equivalent(virtual_gs110emx, GS110EMX_PINS)


def test_nsdp_write_equiv_set_pvid() -> None:
    assert_write_equivalent(
        lambda s: s.set_pvid(5, 90),
        lambda a: a.set_pvid(5, 90),
        lambda snap: (5, 90) in snap.pvids,
        model="gs110emx",
    )


def test_nsdp_write_equiv_set_vlan_membership() -> None:
    assert_write_equivalent(
        lambda s: s.set_vlan_membership(90, 5, VlanMode.TAGGED),
        lambda a: a.set_vlan_membership(90, 5, VlanMode.TAGGED),
        lambda snap: 5 in next(v for v in snap.vlans if v.vlan_id == 90).member_ports,
        model="gs110emx",
    )


def test_nsdp_write_equiv_set_mgmt_ip() -> None:
    assert_write_equivalent(
        lambda s: s.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda a: a.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda snap: snap.mgmt_ip is not None and snap.mgmt_ip.address == "10.9.9.9",
        model="gs110emx",
    )
