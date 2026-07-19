"""Capstone NSDP integration: sync (UdpNsdpClient) and async (AsyncUdpNsdpClient)
facades against the same live NSDP VirtualSwitch face must return identical
model objects, and writes applied via each facade must produce identical device
state -- proving the backend is sync/async symmetric with no hardware.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from equivalence import (
    GS110EMX_PINS,
    assert_nsdp_facades_equivalent,
    assert_write_equivalent,
    facades_for,
)
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import VlanMode
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch

if TYPE_CHECKING:
    from netgear_switch.virtual.server import VirtualSwitch


def test_nsdp_sync_and_async_reads_are_identical(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    assert_nsdp_facades_equivalent(virtual_gs110emx, GS110EMX_PINS)


def test_nsdp_device_facade_returns_complete_device(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    """SyncSwitch.nsdp_device()/AsyncSwitch.nsdp_device() against the virtual
    gs110emx must return a COMPLETE NsdpDevice (identity, mgmt IP, ports, VLANs
    plus the 5 newly-parsed tags from Slice 9b), and sync/async must agree."""
    sync, aio = facades_for(virtual_gs110emx)

    sync_dev = sync.nsdp_device()
    async_dev = asyncio.run(aio.nsdp_device())

    assert sync_dev == async_dev

    dev = sync_dev
    assert dev.model == "GS110EMX"
    assert dev.hostname == "plus-sw"
    assert dev.firmware_version == "1.0.0.7"
    assert dev.serial_number == "53H6025EA0083"
    assert dev.dhcp_enabled is False
    assert dev.port_count == 10
    assert dev.port_status
    assert dev.vlan_members
    # The 5 tags Slice 9b adds parse cases for.
    assert dev.qos_engine == 1
    assert dev.port_mirroring is not None
    assert dev.port_mirroring.destination_port == 10
    assert dev.port_mirroring.source_ports == frozenset({1, 2})
    assert dev.igmp_snooping is not None
    assert dev.igmp_snooping.enabled is True
    assert dev.igmp_snooping.vlan_id == 90
    assert dev.broadcast_filtering is True
    assert dev.loop_detection is True


def test_nsdp_device_raises_for_non_nsdp_model() -> None:
    """A model with no NSDP backend must raise UnsupportedCapabilityError,
    never fabricate a device (honesty over guessing)."""
    sw = SyncSwitch(get_model("gsm7252ps"), "203.0.113.1")  # SNMP-only, no NSDP
    with pytest.raises(UnsupportedCapabilityError):
        sw.nsdp_device()


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
