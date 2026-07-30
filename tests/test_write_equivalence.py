"""Sync/async write-equivalence against the live mutable VirtualSwitch."""

from __future__ import annotations

from equivalence import assert_write_equivalent
from netgear_switch.models import VlanMode
from netgear_switch.snmp_write import PoeCycleTimeouts

_FAST = PoeCycleTimeouts(off_timeout=2, on_timeout=2, poll_interval=0)


def test_write_equiv_set_poe_off():
    assert_write_equivalent(
        lambda s: s.set_poe(1, on=False, force=True),
        lambda a: a.set_poe(1, on=False, force=True),
        lambda snap: not next(p for p in snap.poe if p.port == 1).admin_enabled,
    )


def test_write_equiv_set_port_enabled():
    assert_write_equivalent(
        lambda s: s.set_port_enabled(5, enabled=False, force=True),
        lambda a: a.set_port_enabled(5, enabled=False, force=True),
        lambda snap: not next(p for p in snap.ports if p.port == 5).admin_enabled,
    )


def test_write_equiv_set_pvid():
    assert_write_equivalent(
        lambda s: s.set_pvid(10, 90, force=True),
        lambda a: a.set_pvid(10, 90, force=True),
        lambda snap: (10, 90) in snap.pvids,
    )


def test_write_equiv_set_vlan_membership():
    assert_write_equivalent(
        lambda s: s.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True),
        lambda a: a.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True),
        lambda snap: 25 in next(v for v in snap.vlans if v.vlan_id == 90).member_ports,
    )


def test_write_equiv_create_then_delete_vlan():
    assert_write_equivalent(
        lambda s: s.create_vlan(200, "guests"),
        lambda a: a.create_vlan(200, "guests"),
        lambda snap: any(v.vlan_id == 200 and v.name == "guests" for v in snap.vlans),
    )


def test_write_equiv_cycle_poe():
    assert_write_equivalent(
        lambda s: s.cycle_poe(1, force=True, timeouts=_FAST),
        lambda a: a.cycle_poe(1, force=True, timeouts=_FAST),
        lambda snap: next(p for p in snap.poe if p.port == 1).delivering,
    )


def test_write_equiv_set_mgmt_ip():
    assert_write_equivalent(
        lambda s: s.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda a: a.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True),
        lambda snap: snap.mgmt_ip is not None and snap.mgmt_ip.address == "10.9.9.9",
    )


# --- Supplementary coverage: the write surface beyond the tests above -------
#
# The tests above (verbatim from the task brief) exercise set_poe(off),
# set_port_enabled, set_pvid, set_vlan_membership(TAGGED), create_vlan,
# cycle_poe, and set_mgmt_ip. They never drive set_poe(on=True), delete_vlan,
# clear_poe_fault, or the UNTAGGED/EXCLUDED VlanMode variants through both
# facades. Add those here so every write op (and every VlanMode) is proven
# sync/async-equivalent against the live mutable VirtualSwitch.


def _poe_toggle_on_sync(s):
    # Genuine on/off/on toggle (not just "already on") so the final admin=on
    # readback is a real effect of this write, not a pre-existing seed value.
    s.set_poe(3, on=False, force=True)
    s.set_poe(3, on=True, force=True)


async def _poe_toggle_on_async(a):
    await a.set_poe(3, on=False, force=True)
    await a.set_poe(3, on=True, force=True)


def test_write_equiv_set_poe_on():
    assert_write_equivalent(
        _poe_toggle_on_sync,
        _poe_toggle_on_async,
        lambda snap: next(p for p in snap.poe if p.port == 3).admin_enabled,
    )


def test_write_equiv_set_vlan_membership_untagged():
    assert_write_equivalent(
        lambda s: s.set_vlan_membership(90, 26, VlanMode.UNTAGGED, force=True),
        lambda a: a.set_vlan_membership(90, 26, VlanMode.UNTAGGED, force=True),
        lambda snap: (
            26 in next(v for v in snap.vlans if v.vlan_id == 90).member_ports
            and 26 in next(v for v in snap.vlans if v.vlan_id == 90).untagged_ports
        ),
    )


def test_write_equiv_set_vlan_membership_excluded():
    # Seed has vlan 90 member={1, 2, 10}; port 10 is a genuine existing tagged
    # member, so excluding it is a real, non-vacuous removal.
    assert_write_equivalent(
        lambda s: s.set_vlan_membership(90, 10, VlanMode.EXCLUDED, force=True),
        lambda a: a.set_vlan_membership(90, 10, VlanMode.EXCLUDED, force=True),
        lambda snap: (
            10 not in next(v for v in snap.vlans if v.vlan_id == 90).member_ports
        ),
    )


def test_write_equiv_delete_vlan():
    # Seed has vlan 90 pre-existing, so its absence afterward is a genuine
    # effect of delete_vlan, not a vacuous "never existed" pass.
    assert_write_equivalent(
        lambda s: s.delete_vlan(90, force=True),
        lambda a: a.delete_vlan(90, force=True),
        lambda snap: all(v.vlan_id != 90 for v in snap.vlans),
    )


def test_write_equiv_clear_poe_fault():
    assert_write_equivalent(
        lambda s: s.clear_poe_fault(4, force=True, timeouts=_FAST),
        lambda a: a.clear_poe_fault(4, force=True, timeouts=_FAST),
        lambda snap: next(p for p in snap.poe if p.port == 4).delivering,
    )
