"""Hand-authored ``VirtualSwitchState`` seed for the GSM7252PS.

Every read op (Task 5-9) has at least one non-empty, non-vacuous example in
this seed: ports with link/admin/speed, RX/TX counters on >=2 ports, >=1
VLAN with egress/untagged bitmaps and PVIDs, PoE with a delivering port,
fan/temperature/PSU sensors (including a "Not Supported" fan slot), >=2
MAC/FDB entries with their bridge-port->ifIndex mappings, >=1 LLDP
neighbour, and a static management IP. This makes the Task 16 SNMP<->SNMP
equivalence test (and the round-trip tests here) exercise real data on every
parser, not an empty table.
"""
from __future__ import annotations

from .state import (
    LldpSim,
    MacSim,
    MgmtSim,
    PoeSim,
    PortSim,
    SensorSim,
    VirtualSwitchState,
    VlanSim,
)

_POE_PORT_COUNT = 48
_TOTAL_PORT_COUNT = 52


def _port_name(port: int) -> str:
    if port <= _POE_PORT_COUNT:
        return f"1/0/{port}"
    return f"1/xg{port - _POE_PORT_COUNT}"


def seed_gsm7252ps() -> VirtualSwitchState:
    """Build a realistic GSM7252PS (52-port, 48-PoE) virtual switch state."""
    ports: dict[int, PortSim] = {}
    for port in range(1, _TOTAL_PORT_COUNT + 1):
        sim = PortSim(
            name=_port_name(port),
            admin=True,
            link=port != 3,  # port 3 is admin-up but link-down
            speed=1000,
        )
        if port in (1, 2):
            sim.rx_octets = 1_000_000
            sim.tx_octets = 2_000_000
            sim.rx_ucast = 8_000
            sim.tx_ucast = 9_000
            sim.rx_errors = 0
            sim.tx_errors = 0
        ports[port] = sim

    vlans = {
        1: VlanSim(
            name="default",
            member=set(range(1, _TOTAL_PORT_COUNT + 1)),
            untagged=set(range(3, _TOTAL_PORT_COUNT + 1)),
        ),
        90: VlanSim(name="iot", member={1, 2, 10}, untagged={1, 2}),
    }

    pvids = dict.fromkeys(range(1, _TOTAL_PORT_COUNT + 1), 1)
    pvids[1] = 90
    pvids[2] = 90

    poe: dict[int, PoeSim] = {}
    for port in range(1, _POE_PORT_COUNT + 1):
        if port == 1:
            poe[port] = PoeSim(admin=True, detect=3, power_mw=12_800)
        else:
            poe[port] = PoeSim(admin=True, detect=1, power_mw=0)

    sensors = [
        SensorSim(kind="fan", instance="0", raw="3500"),
        SensorSim(kind="fan", instance="1", raw="Not Supported"),
        SensorSim(kind="fan", instance="2", raw="3450"),
        SensorSim(kind="power", instance="0", raw="53"),
        SensorSim(kind="temperature", instance="0", raw="45"),
    ]

    macs = [
        MacSim(vlan=90, mac_bytes=(0xC8, 0x00, 0x84, 0x89, 0x71, 0x70), bridge_port=10),
        MacSim(vlan=1, mac_bytes=(0x00, 0x1B, 0x21, 0x3C, 0x4D, 0x5E), bridge_port=11),
    ]
    # bridge_port 10 deliberately maps to a DIFFERENT ifIndex (110, not 10) so
    # a regression that drops the dot1dBasePortIfIndex join (or falls back to
    # the bridge-port number itself) is detectable: get_macs() must surface
    # the mapped ifIndex 110, never the bridge port 10. bridge_port 11 stays
    # identity-mapped to prove the join also passes through unmapped/1:1 rows
    # unchanged.
    bridge_ports = {10: 110, 11: 11}

    lldp = [
        LldpSim(
            time_mark=75,
            local_port=49,
            rem_idx=7,
            chassis="".join(chr(b) for b in (0xC8, 0x00, 0x84, 0x89, 0x71, 0x70)),
            port_id="1/xg51",
            port_desc="eth0",
            sys_name="sw-cisco-shed",
        ),
    ]

    mgmt = MgmtSim(
        address="10.1.5.20", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gsm7252ps",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,
        sensors=sensors,
        macs=macs,
        bridge_ports=bridge_ports,
        lldp=lldp,
        mgmt=mgmt,
    )


def seed_gs110emx() -> VirtualSwitchState:
    """Build a realistic GS110EMX (10-port Plus, NSDP) virtual switch state."""
    ports: dict[int, PortSim] = {}
    for port in range(1, 11):
        speed = 10000 if port in (9, 10) else 1000
        sim = PortSim(
            name=f"g{port}",
            admin=True,
            link=port != 3,  # port 3 admin-up but link-down
            speed=speed,
        )
        if port in (1, 2):
            sim.rx_octets = 1_000_000
            sim.tx_octets = 2_000_000
            sim.rx_errors = 0
        ports[port] = sim

    vlans = {
        1: VlanSim(name="", member=set(range(1, 11)), untagged=set(range(1, 11))),
        90: VlanSim(name="", member={1, 2, 10}, untagged={1, 2}),
    }
    pvids = dict.fromkeys(range(1, 11), 1)
    pvids[1] = 90
    pvids[2] = 90

    mgmt = MgmtSim(
        address="10.1.5.20", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gs110emx",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        mgmt=mgmt,
        model_name="GS110EMX",
        serial="53H6025EA0083",
        firmware="1.0.0.7",
        hostname="plus-sw",
        nsdp_password="password",
    )
