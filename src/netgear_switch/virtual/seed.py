"""Hand-authored ``VirtualSwitchState`` seeds, one builder per model.

``seed_gsm7252ps`` is the original, most exhaustively-documented seed: every
read op (Task 5-9) has at least one non-empty, non-vacuous example -- ports
with link/admin/speed, RX/TX counters on >=2 ports, >=1 VLAN with egress/
untagged bitmaps and PVIDs, PoE with a delivering port, fan/temperature/PSU
sensors (including a "Not Supported" fan slot), >=2 MAC/FDB entries with
their bridge-port->ifIndex mappings, >=1 LLDP neighbour, and a static
management IP. This makes the Task 16 SNMP<->SNMP equivalence test (and the
round-trip tests here) exercise real data on every parser, not an empty
table. Port 1 also carries an ifAlias description (ports 2+ deliberately
leave it unset) so the ifAlias column exercises both the present and
absent-instance paths. A sysDescr containing "GSM7252PS" plus a placeholder
sysObjectID (Task 2 model detection) round out the identity signals -- see
``VirtualSwitchState.sys_descr``/``sys_object_id``.

``seed_m4300_24x``/``seed_m4300_16x`` are transcribed directly from the
committed real-hardware captures (``tests/fixtures/captures/m4300-*.json``)
rather than hand-invented, so the M4300 pair's headline capability contrast
(24X has NO PoE, 16X has PoE on all 16 ports) is grounded, not guessed -- see
each function's docstring for exactly what is captured-real vs illustrative.
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
    """Build an ILLUSTRATIVE GSM7252PS (52-port, 48-PoE) virtual switch state.

    HAND-INVENTED, not transcribed. A real capture of this model DOES exist
    (``tests/fixtures/captures/gsm7252ps.json``) and this seed CONTRADICTS it
    throughout -- mgmt 10.1.5.20 vs the captured 10.1.5.22, 2 VLANs vs the real
    14, one PoE port delivering vs 31, and a temperature sensor the real
    capture does not have at all. The values here are chosen so every SNMP read
    op has a non-vacuous example (see this module's docstring), NOT to describe
    a real device; do not treat any of them as observed. ``capture_parity.py``
    cites this function as the canonical example of an illustrative seed."""
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
        if port == 1:
            sim.description = "uplink-to-core"  # port 2+ left None: absent ifAlias
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
        # Illustrative sysDescr text -- NOT a captured real firmware string;
        # its only requirement is containing the model name "GSM7252PS" so
        # detect_model_from_sysdescr's string matching has something real to
        # key off end-to-end. sys_object_id is a plausible-looking UNVERIFIED
        # virtual/test placeholder under the model's own 4526.10 vendor
        # subtree -- NOT a claim about the real device's sysObjectID (no
        # capture of the real value exists).
        sys_descr="NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6",
        sys_object_id="1.3.6.1.4.1.4526.10.100.14",
    )


def seed_gsm7228ps() -> VirtualSwitchState:
    """Build a MINIMAL-BUT-VALID GSM7228PS (S3300, 52-port/48-PoE Smart
    Managed Pro) virtual switch state.

    ``gsm7228ps`` is registered ``verified=True`` in ``registry.py`` for its
    SNMP+HTTP backends and port/PoE counts (52/48, matching the real product
    spec) -- but that registry fact is NOT a claim that any value seeded here
    is captured-real. Unlike ``seed_gsm7252ps`` (the codebase's original,
    most-exhaustively-worked illustrative seed) or the M4300 pair (literal
    capture transcriptions -- see their own docstrings), NO real-hardware
    capture exists for this model at all. This seed exists purely so
    ``VirtualSwitch("gsm7228ps")`` can serve every SNMP read op non-vacuously
    for testing, following the exact shape of ``seed_gsm7252ps`` (same real
    port/PoE counts) but with entirely illustrative/structural data -- same
    honesty convention as that function's own ``sys_object_id`` precedent:
    never a claim about a real GSM7228PS's actual configuration.
    """
    ports: dict[int, PortSim] = {}
    for port in range(1, _TOTAL_PORT_COUNT + 1):
        sim = PortSim(
            name=_port_name(port),
            admin=True,
            link=port != 3,  # port 3 is admin-up but link-down
            speed=1000,
        )
        if port in (1, 2):
            sim.rx_octets = 500_000
            sim.tx_octets = 700_000
            sim.rx_ucast = 4_000
            sim.tx_ucast = 4_500
            sim.rx_errors = 0
            sim.tx_errors = 0
        if port == 1:
            sim.description = "uplink-to-core"  # port 2+ left None: absent ifAlias
        ports[port] = sim

    vlans = {
        1: VlanSim(
            name="default",
            member=set(range(1, _TOTAL_PORT_COUNT + 1)),
            untagged=set(range(3, _TOTAL_PORT_COUNT + 1)),
        ),
        50: VlanSim(name="lab", member={1, 2, 5}, untagged={1, 2}),
    }

    pvids = dict.fromkeys(range(1, _TOTAL_PORT_COUNT + 1), 1)
    pvids[1] = 50
    pvids[2] = 50

    poe: dict[int, PoeSim] = {}
    for port in range(1, _POE_PORT_COUNT + 1):
        if port == 1:
            poe[port] = PoeSim(admin=True, detect=3, power_mw=9_000)
        else:
            poe[port] = PoeSim(admin=True, detect=1, power_mw=0)

    sensors = [
        SensorSim(kind="fan", instance="0", raw="3200"),
        SensorSim(kind="power", instance="0", raw="45"),
        SensorSim(kind="temperature", instance="0", raw="40"),
    ]

    macs = [
        MacSim(vlan=50, mac_bytes=(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), bridge_port=1),
        MacSim(vlan=1, mac_bytes=(0x00, 0x11, 0x22, 0x33, 0x44, 0x56), bridge_port=2),
    ]

    lldp = [
        LldpSim(
            time_mark=1,
            local_port=1,
            rem_idx=1,
            chassis="".join(chr(b) for b in (0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            port_id="eth0",
            port_desc="lab-uplink",
            sys_name="sw-lab-example",
        ),
    ]

    mgmt = MgmtSim(
        address="10.1.5.21", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gsm7228ps",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        mgmt=mgmt,
        # Illustrative sysDescr/sysObjectID -- same honesty convention as
        # seed_gsm7252ps: sysDescr just needs to contain the real model name;
        # sysObjectID is a plausible-looking UNVERIFIED placeholder under this
        # model's own 4526.11 (Smart Managed Pro) vendor subtree, never a
        # claim about real hardware (no capture exists to confirm either).
        sys_descr="NETGEAR GSM7228PS (S3300) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.11.100.28",
    )


def seed_gs110emx() -> VirtualSwitchState:
    """Build a GS110EMX (10-port Plus, NSDP+HTTP) state from the REAL capture.

    Identity, mgmt-IP and per-port link/speed/description are transcribed from
    this model's OWN committed captures (``tests/fixtures/http/
    gs110emx_{sysinfo,port_settings,interface_stats}.html``, host 10.1.5.25):
    ports 6/8/9/10 up at 100M/1G/10G/10G with port 8 described "rumpus", the
    rest down; static 10.1.5.25/24 via 10.1.5.1; MAC bc:a5:11:b8:ec:f1.

    Previously these were hand-invented values (hostname "plus-sw", 10.1.5.20,
    the default MAC, 1M/2M counters on idle ports, all-untagged VLAN 1, PVIDs
    90) that CONTRADICTED this model's own captures while tests pinned them as
    if true. Now transcribed: identity, mgmt-IP, port link/speed/description,
    per-port counters, VLAN 1 membership and every PVID.

    STILL ILLUSTRATIVE (no capture exists, and this says so rather than
    implying otherwise): VLAN 90's member/untagged sets -- only VLAN 1's
    membership page was captured -- and the QoS/mirroring/IGMP/broadcast/
    loop-detection tag values further down, which are test fixtures chosen so
    nsdp_device() has something non-vacuous to decode on every parsed tag.
    """
    real_speed = {6: 100, 8: 1000, 9: 10000, 10: 10000}
    # Counters transcribed from gs110emx_interface_stats.html: traffic is on
    # 6/8/9/10; ports 1-5 and 7 really are all zeros. (An earlier seed put
    # 1M/2M on ports 1-2, contradicting that same capture.)
    real_octets = {
        6: (0, 70_892_018_242),
        8: (59_921_732_691, 78_637_274_870),
        9: (2_963_140_428_936, 1_189_358_575_871),
        10: (1_195_417_274_187, 3_027_396_511_187),
    }
    ports: dict[int, PortSim] = {}
    for port in range(1, 11):
        sim = PortSim(
            name=f"g{port}",
            admin=True,
            link=port in real_speed,
            speed=real_speed.get(port, 0),
            description="rumpus" if port == 8 else None,
        )
        sim.rx_octets, sim.tx_octets = real_octets.get(port, (0, 0))
        sim.rx_errors = 0
        ports[port] = sim

    # VLAN 1 membership is TRANSCRIBED from gs110emx_vlanmembership.html
    # (hiddenMem "1111111122" = ports 1-8 untagged, 9-10 tagged). VLAN 90 is
    # one of the 12 VLAN IDs the real Cf8021q capture lists, but its MEMBERSHIP
    # was never captured (only VLAN 1's page was), so the member/untagged sets
    # for it are ILLUSTRATIVE, not observed.
    vlans = {
        1: VlanSim(name="", member=set(range(1, 11)), untagged=set(range(1, 9))),
        90: VlanSim(name="", member={1, 2, 10}, untagged={1, 2}),
    }
    # Transcribed from gs110emx_pvid.html: every port is PVID 1 on this unit.
    pvids = dict.fromkeys(range(1, 11), 1)

    mgmt = MgmtSim(
        address="10.1.5.25", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gs110emx",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        mgmt=mgmt,
        model_name="GS110EMX",
        serial="53H60253A0032",
        firmware="1.0.1.4",
        hostname="sw-netgear-gs110emx1",
        nsdp_mac=b"\xbc\xa5\x11\xb8\xec\xf1",
        nsdp_password="password",
        # QoS/mirroring/IGMP/broadcast-filtering/loop-detection test fixtures
        # (Slice 9b): illustrative, non-vacuous values so nsdp_device() has
        # something real to decode on every one of the 5 newly-parsed tags.
        nsdp_qos_engine=1,  # port-based
        nsdp_port_mirroring_dest=10,
        nsdp_port_mirroring_sources=frozenset({1, 2}),
        nsdp_igmp_snooping_enabled=True,
        nsdp_igmp_snooping_vlan=90,
        nsdp_broadcast_filtering=True,
        nsdp_loop_detection=True,
    )


def seed_gs305ep() -> VirtualSwitchState:
    """Build an ILLUSTRATIVE GS305EP (5-port, PoE ports 1-4) virtual state.

    HAND-INVENTED: no capture of any kind exists for gs305ep. The port speeds,
    the 12800 mW PoE reading, VLAN 90 and the PVIDs are all structural test
    data, NOT observed values -- same convention as ``seed_gsm7228ps``, which
    says so explicitly. Only the shape is grounded: the Plus family genuinely
    has no MAC/FDB, no box sensors and no LLDP over its web UI.
    """
    ports = {
        p: PortSim(
            name=f"Port {p}", admin=p != 3, link=p == 1, speed=1000 if p == 1 else 0
        )
        for p in range(1, 6)
    }
    ports[1].rx_octets = 1_000_000
    ports[1].tx_octets = 2_000_000
    ports[1].rx_errors = 0
    vlans = {
        1: VlanSim(name="default", member={1, 2, 3, 4, 5}, untagged={3, 4, 5}),
        90: VlanSim(name="iot", member={1, 2}, untagged={1, 2}),
    }
    pvids = {1: 90, 2: 90, 3: 1, 4: 1, 5: 1}
    poe = {
        1: PoeSim(admin=True, detect=3, power_mw=12_800),
        2: PoeSim(admin=True, detect=1, power_mw=0),
        3: PoeSim(admin=True, detect=1, power_mw=0),
        4: PoeSim(admin=False, detect=1, power_mw=0),
    }
    return VirtualSwitchState(
        model_key="gs305ep", ports=ports, vlans=vlans, pvids=pvids, poe=poe
    )


def seed_gs105pe() -> VirtualSwitchState:
    """Build a GS105PE (5-port Plus, NSDP+HTTP) virtual state from a REAL live
    capture (host 10.1.5.30 / poe-micro3, 2026-07-21 -- see
    netgear-m4300-http-cheetah / the gs105pe live findings). Every value below
    is transcribed from the captured NsdpDevice: ports 3 (100M) and 5 (1G) up,
    the rest down; VLANs 1/41/90 with their real member/untagged sets; real
    PVIDs; DHCP mgmt-IP; and the QoS/mirroring/IGMP engine tags. Port mirroring
    is OFF on this unit (dest 0, no sources) -- the 3-byte PORT_MIRRORING TLV
    that exposed the fixed-width parser bug (see parse_port_mirroring)."""
    ports = {
        p: PortSim(
            name=f"Port {p}",
            admin=True,
            link=p in (3, 5),
            speed={3: 100, 5: 1000}.get(p, 0),
        )
        for p in range(1, 6)
    }
    ports[3].tx_octets = 10_246_512
    ports[5].rx_octets = 29_303_468
    ports[5].tx_octets = 289_149
    ports[5].rx_errors = 228_666
    vlans = {
        1: VlanSim(name="", member={5}, untagged={5}),
        41: VlanSim(name="", member={1, 2, 4, 5}, untagged={1, 2, 4}),
        90: VlanSim(name="", member={3, 5}, untagged={3}),
    }
    pvids = {1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
    return VirtualSwitchState(
        model_key="gs105pe",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        mgmt=MgmtSim(
            address="10.1.5.30",
            netmask="255.255.255.0",
            gateway="10.1.5.1",
            mode="dhcp",
        ),
        model_name="GS105PE",
        serial="61W19753A00A8",
        firmware="V1.6.0.4",
        hostname="poe-micro3",
        nsdp_mac=b"\x38\x94\xed\xb7\xcd\xe0",
        nsdp_password="password",
        nsdp_qos_engine=2,
        nsdp_port_mirroring_dest=0,
        nsdp_port_mirroring_sources=frozenset(),
        nsdp_igmp_snooping_enabled=True,
        nsdp_igmp_snooping_vlan=1,
        nsdp_broadcast_filtering=False,
        nsdp_loop_detection=False,
    )


def _mac_hex_to_raw(hexstr: str) -> str:
    """``"88:A2:9E:80:87:01"`` -> the 6 raw latin-1 bytes it represents.

    The real-hardware captures (``tests/fixtures/captures/*.json``) store
    already-PARSED values (e.g. ``MacEntry.mac``/``LLDPNeighbor.remote_chassis_id``
    are colon-hex text), not the raw wire bytes. Seeding ``oid_map()`` needs
    the raw bytes back (a MAC-address chassis/port-id subtype is genuinely
    binary on the wire -- see ``parse._format_chassis_id``/``_format_port_id``),
    so this is the exact inverse of that formatting.
    """
    return "".join(chr(int(p, 16)) for p in hexstr.split(":"))


# M4300-24X (28 registered ports, 0 PoE -- Fully Managed, SNMP-only): every
# value below is transcribed directly from the real captured snapshot
# (tests/fixtures/captures/m4300-24x.json, host 10.1.5.13) -- port
# name/admin/link/speed/description/counters, VLANs (all 14, full real
# member/untagged sets), PVIDs, sensors, and the base MAC. The real switch
# exposes 155 ifIndexes (24 physical + a CPU interface + 128 LAG placeholders
# + 2 VLAN interfaces); only a representative slice of the non-physical ones
# is seeded (the one real in-use LAG plus one unused placeholder, the CPU
# interface, and both VLAN interfaces) rather than all 128 mostly-identical
# unused LAGs -- the model's CAPABILITIES (port count/names/speeds, VLANs,
# PVIDs, sensors, mgmt-IP, and CRUCIALLY the absence of PoE) match the
# capture exactly. dot1dBaseBridgeAddress is VERIFIED to come back as ASCII
# colon-hex text on this exact model (see ``_mac_from_ascii_text``), so
# ``dot1d_base_mac_ascii=True`` here specifically -- NOT on m4300-16x below,
# where no such quirk has been captured.
def seed_m4300_24x() -> VirtualSwitchState:
    """Build a realistic M4300-24X (24-port, non-PoE) virtual switch state."""
    _phys = (  # port, name, admin, link, speed_mbps(0=down), description
        (1, "1/0/1", True, True, 10000, "trunk.sw-cisco-shed"),
        (2, "1/0/2", True, True, 10000, "trunk.gsm7252ps-s1"),
        (3, "1/0/3", True, True, 1000, "bmc.big-storage"),
        (4, "1/0/4", True, False, 0, "bmc.gpu"),
        (5, "1/0/5", True, True, 100, "openmesh.wifi"),
        (6, "1/0/6", True, True, 1000, "eth0.rpi4-ups"),
        (7, "1/0/7", True, False, 0, "empty"),
        (8, "1/0/8", True, False, 0, "empty"),
        (9, "1/0/9", True, True, 1000, "oob1.sw-bb-25g"),
        (10, "1/0/10", True, True, 1000, "oob2.sw-bb-25g"),
        (11, "1/0/11", True, False, 0, "oob1.sw-bb-100g"),
        (12, "1/0/12", True, False, 0, "oob2.sw-bb-100g"),
        (13, "1/0/13", True, False, 0, "bmc1.nvmeof"),
        (14, "1/0/14", True, False, 0, "bmc2.nvmeof"),
        (15, "1/0/15", True, False, 0, "empty"),
        (16, "1/0/16", True, False, 0, "empty"),
        (17, "1/0/17", True, False, 0, "10g1.gpu"),
        (18, "1/0/18", True, False, 0, "10g2.gpu"),
        (19, "1/0/19", True, True, 10000, "10g1.big-storage"),
        (20, "1/0/20", True, True, 10000, "10g2.big-storage"),
        (21, "1/0/21", True, True, 10000, "lag.sw-bb-25g"),
        (22, "1/0/22", True, True, 10000, "lag.sw-bb-25g"),
        (23, "1/0/23", True, True, 10000, "lag.sw-bb-25g"),
        (24, "1/0/24", True, True, 10000, "lag.sw-bb-25g"),
    )
    # (port, rx_bytes, tx_bytes, rx_errors) -- real captured ifHCIn/OutOctets
    # + ifInErrors; tx_errors is 0 for every port on this capture.
    _stats = {
        1: (14778916968081, 11768639639224, 5),
        2: (22592906553, 72917119482, 0),
        3: (2762192715, 3069701383, 0),
        4: (0, 0, 0),
        5: (9928397370, 103562789705, 0),
        6: (2936543951, 6369912656, 0),
        7: (0, 0, 0),
        8: (0, 0, 0),
        9: (241280077, 1045875073, 0),
        10: (79644425, 1532447568, 0),
        11: (0, 0, 0),
        12: (0, 0, 0),
        13: (0, 4321, 0),
        14: (0, 4385, 0),
        15: (0, 0, 0),
        16: (0, 0, 0),
        17: (0, 0, 0),
        18: (0, 0, 0),
        19: (10574049492450, 7436979985884, 0),
        20: (906023695499, 3169248684569, 0),
        21: (46742037001, 214440657859, 0),
        22: (62196040279, 2295667872290, 0),
        23: (53538213549, 4490316365, 0),
        24: (60910004579, 1478343156644, 0),
    }
    ports: dict[int, PortSim] = {}
    for port, name, admin, link, speed, desc in _phys:
        rx_bytes, tx_bytes, rx_errors = _stats[port]
        ports[port] = PortSim(
            name=name, admin=admin, link=link, speed=speed, description=desc,
            rx_octets=rx_bytes, tx_octets=tx_bytes, rx_errors=rx_errors,
            tx_errors=0,
        )
    # Representative non-physical ifIndexes (see module docstring above):
    # the CPU interface, one real in-use LAG + one unused placeholder LAG,
    # and the switch's two VLAN interfaces.
    ports[769] = PortSim(name="CPU Interface:  0/15/1", admin=True, link=True, speed=0)
    ports[770] = PortSim(
        name="lag 1", admin=True, link=True, speed=40000, description="lag.sw-bb-25g"
    )
    ports[771] = PortSim(name="lag 2", admin=True, link=False, speed=0)
    ports[898] = PortSim(name="vlan 1", admin=True, link=True, speed=10)
    ports[899] = PortSim(name="vlan 5", admin=True, link=True, speed=10)

    # All 14 real VLANs, full real member/untagged port sets (including the
    # 128-wide LAG range 770-897 every VLAN's trunk carries) -- `tagged` is
    # always `member - untagged` (see VirtualSwitchState.nsdp_tlvs), matching
    # the capture's own tagged_ports for every VLAN checked.
    _lags = set(range(770, 898))  # lag 1..128 -> ifIndex 770..897
    vlans = {
        1: VlanSim(
            name="default",
            member={1, 2, 5, 7, 8} | _lags,
            untagged={1, 2, 7, 8} | _lags,
        ),
        4: VlanSim(name="wifi", member={1, 2, 770}, untagged=set()),
        5: VlanSim(
            name="net",
            member={1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 770},
            untagged={3, 4, 5, 9, 10, 11, 12, 13, 14},
        ),
        6: VlanSim(name="pwr", member={1, 2, 5, 770}, untagged=set()),
        7: VlanSim(name="store", member={1, 2, 5, 770}, untagged=set()),
        10: VlanSim(
            name="int",
            member={1, 2, 5, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 770},
            untagged={15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
        ),
        20: VlanSim(name="roam", member={1, 2, 5, 770}, untagged=set()),
        21: VlanSim(name="fpgas", member={1, 2, 770}, untagged=set()),
        41: VlanSim(name="sm", member={1, 2, 5, 770}, untagged=set()),
        89: VlanSim(name="sdr", member={1, 2, 770}, untagged=set()),
        90: VlanSim(name="iot", member={1, 2, 5, 6, 770}, untagged={6}),
        99: VlanSim(name="guest", member={1, 2, 5, 770}, untagged=set()),
        121: VlanSim(name="t-fpgas", member={1, 2, 5, 770}, untagged=set()),
        141: VlanSim(name="t-sm", member={1, 2, 5, 770}, untagged=set()),
    }
    pvids = {
        1: 1, 2: 1, 3: 5, 4: 5, 5: 5, 6: 90, 7: 1, 8: 1, 9: 5, 10: 5,
        11: 5, 12: 5, 13: 5, 14: 5, 15: 10, 16: 10, 17: 10, 18: 10, 19: 10,
        20: 10, 21: 10, 22: 10, 23: 10, 24: 10,
    }
    sensors = [
        SensorSim(kind="fan", instance="0", raw="5160"),
        SensorSim(kind="fan", instance="1", raw="4560"),
        SensorSim(kind="power", instance="0", raw="49"),
        SensorSim(kind="temperature", instance="1", raw="49"),
    ]
    # A representative slice of the real (30-capped) captured MAC/FDB table,
    # identity-mapped bridge-port -> ifIndex (see gsm7252ps's seed for the
    # non-identity-mapping case; that path is already covered there).
    macs = [
        MacSim(vlan=1, mac_bytes=(0x00, 0x0A, 0xFA, 0x24, 0x28, 0x20), bridge_port=1),
        MacSim(vlan=90, mac_bytes=(0x00, 0xE0, 0x4C, 0x68, 0x36, 0x95), bridge_port=1),
        MacSim(vlan=1, mac_bytes=(0x02, 0x00, 0x0A, 0x01, 0x00, 0x01), bridge_port=1),
    ]
    # Real LLDP neighbours (a representative few of the capture's list): mixed
    # MAC-shaped (raw-bytes) and plain-text port-id subtypes on purpose, so
    # both `_format_port_id` branches round-trip through the mock.
    lldp = [
        LldpSim(
            time_mark=1, local_port=1, rem_idx=1,
            chassis=_mac_hex_to_raw("88:A2:9E:80:87:01"),
            port_id=_mac_hex_to_raw("88:A2:9E:80:87:01"),
            port_desc="eth0", sys_name="rpi-sdr-kraken",
        ),
        LldpSim(
            time_mark=1, local_port=2, rem_idx=1,
            chassis=_mac_hex_to_raw("E0:91:F5:0C:D6:DB"),
            port_id="1/0/49",  # plain interface name, NOT a MAC -- text subtype
            port_desc="1/0/2.sw-netgear-m4300-24x",
            sys_name="sw-netgear-gsm7252ps-s1.welland.mithis.com",
        ),
        LldpSim(
            time_mark=1, local_port=6, rem_idx=1,
            chassis=_mac_hex_to_raw("E4:5F:01:8D:F4:FD"),
            port_id=_mac_hex_to_raw("E4:5F:01:8D:F4:FD"),
            port_desc="eth0", sys_name="rpi4-ups",
        ),
    ]
    mgmt = MgmtSim(
        address="10.1.5.13", netmask="255.255.255.0", gateway="10.1.5.1",
        # Real capture reports mode="unknown" (the UNVERIFIED DHCP-mode OID
        # -- see VendorOids.dhcp_mode_unverified); "static" is the honest,
        # documented best inference for a device with a real static address,
        # not itself a captured value.
        mode="static",
    )
    return VirtualSwitchState(
        model_key="m4300-24x",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe={},  # VERIFIED: real capture's poe=[] -- this model has NO PoE.
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        mgmt=mgmt,
        # Real captured base MAC (mgmt_ip.base_mac in the capture).
        nsdp_mac=bytes.fromhex("8C3BAD6BBBE0"),
        # VERIFIED on this exact model (see field docstring + parse.py's
        # _mac_from_ascii_text): dot1dBaseBridgeAddress comes back as ASCII
        # colon-hex text on the real M4300-24X, not raw OCTET STRING bytes.
        dot1d_base_mac_ascii=True,
        # Illustrative sysDescr/sysObjectID (Task 2 model detection) -- same
        # honesty convention as seed_gsm7252ps: sysDescr just needs to
        # contain the real model name; sysObjectID has no known real value
        # (no OID->model table exists) so this is a placeholder under the
        # model's own vendor subtree, never a claim about real hardware.
        sys_descr="NETGEAR M4300-24X (XSM4324CS) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.10.100.24",
    )


# M4300-16X (16 registered ports, all 16 PoE -- Fully Managed, SNMP-only):
# same transcription approach as seed_m4300_24x, from
# tests/fixtures/captures/m4300-16x.json (host unrecorded in that capture).
# The real capture's mgmt_ip.address is None (no static IP was ever
# discovered over this OID chain on that device) -- honestly left unseeded
# (the default blank 0.0.0.0/dhcp MgmtSim) rather than inventing one; the
# real captured base MAC is kept, so get_mgmt_ip().base_mac is still real.
# dot1d_base_mac_ascii is NOT set here: only the M4300-24X's ASCII-text quirk
# has been captured/verified (see seed_m4300_24x and parse.py's
# _mac_from_ascii_text docstring) -- this model uses the standard raw-bytes
# encoding.
def seed_m4300_16x() -> VirtualSwitchState:
    """Build a realistic M4300-16X (16-port, all-16 PoE) virtual switch state."""
    _phys = (  # port, name, admin, link, speed_mbps(0=down)
        (1, "1/0/1", True, False, 0),
        (2, "1/0/2", True, False, 0),
        (3, "1/0/3", True, False, 0),
        (4, "1/0/4", True, False, 0),
        (5, "1/0/5", True, False, 0),
        (6, "1/0/6", True, False, 0),
        (7, "1/0/7", True, False, 0),
        (8, "1/0/8", True, False, 0),
        (9, "1/0/9", True, False, 0),
        (10, "1/0/10", True, False, 0),
        (11, "1/0/11", True, True, 1000),
        (12, "1/0/12", True, True, 1000),
        (13, "1/0/13", True, False, 0),
        (14, "1/0/14", True, False, 0),
        (15, "1/0/15", True, False, 0),
        (16, "1/0/16", True, True, 10000),
    )
    # (port, rx_bytes, tx_bytes) -- real captured ifHCIn/OutOctets; every
    # port's ifInErrors/ifOutErrors is 0 on this capture.
    _stats = {
        1: (0, 0), 2: (0, 0), 3: (0, 0), 4: (0, 0), 5: (0, 0), 6: (0, 0),
        7: (0, 0), 8: (0, 0), 9: (0, 0), 10: (0, 0),
        11: (0, 7813924), 12: (30388, 7819868), 13: (0, 0), 14: (0, 0),
        15: (0, 0), 16: (3347925876, 7868391),
    }
    ports: dict[int, PortSim] = {}
    for port, name, admin, link, speed in _phys:
        rx_bytes, tx_bytes = _stats[port]
        ports[port] = PortSim(
            name=name, admin=admin, link=link, speed=speed,
            rx_octets=rx_bytes, tx_octets=tx_bytes, rx_errors=0, tx_errors=0,
        )
    ports[769] = PortSim(name="CPU Interface:  0/15/1", admin=True, link=True, speed=0)
    ports[770] = PortSim(name="lag 1", admin=True, link=False, speed=0)
    ports[898] = PortSim(name="vlan 5", admin=True, link=True, speed=10)

    _lags = set(range(770, 898))
    _uplink_ports = {9, 10, 11, 12, 13, 14, 15, 16}
    vlans = {
        1: VlanSim(
            name="default",
            member=set(range(1, 17)) | _lags,
            untagged=set(range(1, 17)) | _lags,
        ),
        4: VlanSim(name="wifi", member=set(_uplink_ports), untagged=set()),
        5: VlanSim(name="net", member=set(_uplink_ports), untagged=set()),
        6: VlanSim(name="pwr", member=set(_uplink_ports), untagged=set()),
        7: VlanSim(name="store", member=set(_uplink_ports), untagged=set()),
        10: VlanSim(name="int", member=set(_uplink_ports), untagged=set()),
        20: VlanSim(name="roam", member=set(_uplink_ports), untagged=set()),
        21: VlanSim(name="fpgas", member=set(_uplink_ports), untagged=set()),
        41: VlanSim(name="sm", member=set(_uplink_ports), untagged=set()),
        89: VlanSim(name="sdr", member=set(_uplink_ports), untagged=set()),
        90: VlanSim(name="iot", member=set(_uplink_ports), untagged=set()),
        99: VlanSim(name="guest", member=set(_uplink_ports), untagged=set()),
        121: VlanSim(name="t-fpgas", member=set(_uplink_ports), untagged=set()),
        141: VlanSim(name="t-sm", member=set(_uplink_ports), untagged=set()),
    }
    pvids = dict.fromkeys(range(1, 17), 1)
    poe = {
        1: PoeSim(admin=True, detect=2, power_mw=0),
        2: PoeSim(admin=True, detect=2, power_mw=0),
        3: PoeSim(admin=True, detect=2, power_mw=0),
        4: PoeSim(admin=True, detect=2, power_mw=0),
        5: PoeSim(admin=True, detect=2, power_mw=0),
        6: PoeSim(admin=True, detect=2, power_mw=0),
        7: PoeSim(admin=True, detect=2, power_mw=0),
        8: PoeSim(admin=True, detect=2, power_mw=0),
        9: PoeSim(admin=True, detect=2, power_mw=0),
        10: PoeSim(admin=True, detect=2, power_mw=0),
        11: PoeSim(admin=True, detect=3, power_mw=5000),  # delivering
        12: PoeSim(admin=True, detect=3, power_mw=2100),  # delivering
        13: PoeSim(admin=True, detect=2, power_mw=0),
        14: PoeSim(admin=True, detect=2, power_mw=0),
        15: PoeSim(admin=True, detect=2, power_mw=0),
        16: PoeSim(admin=True, detect=2, power_mw=0),
    }
    sensors = [
        SensorSim(kind="fan", instance="0", raw="4200"),
        SensorSim(kind="fan", instance="1", raw="4080"),
        SensorSim(kind="power", instance="0", raw="40"),
        SensorSim(kind="power", instance="1", raw="42"),
        SensorSim(kind="temperature", instance="1", raw="42"),
    ]
    macs = [
        MacSim(vlan=1, mac_bytes=(0x80, 0xCC, 0x9C, 0x91, 0x4F, 0x8C), bridge_port=12),
        MacSim(vlan=90, mac_bytes=(0x00, 0x08, 0xA2, 0x09, 0xEF, 0xED), bridge_port=16),
        MacSim(vlan=1, mac_bytes=(0x00, 0x0A, 0xFA, 0x24, 0x28, 0x1F), bridge_port=16),
    ]
    lldp = [
        LldpSim(
            time_mark=1, local_port=12, rem_idx=1,
            chassis=_mac_hex_to_raw("80:CC:9C:91:4F:8C"),
            port_id="5",  # plain numeric device-port label, NOT a MAC
            port_desc="Device Port 5", sys_name="sw-poe-micro2",
        ),
        LldpSim(
            time_mark=1, local_port=16, rem_idx=1,
            chassis=_mac_hex_to_raw("00:0A:FA:24:28:25"),
            port_id=_mac_hex_to_raw("00:0A:FA:24:28:1F"),
            port_desc="eth8", sys_name="ten64.welland.mithis.com",
        ),
    ]
    return VirtualSwitchState(
        model_key="m4300-16x",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,  # VERIFIED: real capture -- all 16 ports PoE-capable.
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        # mgmt left at the default blank MgmtSim -- honest: the real capture's
        # mgmt_ip.address was None (see module docstring above).
        nsdp_mac=bytes.fromhex("8C3BAD691C38"),  # real captured base MAC
        sys_descr="NETGEAR M4300-16X (XSM4316) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.10.100.16",
    )
