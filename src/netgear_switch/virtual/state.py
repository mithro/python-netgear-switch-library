"""The one authoritative in-memory virtual-switch device state.

``VirtualSwitchState`` holds everything a simulated switch "knows" about
itself — port link/admin/speed, counters, VLANs, PoE, sensors, the MAC/FDB
table, LLDP neighbours and the management IP — as small mutable ``*Sim``
dataclasses. ``oid_map()`` projects that state onto the flat numeric
OID -> (snmp_type, value) view a protocol face (Task 15) serves and the
Task 5-9 parsers consume. This module is pure data + projection: no network.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..registry import get_model


def encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a latin-1 bitmap.

    Bit 7 (MSB) of byte 0 is port 1, matching the decode side. The result is
    grown past ``width_bytes`` if a port number requires it, so callers never
    need to pre-size the buffer for the actual port count.
    """
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return data.decode("latin-1")


@dataclass
class PortSim:
    """One switch port's link/admin/speed/name plus optional HC counters.

    Counters are ``int | None``: ``None`` means "this port does not expose
    this counter" and must round-trip to an *absent* row in ``oid_map()`` (no
    fabricated zero), so ``parse_port_stats`` yields ``None`` there too.
    """

    name: str
    admin: bool
    link: bool
    speed: int
    rx_octets: int | None = None
    tx_octets: int | None = None
    rx_ucast: int | None = None
    tx_ucast: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None


@dataclass
class VlanSim:
    """One dot1q VLAN: display name plus egress-member and untagged port sets."""

    name: str
    member: set[int] = field(default_factory=set)
    untagged: set[int] = field(default_factory=set)


@dataclass
class PoeSim:
    """One PoE port: RFC3621 admin/detect state plus vendor delivered power."""

    admin: bool
    detect: int
    power_mw: int = 0


@dataclass
class SensorSim:
    """One box sensor reading (fan RPM / PSU watts / temperature).

    ``raw`` is the literal wire text: either a decimal integer string or
    Netgear's ``"Not Supported"`` placeholder for an unpopulated slot.
    """

    kind: str  # "fan" | "power" | "temperature"
    instance: str
    raw: str


@dataclass
class MacSim:
    """One learned MAC/FDB entry: VLAN, 6-byte MAC, bridge-port index."""

    vlan: int
    mac_bytes: tuple[int, int, int, int, int, int]
    bridge_port: int


@dataclass
class LldpSim:
    """One lldpRemTable neighbour row group."""

    time_mark: int
    local_port: int
    rem_idx: int
    chassis: str
    port_id: str
    port_desc: str
    sys_name: str


@dataclass
class MgmtSim:
    """The switch's own management-IP configuration."""

    address: str
    netmask: str
    gateway: str
    mode: str  # "static" | "dhcp"


@dataclass
class VirtualSwitchState:
    """The one authoritative virtual-switch device state.

    A mutable holder (later slices mutate it to simulate writes); pure data
    plus the ``oid_map()`` SNMP projection, no network here.
    """

    model_key: str
    ports: dict[int, PortSim] = field(default_factory=dict)
    vlans: dict[int, VlanSim] = field(default_factory=dict)
    pvids: dict[int, int] = field(default_factory=dict)
    poe: dict[int, PoeSim] = field(default_factory=dict)
    sensors: list[SensorSim] = field(default_factory=list)
    macs: list[MacSim] = field(default_factory=list)
    bridge_ports: dict[int, int] = field(default_factory=dict)
    lldp: list[LldpSim] = field(default_factory=list)
    mgmt: MgmtSim = field(
        default_factory=lambda: MgmtSim(
            address="0.0.0.0", netmask="0.0.0.0", gateway="0.0.0.0", mode="dhcp"
        )
    )

    def oid_map(self) -> dict[str, tuple[str, str]]:
        """Project this state onto the full numeric OID -> (type, value) view.

        Built directly from the exact OID layouts in ``protocols.snmp.oids``
        so a protocol face can serve it and the Task 5-9 parsers reconstruct
        the seeded state from what the face returns.
        """
        from ..protocols.snmp import oids

        v = oids.vendor_oids(get_model(self.model_key))
        m: dict[str, tuple[str, str]] = {}

        for port, sim in self.ports.items():
            m[f"{oids.IF_ADMIN_STATUS}.{port}"] = ("INTEGER", "1" if sim.admin else "2")
            m[f"{oids.IF_OPER_STATUS}.{port}"] = ("INTEGER", "1" if sim.link else "2")
            m[f"{oids.IF_HIGH_SPEED}.{port}"] = ("Gauge32", str(sim.speed))
            m[f"{oids.IF_NAME}.{port}"] = ("OCTETSTR", sim.name)
            # Port stats: only emit a counter the port actually exposes
            # (None -> skip, so parse_port_stats yields None there, never a
            # fabricated 0).
            stat_cols: tuple[tuple[str, str, int | None], ...] = (
                (oids.IF_HC_IN_OCTETS, "Counter64", sim.rx_octets),
                (oids.IF_HC_OUT_OCTETS, "Counter64", sim.tx_octets),
                (oids.IF_HC_IN_UCAST, "Counter64", sim.rx_ucast),
                (oids.IF_HC_OUT_UCAST, "Counter64", sim.tx_ucast),
                (oids.IF_IN_ERRORS, "Counter32", sim.rx_errors),
                (oids.IF_OUT_ERRORS, "Counter32", sim.tx_errors),
            )
            for base, typ, val in stat_cols:
                if val is not None:
                    m[f"{base}.{port}"] = (typ, str(val))

        for vid, vsim in self.vlans.items():
            m[f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}"] = ("OCTETSTR", vsim.name)
            m[f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"] = (
                "OCTETSTR", encode_port_bitmap(vsim.member))
            m[f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"] = (
                "OCTETSTR", encode_port_bitmap(vsim.untagged))

        for port, pv in self.pvids.items():
            m[f"{oids.DOT1Q_PVID}.{port}"] = ("Gauge32", str(pv))

        for port, psim in self.poe.items():
            m[f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"] = (
                "INTEGER", "1" if psim.admin else "2")
            m[f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}"] = (
                "INTEGER", str(psim.detect))
            m[f"{v.poe_power_mw}.1.{port}"] = ("Gauge32", str(psim.power_mw))

        for ssim in self.sensors:
            base = {
                "fan": v.box_fan,
                "power": v.box_psu_power,
                "temperature": v.box_temp,
            }[ssim.kind]
            m[f"{base}.{ssim.instance}"] = ("OCTETSTR", ssim.raw)

        # MAC/FDB: dot1qTpFdbPort values keyed by <vlan>.<6 MAC bytes>, plus
        # the dot1dBasePortIfIndex bridge-port -> ifIndex rows the parser
        # joins on.
        for msim in self.macs:
            mac_suffix = ".".join(str(b) for b in msim.mac_bytes)
            m[f"{oids.DOT1Q_TP_FDB_PORT}.{msim.vlan}.{mac_suffix}"] = (
                "INTEGER", str(msim.bridge_port))
        for bridge_port, ifindex in self.bridge_ports.items():
            m[f"{oids.DOT1D_BASE_PORT_IF_INDEX}.{bridge_port}"] = (
                "INTEGER", str(ifindex))

        # LLDP remote neighbours across lldpRemTable columns 5/7/8/9.
        for nb in self.lldp:
            idx = f"{nb.time_mark}.{nb.local_port}.{nb.rem_idx}"
            m[f"{oids.LLDP_REM_TABLE}.1.5.{idx}"] = ("OCTETSTR", nb.chassis)
            m[f"{oids.LLDP_REM_TABLE}.1.7.{idx}"] = ("OCTETSTR", nb.port_id)
            m[f"{oids.LLDP_REM_TABLE}.1.8.{idx}"] = ("OCTETSTR", nb.port_desc)
            m[f"{oids.LLDP_REM_TABLE}.1.9.{idx}"] = ("OCTETSTR", nb.sys_name)

        # mgmt-ip: ipAddrTable + ipRouteTable + DHCP mode.
        idx = self.mgmt.address
        m[f"{oids.IP_ADENT_ADDR}.{idx}"] = ("IPADDR", self.mgmt.address)
        m[f"{oids.IP_ADENT_NETMASK}.{idx}"] = ("IPADDR", self.mgmt.netmask)
        m[f"{oids.IP_ROUTE_DEST}.0.0.0.0"] = ("IPADDR", "0.0.0.0")
        m[f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0"] = ("IPADDR", self.mgmt.gateway)
        # Single named UNVERIFIED DHCP-mode OID (Task 4) — never a bare
        # ".99.1" literal.
        m[f"{v.dhcp_mode_unverified}.0"] = (
            "INTEGER", "2" if self.mgmt.mode == "static" else "1")

        return m
