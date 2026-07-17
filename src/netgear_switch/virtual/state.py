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

    Delegates to the canonical bytes encoder in
    ``protocols/snmp/write.encode_port_bitmap`` (single source of truth for the
    MSB-first bit-packing) and decodes to the latin-1 ``str`` this module's
    callers expect.
    """
    from ..protocols.snmp.write import encode_port_bitmap as _encode_bytes

    return _encode_bytes(ports, width_bytes).decode("latin-1")


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

    def apply_write(self, oid: str, value: int | bytes | str) -> None:
        """Mutate this state from one SNMP SET varbind, with device coherence.

        Dispatches on the OID's column prefix. Applies the same coherence a real
        PoE switch shows so ``cycle_poe`` terminates against the mock: admin off
        -> detect=1 (unused) + data-port link down; admin on -> detect=3
        (delivering). Unhandled writable OIDs are a deliberate no-op (the write
        "succeeds" but reads back unchanged), which is exactly what a
        verify-after-write must catch. (The SNMP face layer additionally
        rejects a SET on an OID ``is_writable_oid`` doesn't recognize at all
        with a proper SNMP error, before it ever reaches here — see
        ``faces/snmp.py``.)
        """
        from ..protocols.snmp import oids
        from ..registry import get_model

        v = oids.vendor_oids(get_model(self.model_key))

        def _tail(base: str) -> int | None:
            prefix = base + "."
            if oid.startswith(prefix) and oid[len(prefix):].isdigit():
                return int(oid[len(prefix):])
            return None

        def _as_bytes(val: int | bytes | str) -> bytes:
            if isinstance(val, bytes):
                return val
            if isinstance(val, str):
                return val.encode("latin-1")
            return bytes([val])

        # ifAdminStatus.<port>
        port = _tail(oids.IF_ADMIN_STATUS)
        if port is not None and port in self.ports:
            self.ports[port].admin = int(value) == 1
            if int(value) != 1:
                self.ports[port].link = False
            return

        # pethPsePortAdminEnable = <table>.3.1.<port>
        poe_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if oid.startswith(poe_prefix) and oid[len(poe_prefix):].isdigit():
            p = int(oid[len(poe_prefix):])
            if p in self.poe:
                on = int(value) == 1
                self.poe[p].admin = on
                self.poe[p].detect = 3 if on else 1  # delivering / unused
                if not on and p in self.ports:
                    self.ports[p].link = False
            return

        # dot1qPvid.<port>
        port = _tail(oids.DOT1Q_PVID)
        if port is not None:
            self.pvids[port] = int(value)
            return

        # dot1qVlanStaticEgressPorts.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_EGRESS)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap
            self.vlans[vid].member = set(decode_port_bitmap(_as_bytes(value)))
            return

        # dot1qVlanStaticUntaggedPorts.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_UNTAGGED)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap
            self.vlans[vid].untagged = set(decode_port_bitmap(_as_bytes(value)))
            return

        # dot1qVlanStaticRowStatus.<vid>  (createAndGo=4 / destroy=6)
        vid = _tail(oids.DOT1Q_VLAN_STATIC_ROW_STATUS)
        if vid is not None:
            if int(value) == oids.ROW_STATUS_DESTROY:
                self.vlans.pop(vid, None)
            elif int(value) == oids.ROW_STATUS_CREATE_AND_GO and vid not in self.vlans:
                self.vlans[vid] = VlanSim(name="")
            return

        # dot1qVlanStaticName.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_NAME)
        if vid is not None:
            name = value.decode("latin-1") if isinstance(value, bytes) else str(value)
            if vid in self.vlans:
                self.vlans[vid].name = name
            else:
                self.vlans[vid] = VlanSim(name=name)
            return

        # UNVERIFIED mgmt-IP write OIDs -> MgmtSim (read projection follows).
        if oid == v.mgmt_write_addr_unverified:
            self.mgmt.address = str(value)
            return
        if oid == v.mgmt_write_netmask_unverified:
            self.mgmt.netmask = str(value)
            return
        if oid == v.mgmt_write_gateway_unverified:
            self.mgmt.gateway = str(value)
            return

        # UNVERIFIED dhcp-mode write OID (same scalar the read projection
        # advertises, mirroring the mgmt-write precedent above): 2=static,
        # anything else=dhcp, matching oid_map()'s own encoding exactly.
        if oid == f"{v.dhcp_mode_unverified}.0":
            self.mgmt.mode = "static" if int(value) == 2 else "dhcp"
            return

        # Unhandled writable OID: deliberate no-op (verify-after-write catches it).

    def is_writable_oid(self, oid: str) -> bool:
        """True if ``oid`` is one this mock recognizes as SNMP-writable.

        Mirrors ``apply_write``'s dispatch prefixes on purpose (single set of
        column constants from ``protocols.snmp.oids``, kept in sync
        deliberately) so the SNMP face (``faces/snmp.py``) can reject a SET on
        a genuinely unknown/read-only OID with a proper SNMP error
        (notWritable) instead of the always-succeeding no-op ``apply_write``
        itself deliberately allows for a recognized-but-absent instance (e.g.
        creating a not-yet-existing VLAN row).
        """
        from ..protocols.snmp import oids
        from ..registry import get_model

        v = oids.vendor_oids(get_model(self.model_key))

        def _is_col(base: str) -> bool:
            prefix = base + "."
            return oid.startswith(prefix) and oid[len(prefix):].isdigit()

        if _is_col(oids.IF_ADMIN_STATUS):
            return True
        poe_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if oid.startswith(poe_prefix) and oid[len(poe_prefix):].isdigit():
            return True
        if _is_col(oids.DOT1Q_PVID):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_EGRESS):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_ROW_STATUS):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_NAME):
            return True
        if oid in (
            v.mgmt_write_addr_unverified,
            v.mgmt_write_netmask_unverified,
            v.mgmt_write_gateway_unverified,
        ):
            return True
        return oid == f"{v.dhcp_mode_unverified}.0"
