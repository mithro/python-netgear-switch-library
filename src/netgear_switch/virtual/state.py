"""The one authoritative in-memory virtual-switch device state.

``VirtualSwitchState`` holds everything a simulated switch "knows" about
itself — port link/admin/speed, counters, VLANs, PoE, sensors, the MAC/FDB
table, LLDP neighbours and the management IP — as small mutable ``*Sim``
dataclasses. ``oid_map()`` projects that state onto the flat numeric
OID -> (snmp_type, value) view a protocol face (Task 15) serves and the
Task 5-9 parsers consume. This module is pure data + projection: no network.
"""
from __future__ import annotations

import copy
import dataclasses
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..registry import get_model

if TYPE_CHECKING:
    from ..protocols.nsdp.protocol import Tag, TLVEntry


def encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a latin-1 bitmap.

    Delegates to the canonical bytes encoder in
    ``protocols/snmp/write.encode_port_bitmap`` (single source of truth for the
    MSB-first bit-packing) and decodes to the latin-1 ``str`` this module's
    callers expect.
    """
    from ..protocols.snmp.write import encode_port_bitmap as _encode_bytes

    return _encode_bytes(ports, width_bytes).decode("latin-1")


def _mbps_to_speed_byte(mbps: int) -> int:
    """Map a negotiated Mbps rate to its NSDP LinkSpeed wire byte."""
    return {10: 0x02, 100: 0x04, 1000: 0x05, 10000: 0xFF}.get(mbps, 0x00)


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
    # ifAlias (operator-set port description). None = this port's ifAlias
    # column instance is entirely absent (never configured), mirroring real
    # hardware where an unset alias may not answer at all -- not a fabricated
    # "".
    description: str | None = None


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
    model_name: str = ""
    serial: str = ""
    firmware: str = ""
    hostname: str = ""
    nsdp_password: str = "password"
    # QoS engine mode (NSDP tag 0x3400): None = unseeded (tag omitted from
    # nsdp_tlvs(), exactly like a real switch that doesn't answer it).
    nsdp_qos_engine: int | None = None
    # Port mirroring (NSDP tag 0x5C00): None destination = unseeded/disabled.
    nsdp_port_mirroring_dest: int | None = None
    nsdp_port_mirroring_sources: frozenset[int] = field(default_factory=frozenset)
    # IGMP snooping (NSDP tag 0x6800): None = unseeded.
    nsdp_igmp_snooping_enabled: bool | None = None
    nsdp_igmp_snooping_vlan: int | None = None
    # Broadcast storm filtering (NSDP tag 0x5400): None = unseeded.
    nsdp_broadcast_filtering: bool | None = None
    # Loop detection (NSDP tag 0x9000): None = unseeded.
    nsdp_loop_detection: bool | None = None
    # Fixed seed MAC for device identity: the NSDP identity TLV (Tag.MAC /
    # server_mac) AND the SNMP dot1dBaseBridgeAddress scalar (see oid_map())
    # both project this same value -- on real hardware they're the same
    # physical base MAC.
    nsdp_mac: bytes = b"\x28\xc6\x8e\x00\x00\x01"
    # MIB-II sysDescr (Task 2 model detection). Empty means unseeded: oid_map()
    # falls back to a generic-but-real-model-name text derived from the
    # registry's own display_name, so sysDescr-based detection works out of
    # the box for every SNMP-capable registered model, not just the ones with
    # a hand-authored seed_*() (see seed_gsm7252ps for the hand-seeded case).
    sys_descr: str = ""
    # UNVERIFIED sysObjectID test fixture -- see oid_map(). There is no known
    # real sysObjectID -> model table (no MIBs/captures/prior-art exist for
    # one); this value is NEVER a claim about real hardware, purely a
    # plausible-looking virtual/test placeholder under the model's own
    # 1.3.6.1.4.1.4526 vendor subtree, so sysObjectID round-trips end-to-end.
    # Empty means unseeded: oid_map() derives one from the model's vendor base.
    sys_object_id: str = ""
    # dot1dBaseBridgeAddress wire quirk: VERIFIED on the real M4300-24X (see
    # protocols/snmp/parse.py::_mac_from_ascii_text) -- that firmware answers
    # this scalar as a 17-character ASCII colon-hex STRING ("XX:XX:..:XX")
    # rather than the 6 raw OCTET STRING bytes every other captured model
    # (gsm7252ps, m4300-16x) uses. False (the default) emits the normal raw
    # 6-byte encoding; only a seed with hardware evidence of this quirk
    # should set it True.
    dot1d_base_mac_ascii: bool = False

    def oid_map(self) -> dict[str, tuple[str, str]]:
        """Project this state onto the full numeric OID -> (type, value) view.

        Built directly from the exact OID layouts in ``protocols.snmp.oids``
        so a protocol face can serve it and the Task 5-9 parsers reconstruct
        the seeded state from what the face returns.
        """
        from ..protocols.snmp import oids
        from ..protocols.snmp.write import vlan_bitmap_width

        model = get_model(self.model_key)
        v = oids.vendor_oids(model)
        vlan_width = vlan_bitmap_width(model)
        m: dict[str, tuple[str, str]] = {}

        # dot1dBaseBridgeAddress (BRIDGE-MIB scalar): the switch's own base
        # MAC. Reuses `nsdp_mac` -- on a real device the SNMP bridge base
        # address and the NSDP-reported identity MAC are the same physical
        # address, so one seed value serves both protocol faces. Most models
        # emit the standard raw 6-byte OCTET STRING; `dot1d_base_mac_ascii`
        # (verified on the real M4300-24X) instead emits the 17-character
        # ASCII colon-hex text form -- see `_mac_from_ascii_text`.
        if self.dot1d_base_mac_ascii:
            base_mac_wire = ":".join(f"{b:02X}" for b in self.nsdp_mac)
        else:
            base_mac_wire = self.nsdp_mac.decode("latin-1")
        m[f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0"] = ("OCTETSTR", base_mac_wire)

        # MIB-II System group (Task 2 model detection). sysDescr is a REAL,
        # honestly-matchable signal (a real switch's own sysDescr text
        # contains its model name); sysObjectID has no known OID->model
        # table, so the value projected here is an UNVERIFIED virtual/test
        # fixture only -- see the field docstrings above, never trust it as
        # ground truth for a real device.
        m[oids.SYS_DESCR] = (
            "OCTETSTR", self.sys_descr or f"Netgear {model.display_name}"
        )
        m[oids.SYS_OBJECT_ID] = ("OID", self.sys_object_id or f"{v.base}.1")

        for port, sim in self.ports.items():
            m[f"{oids.IF_ADMIN_STATUS}.{port}"] = ("INTEGER", "1" if sim.admin else "2")
            m[f"{oids.IF_OPER_STATUS}.{port}"] = ("INTEGER", "1" if sim.link else "2")
            m[f"{oids.IF_HIGH_SPEED}.{port}"] = ("Gauge32", str(sim.speed))
            m[f"{oids.IF_NAME}.{port}"] = ("OCTETSTR", sim.name)
            if sim.description is not None:
                m[f"{oids.IF_ALIAS}.{port}"] = ("OCTETSTR", sim.description)
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
                "OCTETSTR", encode_port_bitmap(vsim.member, width_bytes=vlan_width))
            m[f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"] = (
                "OCTETSTR", encode_port_bitmap(vsim.untagged, width_bytes=vlan_width))

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

    def snapshot(self) -> VirtualSwitchState:
        """Deep-copy this state, for atomic multi-varbind SET rollback.

        A single SNMP SET PDU can carry several varbinds (e.g.
        ``set_vlan_membership`` writing both the egress and untagged
        bitmaps in one ``set_many`` call) and a real agent guarantees they
        apply all-or-nothing. ``faces/snmp.py``'s ``write_variables``
        snapshots the state before applying a PDU's varbinds and calls
        ``restore`` on this snapshot if any of them fails, so a partial
        mutation is never observable. See ``restore``.
        """
        return copy.deepcopy(self)

    def restore(self, snapshot: VirtualSwitchState) -> None:
        """Restore this state in place from a prior ``snapshot()`` result.

        Copies every dataclass field from ``snapshot`` onto ``self`` rather
        than replacing ``self`` itself, so existing references to this exact
        object (e.g. ``VirtualSwitch.state``, ``StateMibView._state``) keep
        seeing the restored data.
        """
        for f in dataclasses.fields(self):
            setattr(self, f.name, getattr(snapshot, f.name))

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

    def nsdp_tlvs(self, tags: set[Tag]) -> list[TLVEntry]:
        """Project this state onto NSDP read TLVs for the requested tags.

        MODEL / MAC / PORT_COUNT identity is always included (a real Plus switch
        echoes it, and ``parse_device`` needs the model + a port count to size
        VLAN bitmaps). Only tags this mock knows are emitted; unknown requested
        tags are silently skipped, exactly as real hardware does.
        """
        import socket

        from ..protocols.nsdp.protocol import Tag, TLVEntry

        model = get_model(self.model_key)
        port_count = model.port_count
        width = (port_count + 7) // 8
        model_bytes = (self.model_name or model.display_name).encode("ascii")
        # STRICT: answer with ONLY the tags requested. Real Plus hardware does
        # exactly this -- a read that omits MODEL gets a MODEL-less response,
        # which is why every per-op read must request it (see nsdp_read
        # ``_with_model``). Emitting identity tags unconditionally, as this used
        # to, made the mock over-serve and hid that bug from CI entirely.
        out: list[TLVEntry] = []
        if Tag.MODEL in tags:
            out.append(TLVEntry(Tag.MODEL, model_bytes))
        if Tag.MAC in tags:
            out.append(TLVEntry(Tag.MAC, self.nsdp_mac))
        if Tag.PORT_COUNT in tags:
            out.append(TLVEntry(Tag.PORT_COUNT, bytes([port_count])))
        if Tag.SERIAL_NUMBER in tags and self.serial:
            serial_bytes = b"\x01" + self.serial.encode("ascii")
            out.append(TLVEntry(Tag.SERIAL_NUMBER, serial_bytes))
        if Tag.HOSTNAME in tags and self.hostname:
            out.append(TLVEntry(Tag.HOSTNAME, self.hostname.encode("ascii")))
        if Tag.FIRMWARE_VER_1 in tags and self.firmware:
            out.append(TLVEntry(Tag.FIRMWARE_VER_1, self.firmware.encode("ascii")))
        if Tag.PORT_STATUS in tags:
            for port, sim in sorted(self.ports.items()):
                speed_byte = _mbps_to_speed_byte(sim.speed) if sim.link else 0x00
                out.append(TLVEntry(Tag.PORT_STATUS, bytes([port, speed_byte, 0x01])))
        if Tag.PORT_STATISTICS in tags:
            # Real hardware returns a PORT_STATISTICS TLV for EVERY port, with
            # zeroed counters on idle ports (verified on a real GS105PE, whose
            # capture has all 5 rows). Previously ports with rx_octets=None were
            # skipped, so the NSDP face disagreed with the HTTP face -- which
            # renders every port -- for the SAME state, hiding any lost-row bug.
            for port, sim in sorted(self.ports.items()):
                out.append(
                    TLVEntry(
                        Tag.PORT_STATISTICS,
                        bytes([port])
                        + struct.pack(">Q", sim.rx_octets or 0)
                        + struct.pack(">Q", sim.tx_octets or 0)
                        + struct.pack(">Q", sim.rx_errors or 0)
                        + b"\x00" * 24,
                    )
                )
        if Tag.VLAN_MEMBERS in tags:
            from ..protocols.nsdp.parsers import ports_to_bitmap
            for vid, vsim in sorted(self.vlans.items()):
                tagged = vsim.member - vsim.untagged
                out.append(
                    TLVEntry(
                        Tag.VLAN_MEMBERS,
                        struct.pack(">H", vid)
                        + ports_to_bitmap(vsim.member, width)
                        + ports_to_bitmap(tagged, width),
                    )
                )
        if Tag.PORT_PVID in tags:
            for port, pv in sorted(self.pvids.items()):
                pvid_bytes = bytes([port]) + struct.pack(">H", pv)
                out.append(TLVEntry(Tag.PORT_PVID, pvid_bytes))
        if Tag.IP_ADDRESS in tags:
            out.append(TLVEntry(Tag.IP_ADDRESS, socket.inet_aton(self.mgmt.address)))
        if Tag.NETMASK in tags:
            out.append(TLVEntry(Tag.NETMASK, socket.inet_aton(self.mgmt.netmask)))
        if Tag.GATEWAY in tags:
            out.append(TLVEntry(Tag.GATEWAY, socket.inet_aton(self.mgmt.gateway)))
        if Tag.DHCP_MODE in tags:
            dhcp_byte = b"\x00" if self.mgmt.mode == "static" else b"\x01"
            out.append(TLVEntry(Tag.DHCP_MODE, dhcp_byte))
        if Tag.QOS_ENGINE in tags and self.nsdp_qos_engine is not None:
            out.append(TLVEntry(Tag.QOS_ENGINE, bytes([self.nsdp_qos_engine])))
        if Tag.PORT_MIRRORING in tags and self.nsdp_port_mirroring_dest is not None:
            from ..protocols.nsdp.parsers import ports_to_bitmap
            # The source-port bitmap width is MODEL-dependent on real hardware:
            # a 5-port GS105PE returns a 2-byte bitmap (3-byte TLV) while a
            # 10-port GS110EMX returns 3 bytes. Hard-coding 3 meant the mock
            # could never reproduce the narrow TLV that broke
            # parse_port_mirroring, so derive it from port_count exactly like
            # the VLAN bitmap above.
            out.append(
                TLVEntry(
                    Tag.PORT_MIRRORING,
                    bytes([self.nsdp_port_mirroring_dest])
                    + ports_to_bitmap(self.nsdp_port_mirroring_sources, width),
                )
            )
        if Tag.IGMP_SNOOPING in tags and self.nsdp_igmp_snooping_enabled is not None:
            vlan_byte = self.nsdp_igmp_snooping_vlan or 0
            out.append(
                TLVEntry(
                    Tag.IGMP_SNOOPING,
                    bytes([0x00, 1 if self.nsdp_igmp_snooping_enabled else 0,
                           0x00, vlan_byte]),
                )
            )
        if (Tag.BROADCAST_FILTERING in tags
                and self.nsdp_broadcast_filtering is not None):
            out.append(
                TLVEntry(
                    Tag.BROADCAST_FILTERING,
                    bytes([1 if self.nsdp_broadcast_filtering else 0]),
                )
            )
        if Tag.LOOP_DETECTION in tags and self.nsdp_loop_detection is not None:
            out.append(
                TLVEntry(
                    Tag.LOOP_DETECTION,
                    bytes([1 if self.nsdp_loop_detection else 0]),
                )
            )
        return out

    def apply_nsdp_write(self, tag: Tag | int, value: bytes) -> None:
        """Mutate this state from one NSDP write TLV (verify-after-write reads it
        back). Unknown/read-only tags are a deliberate no-op."""
        import socket

        from ..protocols.nsdp.parsers import parse_vlan_members
        from ..protocols.nsdp.protocol import Tag

        model = get_model(self.model_key)
        if tag == Tag.PORT_PVID:
            self.pvids[value[0]] = struct.unpack_from(">H", value, 1)[0]
        elif tag == Tag.VLAN_MEMBERS:
            m = parse_vlan_members(value, model.port_count)
            existing = self.vlans.get(m.vlan_id)
            name = existing.name if existing is not None else ""
            self.vlans[m.vlan_id] = VlanSim(
                name=name,
                member=set(m.member_ports),
                untagged=set(m.untagged_ports),
            )
        elif tag == Tag.IP_ADDRESS:
            self.mgmt.address = socket.inet_ntoa(value)
        elif tag == Tag.NETMASK:
            self.mgmt.netmask = socket.inet_ntoa(value)
        elif tag == Tag.GATEWAY:
            self.mgmt.gateway = socket.inet_ntoa(value)
        elif tag == Tag.DHCP_MODE:
            self.mgmt.mode = "dhcp" if value[:1] == b"\x01" else "static"
        # REBOOT / FACTORY_RESET / unknown: deliberate no-op.

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

    def is_oid_implemented(self, oid: str) -> bool:
        """True unless ``oid`` falls under a MIB subtree this model's real
        SNMP agent never registers at all (e.g. the RFC3621 PoE MIB on a
        non-PoE model) -- see ``protocols.snmp.oids.is_oid_implemented``.
        Used by ``StateMibView``/``faces/snmp.py`` to answer ``noSuchObject``
        for such a request instead of silently walking into an unrelated
        subtree.
        """
        from ..protocols.snmp import oids

        return oids.is_oid_implemented(get_model(self.model_key), oid)
