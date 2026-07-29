# src/netgear_switch/protocols/snmp/parse.py
"""Pure SNMP-row -> models.py parsers. No I/O."""
from __future__ import annotations

import string
from typing import TYPE_CHECKING

from ...models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    VLANInfo,
)
from .client import SnmpError, SnmpRow

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ...registry import SwitchModel


def _suffix(row: SnmpRow, base: str) -> str | None:
    prefix = base + "."
    if not row.oid.startswith(prefix):
        return None
    return row.oid[len(prefix):]


def index_int_column(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, int]:
    """Map a single-int-index column walk to {index: int_value}.

    Raises SnmpError on a value that is not an integer under base_oid: the
    walk is pinned to one column, so a non-integer means the table drifted.
    """
    out: dict[int, int] = {}
    for row in rows:
        suffix = _suffix(row, base_oid)
        if suffix is None or "." in suffix:
            continue
        try:
            idx = int(suffix)
        except ValueError as exc:
            raise SnmpError(
                f"malformed index {suffix!r} at {row.oid}"
            ) from exc
        try:
            value = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer value {row.value!r} at {row.oid}"
            ) from exc
        out[idx] = value
    return out


def index_str_column(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, str]:
    """Map a single-index column walk to {index: str_value}.

    An absent column (no rows under base_oid) yields an empty dict. But a row
    that IS present under base_oid with a single, non-integer index component is
    table drift, not absence, and raises SnmpError naming the offending OID —
    consistent with index_int_column. (A multi-component suffix belongs to a
    different, deeper column and is skipped.)

    A text-name OCTET STRING (ifName/ifAlias/dot1qVlanStaticName) can
    legitimately arrive as ``str`` from the CLI transport or ``bytes`` from
    the pysnmp transport (its non-printable heuristic picks Hex-STRING for
    values with any byte outside the printable-ASCII range, e.g. a name with
    a trailing NUL). Both are valid text here: ``bytes`` is decoded to
    ``str`` (utf-8, replacing undecodable bytes) so the two transports yield
    the same model value. Any other type (e.g. an int) is a genuine wrong-type
    reply and still raises.
    """
    out: dict[int, str] = {}
    for row in rows:
        suffix = _suffix(row, base_oid)
        if suffix is None or "." in suffix:
            continue
        try:
            idx = int(suffix)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer index {suffix!r} at {row.oid}"
            ) from exc
        value = row.value
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        elif not isinstance(value, str):
            raise SnmpError(f"non-string value {value!r} at {row.oid}")
        out[idx] = value
    return out


def parse_port_status(
    admin: Sequence[SnmpRow],
    oper: Sequence[SnmpRow],
    speed: Sequence[SnmpRow],
    names: Sequence[SnmpRow],
    aliases: Sequence[SnmpRow],
) -> list[PortStatus]:
    from . import oids

    admin_map = index_int_column(admin, oids.IF_ADMIN_STATUS)
    oper_map = index_int_column(oper, oids.IF_OPER_STATUS)
    speed_map = index_int_column(speed, oids.IF_HIGH_SPEED)
    name_map = index_str_column(names, oids.IF_NAME)
    # ifAlias (operator-set description): distinct column from ifName above.
    # An absent row for a port (or an empty-string alias) both mean "no
    # description set" -> honest None, never a fabricated "".
    alias_map = index_str_column(aliases, oids.IF_ALIAS)

    ports = sorted(set(admin_map) | set(oper_map))
    result: list[PortStatus] = []
    for p in ports:
        link_up = oper_map.get(p) == 1
        mbps = speed_map.get(p)
        result.append(
            PortStatus(
                port=p,
                name=name_map.get(p) or None,
                admin_enabled=admin_map.get(p) == 1,
                link_up=link_up,
                # A DOWN port has no operational speed: ifHighSpeed keeps
                # reporting the configured rate on a down port (verified on the
                # gsm7252ps: 10000 on down 1/0/52), which is NOT an operational
                # speed. Report None unless the link is up, matching the web
                # UI's "Unknown"->None so both backends agree field-for-field.
                # (ifHighSpeed 0 also maps to None.)
                speed_mbps=mbps if (mbps and link_up) else None,
                description=alias_map.get(p) or None,
            )
        )
    return result


def parse_port_stats(
    *,
    in_octets: Sequence[SnmpRow],
    out_octets: Sequence[SnmpRow],
    in_ucast: Sequence[SnmpRow],
    out_ucast: Sequence[SnmpRow],
    in_errors: Sequence[SnmpRow],
    out_errors: Sequence[SnmpRow],
) -> list[PortStats]:
    from . import oids

    rx_b = index_int_column(in_octets, oids.IF_HC_IN_OCTETS)
    tx_b = index_int_column(out_octets, oids.IF_HC_OUT_OCTETS)
    rx_p = index_int_column(in_ucast, oids.IF_HC_IN_UCAST)
    tx_p = index_int_column(out_ucast, oids.IF_HC_OUT_UCAST)
    rx_e = index_int_column(in_errors, oids.IF_IN_ERRORS)
    tx_e = index_int_column(out_errors, oids.IF_OUT_ERRORS)

    ports = sorted(set(rx_b) | set(tx_b) | set(rx_p) | set(tx_p)
                   | set(rx_e) | set(tx_e))
    return [
        PortStats(
            port=p,
            rx_bytes=rx_b.get(p),
            tx_bytes=tx_b.get(p),
            rx_packets=rx_p.get(p),
            tx_packets=tx_p.get(p),
            rx_errors=rx_e.get(p),
            tx_errors=tx_e.get(p),
        )
        for p in ports
    ]


def decode_port_bitmap(bitmap: bytes | str) -> frozenset[int]:
    """Decode an SNMP VLAN port bitmap. Bit 7 of byte 0 = port 1.

    An empty value is a legitimately absent bitmap -> no ports. Both transports
    normalize the non-printable OCTET STRING onto the wire to ``bytes``, so
    that is the expected form and is used directly (MSB-first). If a bitmap
    ever arrives as a printable ``str`` it is latin-1 encoded first; a str that
    cannot round-trip through latin-1 is malformed and raises SnmpError naming
    the value.
    """
    if not bitmap:
        return frozenset()
    if isinstance(bitmap, bytes):
        data = bitmap
    else:
        try:
            data = bitmap.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise SnmpError(f"malformed VLAN port bitmap {bitmap!r}") from exc
    ports: set[int] = set()
    for byte_idx, byte_val in enumerate(data):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)


def _vlan_bitmap_map(rows: Sequence[SnmpRow], base_oid: str) -> dict[int, bytes | str]:
    """{vlan_id: bitmap_value} for a VLAN bitmap column.

    A row absent from the column is skipped; a row present under base_oid
    whose VLAN index is non-numeric, or whose value is neither bytes nor str
    (wrong SNMP type on the wire), is drift and raises SnmpError naming the
    offending OID rather than silently dropping present-but-malformed data.
    """
    out: dict[int, bytes | str] = {}
    for row in rows:
        s = _suffix(row, base_oid)
        if s is None:
            continue
        if not s.isdigit():
            raise SnmpError(f"malformed VLAN index {s!r} at {row.oid}")
        if not isinstance(row.value, (bytes, str)):
            raise SnmpError(f"malformed VLAN port bitmap type at {row.oid}")
        out[int(s)] = row.value
    return out


def parse_vlans(
    names: Sequence[SnmpRow],
    egress: Sequence[SnmpRow],
    untagged: Sequence[SnmpRow],
) -> list[VLANInfo]:
    from . import oids

    name_map = index_str_column(names, oids.DOT1Q_VLAN_STATIC_NAME)
    egress_map = _vlan_bitmap_map(egress, oids.DOT1Q_VLAN_STATIC_EGRESS)
    untag_map = _vlan_bitmap_map(untagged, oids.DOT1Q_VLAN_STATIC_UNTAGGED)
    result: list[VLANInfo] = []
    for vid in sorted(name_map):
        member = decode_port_bitmap(egress_map.get(vid, ""))
        untag = decode_port_bitmap(untag_map.get(vid, ""))
        result.append(
            VLANInfo(
                vlan_id=vid,
                name=name_map.get(vid) or None,
                member_ports=member,
                tagged_ports=member - untag,
                untagged_ports=untag,
            )
        )
    return result


def parse_pvids(rows: Sequence[SnmpRow]) -> list[tuple[int, int]]:
    from . import oids

    pvids = index_int_column(rows, oids.DOT1Q_PVID)
    return sorted(pvids.items())


def _format_mac_bytes(byte_strs: Sequence[str]) -> str:
    return ":".join(f"{int(b):02X}" for b in byte_strs)


def _format_mac_octetstring(value: int | str | bytes) -> str | None:
    """Format a raw 6-byte MAC-shaped OCTET STRING as ``XX:XX:XX:XX:XX:XX``.

    The value arrives as ``bytes`` from a Hex-STRING varbind, or (for a
    transport that normalizes octet strings to latin-1 text) a 6-character
    ``str``. Returns ``None`` when ``value`` isn't a 6-byte/6-char octet
    string -- the caller decides whether that's absence or malformed drift.
    """
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02X}" for b in value)
    if isinstance(value, str) and len(value) == 6:
        return ":".join(f"{ord(c):02X}" for c in value)
    return None


def _mac_from_ascii_text(value: int | str | bytes) -> str | None:
    """Recognize a MAC already rendered as ASCII text ``XX:XX:XX:XX:XX:XX``.

    Some firmware (verified: the M4300-24X's dot1dBaseBridgeAddress) returns a
    MAC OCTET STRING as a 17-character human-readable colon-hex STRING rather
    than the proper 6 raw bytes. Returns the normalized upper-case MAC, or
    ``None`` when ``value`` isn't such a string (so callers fall through to the
    raw-octet path / malformed handling).
    """
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(len(p) != 2 for p in parts) or any(not 0 <= o <= 0xFF for o in octets):
        return None
    return ":".join(f"{o:02X}" for o in octets)


def _format_chassis_id(value: int | str | bytes) -> str:
    """Format an lldpRemChassisId value.

    The MAC-address chassis subtype formats as ``XX:XX:XX:XX:XX:XX`` (see
    ``_format_mac_octetstring``). Any other chassis-id subtype (e.g. a chassis
    component name) is returned as plain text.
    """
    mac = _format_mac_octetstring(value)
    if mac is not None:
        return mac
    return value if isinstance(value, str) else str(value)


def parse_base_mac(rows: Sequence[SnmpRow]) -> str | None:
    """Parse dot1dBaseBridgeAddress (BRIDGE-MIB scalar, standard MIB-II) into
    a colon-separated MAC string.

    An absent scalar (no row under the OID at all) is honestly ``None`` --
    not every device necessarily answers this instance. A row that IS present
    but isn't a 6-byte/6-char OCTET STRING is drift, not absence, and raises
    SnmpError naming the offending OID, consistent with the other column
    parsers in this module.
    """
    from . import oids

    prefix = oids.DOT1D_BASE_BRIDGE_ADDRESS + "."
    for row in rows:
        if not row.oid.startswith(prefix):
            continue
        mac = _format_mac_octetstring(row.value) or _mac_from_ascii_text(row.value)
        if mac is None:
            raise SnmpError(f"malformed base MAC {row.value!r} at {row.oid}")
        return mac
    return None


def _column_text(value: int | str | bytes) -> str:
    """Render a non-chassis LLDP column (portDesc/sysName) as text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else str(value)


def _format_port_id(value: int | str | bytes) -> str:
    """Format an lldpRemPortId value.

    Consistent with ``_format_chassis_id``: a MAC-address port-id subtype
    (lldpPortIdSubtype 3) is raw binary and formats as
    ``XX:XX:XX:XX:XX:XX`` via ``_format_mac_octetstring``, instead of being
    UTF-8-decoded (with ``errors="replace"``) into garbled U+FFFD text --
    that mismatch, versus chassis-id's correct MAC handling, was the bug.

    A genuinely binary portId always arrives as ``bytes`` (the transport's
    own printable-ASCII heuristic -- see ``index_str_column``'s docstring --
    only emits ``str`` for values that decode cleanly as text), so the
    ``bytes``-and-6-long check below is the reliable MAC signal. A ``str`` is
    additionally treated as raw MAC bytes only when it is NOT printable text
    (mirroring the latin-1-normalizing-transport case exercised for
    ``parse_base_mac``): this guards against a real, everyday ASCII
    interface-name portId that happens to be exactly 6 characters (e.g.
    ``"1/xg51"``) being mistaken for a MAC and corrupted into hex -- unlike
    chassis-id, port-id routinely carries short human-readable interface
    names, so a bare length-6 check on ``str`` is unsafe here. Any other
    value (including a printable 6-char ``str`` or any non-MAC-shaped
    value) is plain text, per ``_column_text``.
    """
    if isinstance(value, bytes) and len(value) == 6:
        mac = _format_mac_octetstring(value)
        if mac is not None:
            return mac
    if isinstance(value, str) and len(value) == 6 and not value.isprintable():
        mac = _format_mac_octetstring(value)
        if mac is not None:
            return mac
    return _column_text(value)


def parse_lldp(rows: Sequence[SnmpRow]) -> list[LLDPNeighbor]:
    """Group lldpRemTable rows by local port into LLDPNeighbor entries.

    The instance suffix is ``<column>.<timeMark>.<localPortNum>.<remIndex>``;
    the middle component is the local port. A row present under the table
    prefix but with fewer than 4 suffix components, or a non-integer column
    or local-port component, is drift (not absence) and raises SnmpError
    naming the offending OID. A fully-empty neighbour group (every tracked
    column absent) carries no data and is skipped.
    """
    from . import oids

    prefix = oids.LLDP_REM_TABLE + ".1."
    grouped: dict[tuple[str, str, str], dict[int, int | str | bytes]] = {}
    for row in rows:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        if len(parts) != 4:
            raise SnmpError(f"malformed LLDP index at {row.oid}")
        try:
            column = int(parts[0])
        except ValueError as exc:
            raise SnmpError(
                f"non-integer LLDP column {parts[0]!r} at {row.oid}"
            ) from exc
        key = (parts[1], parts[2], parts[3])  # timeMark, localPort, remIdx
        grouped.setdefault(key, {})[column] = row.value

    result: list[LLDPNeighbor] = []
    for (_tm, local_port, _rem), cols in grouped.items():
        chassis = cols.get(5, "")
        port_id = cols.get(7, "")
        port_desc = cols.get(8, "")
        sys_name = cols.get(9, "")
        # A neighbour row group with every column empty carries no data
        # (absent); skip it. A present-but-non-integer local-port index is
        # drift -> raise.
        if not (chassis or port_id or port_desc or sys_name):
            continue
        try:
            lp = int(local_port)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer LLDP local port {local_port!r} at {prefix}...{local_port}"
            ) from exc
        result.append(
            LLDPNeighbor(
                local_port=lp,
                remote_sys_name=_column_text(sys_name) or None,
                remote_port_desc=_column_text(port_desc) or None,
                remote_chassis_id=_format_chassis_id(chassis) or None,
                remote_port_id=_format_port_id(port_id) or None,
            )
        )
    return sorted(result, key=lambda n: n.local_port)


def parse_macs(
    fdb: Sequence[SnmpRow], bridge_ports: Sequence[SnmpRow]
) -> list[MacEntry]:
    """Build the MAC/FDB table from dot1qTpFdbPort + dot1dBasePortIfIndex.

    ``dot1qTpFdbPort`` gives the bridge PORT number keyed by
    ``<vlan>.<mac-as-6-oid-octets>``; ``dot1dBasePortIfIndex`` maps that
    bridge port to an ifIndex (falling back to the bridge port number itself
    when unmapped). A bridge-port value that is present but not an integer is
    table drift and raises SnmpError naming the offending OID.
    """
    from . import oids

    bridge_to_if = index_int_column(bridge_ports, oids.DOT1D_BASE_PORT_IF_INDEX)
    prefix = oids.DOT1Q_TP_FDB_PORT + "."
    result: list[MacEntry] = []
    for row in fdb:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        if len(parts) != 7:  # <vlan>.<6 MAC bytes>
            raise SnmpError(f"malformed FDB index at {row.oid}")
        try:
            vlan_id = int(parts[0])
        except ValueError as exc:
            raise SnmpError(
                f"non-integer VLAN index {parts[0]!r} at {row.oid}"
            ) from exc
        try:
            bridge_port = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer bridge port {row.value!r} at {row.oid}"
            ) from exc
        port = bridge_to_if.get(bridge_port, bridge_port)
        result.append(
            MacEntry(mac=_format_mac_bytes(parts[1:7]), port=port, vlan_id=vlan_id)
        )
    return sorted(result, key=lambda m: (m.port, m.mac))


DETECT_MAP: dict[int, PoEDetect] = {
    1: PoEDetect.DISABLED,
    2: PoEDetect.SEARCHING,
    3: PoEDetect.DELIVERING,
    4: PoEDetect.FAULT,
}


def parse_poe(
    status: Sequence[SnmpRow], power_mw: Sequence[SnmpRow]
) -> list[PoEStatus]:
    """Build PoE port status from RFC3621 pethPsePortTable + vendor mW.

    ``status`` is a walk of pethPsePortTable; only columns 3 (admin) and 6
    (detect) are honoured (the hard-won fix: never column 1). Rows are
    grouped by ``(group, port)`` from the ``<col>.<group>.<port>`` instance
    suffix. A port present in the walk but missing either tracked column is
    drift (not absence) and raises SnmpError naming the offending port.
    ``power_mw`` is the vendor per-port power walk, matched to a port by the
    final OID suffix component; a port without a vendor mW row gets
    ``power_mw=None``.
    """
    from . import oids

    prefix = oids.PETH_PSE_PORT_TABLE + "."
    cols: dict[tuple[int, int], dict[int, int]] = {}
    for row in status:
        if not row.oid.startswith(prefix):
            continue
        parts = row.oid[len(prefix):].split(".")
        if len(parts) != 3:
            continue
        column = int(parts[0])
        if column not in (3, 6):
            continue
        try:
            key = (int(parts[1]), int(parts[2]))
            cols.setdefault(key, {})[column] = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer PoE value {row.value!r} at {row.oid}"
            ) from exc

    # vendor mW keyed by port index (2nd suffix component)
    mw: dict[int, int] = {}
    for row in power_mw:
        parts = row.oid.split(".")
        try:
            mw[int(parts[-1])] = int(row.value)
        except ValueError:
            continue

    result: list[PoEStatus] = []
    for (_group, port), c in sorted(cols.items()):
        if 3 not in c:
            raise SnmpError(f"PoE port {port} missing admin (col 3)")
        if 6 not in c:
            raise SnmpError(f"PoE port {port} missing detect (col 6)")
        result.append(
            PoEStatus(
                port=port,
                admin_enabled=c[3] == 1,
                detect=DETECT_MAP.get(c[6], PoEDetect.UNKNOWN),
                power_mw=mw.get(port),
            )
        )
    return result


def parse_box_sensors(
    rows_by_kind: Sequence[tuple[str, str, Sequence[SnmpRow]]],
) -> list[Sensor]:
    """Build box sensors from walk-discovered Netgear vendor columns.

    Each tuple is ``(kind, unit, rows)`` for one vendor column walk (e.g.
    fan RPM, PSU power, temperature). Sensor indices are walk-discovered
    (they differ per model), not hardcoded. The literal string
    ``"Not Supported"`` is Netgear's placeholder for an unpopulated slot and
    is skipped, not an error; any other non-integer value is present-but-
    malformed and raises SnmpError naming the offending OID.
    """
    result: list[Sensor] = []
    for kind, unit, rows in rows_by_kind:
        for row in rows:
            parts = row.oid.split(".")
            instance = parts[-1]
            if row.value == "Not Supported":
                continue
            try:
                value = int(row.value)
            except ValueError as exc:
                raise SnmpError(
                    f"non-integer {kind} reading {row.value!r} at {row.oid}"
                ) from exc
            result.append(
                Sensor(name=f"{kind}{instance}", kind=kind,
                        value=float(value), unit=unit)
            )
    return result


def parse_entity_sensors(
    class_rows: Sequence[SnmpRow],
    name_rows: Sequence[SnmpRow],
    descr_rows: Sequence[SnmpRow],
) -> list[Sensor]:
    """Build box sensors from the standard ENTITY-MIB physical inventory.

    For a model whose SNMP agent implements NO Netgear vendor OIDs (verified:
    the GS728TPP), the fan/PSU components are exposed ONLY as ENTITY-MIB
    ``entPhysicalTable`` rows: ``entPhysicalClass`` (6=powerSupply, 7=fan)
    identifies each, ``entPhysicalName`` (falling back to ``entPhysicalDescr``)
    names it. This is INVENTORY ONLY -- the switch exposes NO live sensor
    value/status anywhere in SNMP (ENTITY-SENSOR-MIB and the vendor tree both
    answer noSuchObject on real hardware), so each Sensor carries
    ``value=NaN`` and ``unit="inventory"``: the component is honestly reported
    as present without a fabricated reading. (HTTP DOES expose a health status
    for these same components -- that is a real per-backend difference, not a
    parser bug; see the cross-backend test.)

    Rows are matched by their shared entPhysicalIndex (the trailing OID
    component). Only powerSupply/fan classes become sensors; chassis/slot/port
    rows are ignored. A non-integer class value present under the class column
    is drift and raises SnmpError naming the offending OID.
    """
    from . import oids

    names = index_str_column(name_rows, oids.ENT_PHYSICAL_NAME)
    descrs = index_str_column(descr_rows, oids.ENT_PHYSICAL_DESCR)
    classes = index_int_column(class_rows, oids.ENT_PHYSICAL_CLASS)
    kind_of = {
        oids.ENT_CLASS_POWER_SUPPLY: "power",
        oids.ENT_CLASS_FAN: "fan",
    }
    result: list[Sensor] = []
    for idx in sorted(classes):
        kind = kind_of.get(classes[idx])
        if kind is None:
            continue
        name = names.get(idx) or descrs.get(idx) or f"{kind}{idx}"
        result.append(
            Sensor(name=_canon_sensor_name(name), kind=kind,
                   value=float("nan"), unit="inventory")
        )
    return result


def _canon_sensor_name(name: str) -> str:
    """Canonicalize an ENTITY-MIB component name to the box-sensor label the
    HTTP DiagnosticsUnitList uses, so the two backends' sensor NAMES are
    identical (only the value/unit differ -- SNMP has no live reading).

    entPhysicalName renders a PSU as ``"Main PowerSupply"`` /
    ``"Redundant PowerSupply"``; the web UI labels the same component
    ``"Main PS"`` / ``"Redundant PS"``. Abbreviating ``PowerSupply`` -> ``PS``
    (with or without an internal space) unifies them; a fan name (``"Fan1"``)
    already matches and is returned unchanged."""
    return name.replace("Power Supply", "PS").replace("PowerSupply", "PS")


def _ip_str(row: SnmpRow) -> str:
    """Return an IP-valued row's value as ``str``.

    Both transports normalize IpAddress varbinds to ``str`` (see SnmpRow's
    docstring); a row present under an address/netmask/gateway column whose
    value is NOT a str is table drift / a malformed reply, not absence, and
    raises SnmpError naming the offending OID.
    """
    if not isinstance(row.value, str):
        raise SnmpError(f"non-IP value {row.value!r} at {row.oid}")
    return row.value


def parse_mgmt_ip(
    addr: Sequence[SnmpRow],
    netmask: Sequence[SnmpRow],
    route_dest: Sequence[SnmpRow],
    route_nexthop: Sequence[SnmpRow],
    dhcp_mode: Sequence[SnmpRow],
    base_mac: Sequence[SnmpRow],
) -> MgmtIpConfig:
    """Build the management-IP config from ipAddrTable/ipRouteTable + vendor mode.

    Address/netmask/gateway come from the standard MIBs (ipAddrTable,
    ipRouteTable) and are trustworthy. The DHCP-vs-static mode is UNVERIFIED
    (see oids.VendorOids.dhcp_mode_unverified): it is read best-effort and
    ``IpMode.UNKNOWN`` is returned whenever the mode OID is absent/unset —
    never a guessed dhcp/static. The mode OID is INTEGER-typed, so both
    transports normalize its value to a Python ``int`` (see ``SnmpRow``'s
    docstring); only a recognized present value (``1``/``2``) maps to
    DHCP/STATIC, any other present value -- including one that cannot be
    coerced to ``int`` at all -- also yields UNKNOWN rather than raising,
    since this OID is explicitly best-effort. ``base_mac`` is the standard
    (non-UNVERIFIED) dot1dBaseBridgeAddress scalar walk -- see
    ``parse_base_mac``; an empty walk (OID absent) yields ``base_mac=None``.
    """
    from . import oids

    ip: str | None = None
    ip_index: str | None = None
    aprefix = oids.IP_ADENT_ADDR + "."
    for row in addr:
        if not row.oid.startswith(aprefix):
            continue
        if row.value == "127.0.0.1":
            continue
        ip = _ip_str(row)
        ip_index = row.oid[len(aprefix):]
        break

    mask: str | None = None
    if ip_index is not None:
        want = oids.IP_ADENT_NETMASK + "." + ip_index
        for r in netmask:
            if r.oid == want:
                mask = _ip_str(r)
                break

    dest_rows = {
        r.oid[len(oids.IP_ROUTE_DEST) + 1:]: r.value for r in route_dest
    }
    gateway: str | None = None
    nprefix = oids.IP_ROUTE_NEXTHOP + "."
    for row in route_nexthop:
        if not row.oid.startswith(nprefix):
            continue
        idx = row.oid[len(nprefix):]
        if dest_rows.get(idx) == "0.0.0.0":
            gateway = _ip_str(row)
            break

    mode = IpMode.UNKNOWN
    for row in dhcp_mode:
        try:
            raw_mode = int(row.value)
        except (TypeError, ValueError):
            break
        if raw_mode == 1:
            mode = IpMode.DHCP
        elif raw_mode == 2:
            mode = IpMode.STATIC
        break

    return MgmtIpConfig(
        mode=mode, address=ip, netmask=mask, gateway=gateway,
        base_mac=parse_base_mac(base_mac),
    )


def _scalar_text(rows: Sequence[SnmpRow], oid: str) -> str | None:
    """Extract one scalar exact-OID GET result's value as text, or None.

    Unlike the walk-based column parsers above (matched by base-OID
    *prefix*), ``sysDescr``/``sysObjectID`` are fetched with a plain exact-OID
    GET (see ``snmp_read.read_system_info``), so ``rows`` is the combined
    result of one ``client.get([...])`` call and this matches by exact OID
    equality. An absent scalar (no row with this exact OID at all) is
    honestly ``None`` -- not every device necessarily answers, and a caller
    must never fabricate a value. A row that IS present but isn't decodable
    to text is drift, not absence, and raises SnmpError naming the offending
    OID, consistent with every other parser in this module.
    """
    for row in rows:
        if row.oid != oid:
            continue
        value = row.value
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        if isinstance(value, str):
            return value
        raise SnmpError(f"non-string value {value!r} at {row.oid}")
    return None


def parse_system_info(rows: Sequence[SnmpRow]) -> tuple[str | None, str | None]:
    """Extract the raw sysDescr/sysObjectID scalar text from one combined GET.

    Pure row -> ``(sys_descr, sys_object_id)`` extraction ONLY -- no model
    matching happens here. Kept strictly separate from
    ``detect_model_from_sysdescr`` so the matching heuristic is unit-testable
    against plain strings, with no SnmpRow/client machinery involved at all.
    """
    from . import oids

    sys_descr = _scalar_text(rows, oids.SYS_DESCR)
    sys_object_id = _scalar_text(rows, oids.SYS_OBJECT_ID)
    return sys_descr, sys_object_id


def _model_match_tokens(model: SwitchModel) -> tuple[str, ...]:
    """Name tokens to search for (uppercased) in a sysDescr string.

    Built ONLY from the registry's own ``key``/``display_name`` -- there is
    NO hand-invented per-model sysDescr/sysObjectID table anywhere (no MIBs,
    no captures, no prior-art map exist for one; see
    ``detect_model_from_sysdescr``'s docstring). ``display_name`` sometimes
    carries a parenthesized alias (e.g. ``"GSM7228PS (S3300)"`` or
    ``"M4300-24X (XSM4324CS)"``); both the main name and the alias are valid
    tokens, since a real switch's sysDescr text could plausibly use either.
    """
    tokens = [model.key.upper()]
    name = model.display_name
    if "(" in name and name.endswith(")"):
        main, _, alias = name.partition("(")
        tokens.append(main.strip())
        tokens.append(alias[:-1].strip())
    else:
        tokens.append(name.strip())
    return tuple(t for t in tokens if t)


# Punctuation stripped from the edges of a whitespace-delimited sysDescr
# word before comparing it to a registered token. Hyphens are deliberately
# EXCLUDED: they are meaningful inside a model identifier itself (e.g.
# "M4300-24X"), so stripping them would merge distinct SKUs together.
_WORD_STRIP_CHARS = string.punctuation.replace("-", "")


def _candidate_tokens(sys_descr: str) -> frozenset[str]:
    """Whitespace-delimited "words" of a sysDescr string, as whole-token
    candidates for exact (uppercased) comparison against a registered
    model's match tokens.

    Only edge punctuation is stripped (e.g. the trailing comma in
    ``"M4300-24X,"``) -- internal structure, in particular hyphens, is left
    intact. This is what makes the comparison a WHOLE-IDENTIFIER match: a
    registered token must equal an entire sysDescr word, not merely appear
    as a prefix/substring of it. That is the crux of the fix for the
    false-positive bug this function exists to prevent (see
    ``detect_model_from_sysdescr``'s docstring) -- e.g. the single sysDescr
    word ``"GS305EPP"`` never equals the registered token ``"GS305EP"``, and
    the single word ``"S3300-28X"`` never equals the registered alias
    token ``"S3300"``, no matter what non-alphanumeric character (or none)
    immediately follows the registered token's text.
    """
    return frozenset(
        word.strip(_WORD_STRIP_CHARS).upper() for word in sys_descr.split()
    )


def detect_model_from_sysdescr(
    sys_descr: str | None, models: Mapping[str, SwitchModel]
) -> str | None:
    """Match a switch's sysDescr text against registered models' names.

    HONESTY CONSTRAINT: there is no ground-truth sysObjectID -> model table
    (see ``oids.SYS_OBJECT_ID`` -- it is read as a raw signal but never used
    here). Matching is EXACT (case-insensitive) whole-word matching: the
    sysDescr string is split into whitespace-delimited candidate tokens
    (``_candidate_tokens``) and a registered model matches only when one of
    its own key/display_name/alias tokens (``_model_match_tokens``) equals
    one of those candidates in full -- NEVER a bare substring/prefix check,
    and NEVER a guess:

    * A sysDescr containing an unregistered Netgear model name (e.g.
      ``"GS752TP"``, not in ``models``) matches no token and correctly
      returns ``None`` -- it is NEVER coerced onto some other, wrong,
      registered model just because it looks Netgear-ish.
    * A non-Netgear/garbage string matches nothing and also returns ``None``.
    * CRITICAL (regression that motivated the switch away from substring
      matching): a real, unregistered Netgear model whose name EXTENDS a
      registered token must also return ``None``, never the shorter
      registered model. Bare substring matching used to fail this both when
      the extension has no separator (``"GS305EPP"`` used to wrongly match
      the registered ``"GS305EP"``, a distinct 123W model vs. the registered
      63W one) AND when it has one (``"S3300-28X"`` / ``"S3300-28X-PoE+"``
      used to wrongly match the registered alias ``"S3300"`` for
      ``gsm7228ps``, a distinct S3300 SKU). Whole-word equality rejects both:
      neither ``"GS305EPP"`` nor ``"S3300-28X"`` is ever *equal* to the
      shorter registered token, regardless of what character (alphanumeric
      or not) follows it in the original text.
    * A sysDescr matching MORE THAN ONE registered model's tokens (meaning
      two registered models' names collide and can't be disambiguated by
      this heuristic) ALSO returns ``None`` rather than guessing between
      them. This never happens for the current registry (verified: no
      model's match tokens equal another's -- e.g. "M4300-24X" vs
      "M4300-16X", "GSM7252PS" vs "GSM7228PS"/"S3300" are all mutually
      exclusive), but the fallback is kept as a permanent safety net against
      a future registry addition introducing a collision.
    """
    if not sys_descr:
        return None
    candidates = _candidate_tokens(sys_descr)
    matches = {
        model.key
        for model in models.values()
        if any(token.upper() in candidates for token in _model_match_tokens(model))
    }
    if len(matches) == 1:
        return next(iter(matches))
    return None
