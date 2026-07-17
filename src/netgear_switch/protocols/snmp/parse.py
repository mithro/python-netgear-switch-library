# src/netgear_switch/protocols/snmp/parse.py
"""Pure SNMP-row -> models.py parsers. No I/O."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...models import LLDPNeighbor, MacEntry, PortStats, PortStatus, VLANInfo
from .client import SnmpError, SnmpRow

if TYPE_CHECKING:
    from collections.abc import Sequence


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
        if not isinstance(row.value, str):
            raise SnmpError(f"non-string value {row.value!r} at {row.oid}")
        out[idx] = row.value
    return out


def parse_port_status(
    admin: Sequence[SnmpRow],
    oper: Sequence[SnmpRow],
    speed: Sequence[SnmpRow],
    names: Sequence[SnmpRow],
) -> list[PortStatus]:
    from . import oids

    admin_map = index_int_column(admin, oids.IF_ADMIN_STATUS)
    oper_map = index_int_column(oper, oids.IF_OPER_STATUS)
    speed_map = index_int_column(speed, oids.IF_HIGH_SPEED)
    name_map = index_str_column(names, oids.IF_NAME)

    ports = sorted(set(admin_map) | set(oper_map))
    result: list[PortStatus] = []
    for p in ports:
        mbps = speed_map.get(p)
        result.append(
            PortStatus(
                port=p,
                name=name_map.get(p) or None,
                admin_enabled=admin_map.get(p) == 1,
                link_up=oper_map.get(p) == 1,
                speed_mbps=mbps if mbps else None,
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


def _format_chassis_id(value: int | str | bytes) -> str:
    """Format an lldpRemChassisId value.

    The MAC-address chassis subtype arrives as a raw 6-byte value: ``bytes``
    from a Hex-STRING varbind, or (for a transport that normalizes octet
    strings to latin-1 text) a 6-character ``str``. Either is formatted as
    ``XX:XX:XX:XX:XX:XX``. Any other chassis-id subtype (e.g. a chassis
    component name) is returned as plain text.
    """
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02X}" for b in value)
    if isinstance(value, str) and len(value) == 6:
        return ":".join(f"{ord(c):02X}" for c in value)
    return value if isinstance(value, str) else str(value)


def _column_text(value: int | str | bytes) -> str:
    """Render a non-chassis LLDP column (portId/portDesc/sysName) as text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else str(value)


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
        if len(parts) < 4:
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
            continue
        try:
            vlan_id = int(parts[0])
        except ValueError:
            continue
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
