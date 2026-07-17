# src/netgear_switch/protocols/snmp/parse.py
"""Pure SNMP-row -> models.py parsers. No I/O."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...models import PortStats, PortStatus, VLANInfo
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
