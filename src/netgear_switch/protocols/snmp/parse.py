# src/netgear_switch/protocols/snmp/parse.py
"""Pure SNMP-row -> models.py parsers. No I/O."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...models import PortStats, PortStatus
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
            out[int(suffix)] = int(row.value)
        except ValueError as exc:
            raise SnmpError(
                f"non-integer value {row.value!r} at {row.oid}"
            ) from exc
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
