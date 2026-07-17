"""Pure SNMP write encoding: SET varbinds and Q-BRIDGE bitmap read-modify-write.

No I/O and transport-agnostic. ``SetVarbind`` carries a net-snmp-style type
letter (``i`` INTEGER, ``u`` Gauge32/unsigned, ``s`` string, ``x`` hex/octets,
``a`` IpAddress) that both transports map onto their own SET call. The bitmap
helpers do a read-modify-write so only the target port's bit changes, leaving
trunks and other access ports untouched (design spec §6).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...models import VlanMode
from .parse import decode_port_bitmap

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ...registry import SwitchModel

SET_TYPE_LETTERS: frozenset[str] = frozenset({"i", "u", "s", "x", "a"})


@dataclass(frozen=True)
class SetVarbind:
    """One SNMP SET varbind: full numeric OID, value, and net-snmp type letter."""

    oid: str
    value: int | str | bytes
    type_letter: str

    def __post_init__(self) -> None:
        if self.type_letter not in SET_TYPE_LETTERS:
            raise ValueError(
                f"unknown SET type letter {self.type_letter!r}; "
                f"expected one of {sorted(SET_TYPE_LETTERS)}"
            )


def encode_port_bitmap(ports: Iterable[int], width_bytes: int = 8) -> bytes:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a wire bitmap.

    Bit 7 (MSB) of byte 0 is port 1. The buffer grows past ``width_bytes`` if a
    port number needs it, so callers never pre-size for the actual port count.
    """
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return bytes(data)


def set_port_bit(
    current: bytes | str, port: int, present: bool, *, width_bytes: int | None = None
) -> bytes:
    """Read-modify-write one port's bit in a VLAN bitmap; all others preserved.

    Preserves the input bitmap's byte width to avoid wire-length mismatches on
    SET for >64-port switches. ``width_bytes``, if given (e.g. a model-derived
    width from ``vlan_bitmap_width``), is honoured too: the result is at least
    8 bytes, at least as wide as the input, and at least ``width_bytes`` wide.
    """
    # Compute the current bitmap's width in bytes
    if isinstance(current, bytes):
        current_width = len(current)
    else:
        current_width = len(current.encode("latin-1"))

    ports = set(decode_port_bitmap(current))
    if present:
        ports.add(port)
    else:
        ports.discard(port)
    target_width = max(8, current_width, width_bytes or 0)
    return encode_port_bitmap(ports, width_bytes=target_width)


def membership_bitmaps(
    *,
    mode: VlanMode,
    port: int,
    egress: bytes | str,
    untagged: bytes | str,
    width_bytes: int | None = None,
) -> tuple[bytes, bytes]:
    """Compute (new_egress, new_untagged) for one port's VLAN membership change.

    UNTAGGED -> egress bit on + untagged bit on; TAGGED -> egress on, untagged
    off; EXCLUDED -> both off. Read-modify-write on the current bitmaps, so
    every other port's membership is preserved. ``width_bytes`` is forwarded to
    ``set_port_bit`` for both columns (see ``vlan_bitmap_width``).
    """
    in_egress = mode in (VlanMode.UNTAGGED, VlanMode.TAGGED)
    in_untagged = mode is VlanMode.UNTAGGED
    return (
        set_port_bit(egress, port, in_egress, width_bytes=width_bytes),
        set_port_bit(untagged, port, in_untagged, width_bytes=width_bytes),
    )


def vlan_bitmap_width(model: SwitchModel) -> int:
    """Wire byte-width of ``model``'s dot1q VLAN egress/untagged bitmaps.

    ``dot1qVlanStaticEgressPorts``/``UntaggedPorts`` are packed 8 ports/byte,
    MSB-first (port 1 = bit 7 of byte 0). The Q-BRIDGE MIB's own default
    PortList width is 8 bytes (64 ports); a model with more ports needs a
    wider bitmap or the SET's wire length won't match what the device expects.
    """
    return max(8, (model.port_count + 7) // 8)
