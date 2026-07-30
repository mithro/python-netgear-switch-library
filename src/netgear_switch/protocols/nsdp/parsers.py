"""Per-tag NSDP byte parsers. Lifted from ``gdoc2netcfg/src/nsdp/parsers.py``,
plus ``ports_to_bitmap`` (the write-path inverse of ``bitmap_to_ports``).

Every parser is total over the bytes it accepts and raises ``ValueError`` on a
wrong length or a bad prefix, so a malformed TLV surfaces early rather than
producing a silently-wrong value.
"""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING

from .protocol import Tag
from .types import (
    LinkSpeed,
    NsdpDevice,
    NsdpIgmpSnooping,
    NsdpPortMirroring,
    NsdpPortPvid,
    NsdpPortStatistics,
    NsdpPortStatus,
    NsdpVlanMembership,
    VLANEngine,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .protocol import NSDPPacket


def parse_ipv4(data: bytes) -> str:
    if len(data) != 4:
        raise ValueError(f"IPv4 TLV must be 4 bytes, got {len(data)}")
    return socket.inet_ntoa(data)


def parse_mac(data: bytes) -> str:
    if len(data) != 6:
        raise ValueError(f"MAC TLV must be 6 bytes, got {len(data)}")
    return ":".join(f"{b:02x}" for b in data)


def parse_port_status(data: bytes) -> NsdpPortStatus:
    if len(data) != 3:
        raise ValueError(f"PORT_STATUS TLV must be 3 bytes, got {len(data)}")
    return NsdpPortStatus(port_id=data[0], speed=LinkSpeed.from_byte(data[1]))


def parse_port_statistics(data: bytes) -> NsdpPortStatistics:
    if len(data) != 49:
        raise ValueError(f"PORT_STATISTICS TLV must be 49 bytes, got {len(data)}")
    rx, tx, crc = struct.unpack_from(">QQQ", data, 1)
    return NsdpPortStatistics(
        port_id=data[0], bytes_received=rx, bytes_sent=tx, crc_errors=crc
    )


def parse_port_pvid(data: bytes) -> NsdpPortPvid:
    if len(data) != 3:
        raise ValueError(f"PORT_PVID TLV must be 3 bytes, got {len(data)}")
    return NsdpPortPvid(port_id=data[0], vlan_id=struct.unpack_from(">H", data, 1)[0])


def parse_serial(data: bytes) -> str:
    if not data or data[0] != 0x01:
        raise ValueError(f"SERIAL_NUMBER TLV: unexpected prefix byte {data[:1]!r}")
    return data[1:].decode("ascii", errors="replace").rstrip("\x00")


def bitmap_to_ports(bitmap: bytes) -> frozenset[int]:
    """MSB-first, 1-based: byte 0 bit 0x80 = port 1 ... 0x01 = port 8."""
    ports: set[int] = set()
    for byte_idx, byte_val in enumerate(bitmap):
        for bit in range(8):
            if byte_val & (0x80 >> bit):
                ports.add(byte_idx * 8 + bit + 1)
    return frozenset(ports)


def ports_to_bitmap(ports: Iterable[int], width_bytes: int) -> bytes:
    """Inverse of ``bitmap_to_ports`` for the write path (same MSB-first layout)."""
    data = bytearray(width_bytes)
    for p in ports:
        byte_idx, bit = divmod(p - 1, 8)
        while byte_idx >= len(data):
            data.append(0)
        data[byte_idx] |= 0x80 >> bit
    return bytes(data)


def parse_vlan_members(data: bytes, port_count: int = 8) -> NsdpVlanMembership:
    bitmap_bytes = (port_count + 7) // 8
    expected = 2 + bitmap_bytes * 2
    if len(data) < expected:
        raise ValueError(
            f"VLAN_MEMBERS TLV must be >={expected} bytes for {port_count} ports, "
            f"got {len(data)}"
        )
    vlan_id = struct.unpack_from(">H", data, 0)[0]
    member = data[2 : 2 + bitmap_bytes]
    tagged = data[2 + bitmap_bytes : 2 + bitmap_bytes * 2]
    return NsdpVlanMembership(
        vlan_id=vlan_id,
        member_ports=bitmap_to_ports(member),
        tagged_ports=bitmap_to_ports(tagged),
    )


def _decode_str(data: bytes) -> str:
    return data.decode("ascii", errors="replace").rstrip("\x00")


def parse_port_mirroring(data: bytes) -> NsdpPortMirroring:
    """Parse NSDP tag 0x5C00: dest_port(1) + a variable-width source bitmap.

    The source-port bitmap width is MODEL-dependent: a 5-port GS105PE returns a
    2-byte bitmap (3-byte TLV in total), a 10-port GS110EMX a 3-byte bitmap
    (4-byte TLV) -- both confirmed live 2026-07-21. Earlier this hard-required
    exactly 4 bytes and so raised on a real GS105PE (``00 00 00`` = mirroring
    off). Accept ``dest_port`` plus the remaining bytes as the bitmap instead.

    Lifted from ``gdoc2netcfg/src/nsdp/parsers.py::parse_port_mirroring``.
    """
    if not data:
        raise ValueError("PORT_MIRRORING TLV must be at least 1 byte, got 0")
    dest_port = data[0]
    source_ports = bitmap_to_ports(data[1:])
    return NsdpPortMirroring(destination_port=dest_port, source_ports=source_ports)


def parse_igmp_snooping(data: bytes) -> NsdpIgmpSnooping:
    """Parse NSDP tag 0x6800 (>=2 bytes: unknown, enabled, [unknown, vlan?]).

    Lifted from ``gdoc2netcfg/src/nsdp/parsers.py::parse_igmp_snooping``.
    """
    if len(data) < 2:
        raise ValueError(f"IGMP_SNOOPING TLV must be >= 2 bytes, got {len(data)}")
    enabled = bool(data[1])
    vlan_id = None
    if len(data) >= 4:
        vlan_id = data[3] if data[3] != 0 else None
    return NsdpIgmpSnooping(enabled=enabled, vlan_id=vlan_id)


def parse_device(packet: NSDPPacket) -> NsdpDevice:
    """Aggregate a READ_RESPONSE packet's TLVs into an NsdpDevice."""
    model: str | None = None
    mac: str | None = None
    fields: dict[str, object] = {}
    port_status: list[NsdpPortStatus] = []
    port_stats: list[NsdpPortStatistics] = []
    vlan_members: list[NsdpVlanMembership] = []
    pvids: list[NsdpPortPvid] = []
    port_count = 8
    # First pass to learn the real port count (bitmaps need it).
    for tlv in packet.tlvs:
        if tlv.tag == Tag.PORT_COUNT and tlv.value:
            port_count = tlv.value[0]
    for tlv in packet.tlvs:
        if tlv.tag == Tag.MODEL:
            model = _decode_str(tlv.value)
        elif tlv.tag == Tag.MAC:
            mac = parse_mac(tlv.value)
        elif tlv.tag == Tag.HOSTNAME:
            fields["hostname"] = _decode_str(tlv.value)
        elif tlv.tag == Tag.IP_ADDRESS:
            fields["ip"] = parse_ipv4(tlv.value)
        elif tlv.tag == Tag.NETMASK:
            fields["netmask"] = parse_ipv4(tlv.value)
        elif tlv.tag == Tag.GATEWAY:
            fields["gateway"] = parse_ipv4(tlv.value)
        elif tlv.tag == Tag.FIRMWARE_VER_1:
            fields["firmware_version"] = _decode_str(tlv.value)
        elif tlv.tag == Tag.DHCP_MODE and tlv.value:
            fields["dhcp_enabled"] = bool(tlv.value[0])
        elif tlv.tag == Tag.PORT_COUNT and tlv.value:
            fields["port_count"] = tlv.value[0]
        elif tlv.tag == Tag.SERIAL_NUMBER:
            fields["serial_number"] = parse_serial(tlv.value)
        elif tlv.tag == Tag.VLAN_ENGINE and tlv.value:
            fields["vlan_engine"] = VLANEngine(tlv.value[0])
        elif tlv.tag == Tag.PORT_STATUS:
            port_status.append(parse_port_status(tlv.value))
        elif tlv.tag == Tag.PORT_STATISTICS:
            port_stats.append(parse_port_statistics(tlv.value))
        elif tlv.tag == Tag.VLAN_MEMBERS:
            vlan_members.append(parse_vlan_members(tlv.value, port_count))
        elif tlv.tag == Tag.PORT_PVID:
            pvids.append(parse_port_pvid(tlv.value))
        elif tlv.tag == Tag.QOS_ENGINE and tlv.value:
            fields["qos_engine"] = tlv.value[0]
        elif tlv.tag == Tag.PORT_MIRRORING:
            fields["port_mirroring"] = parse_port_mirroring(tlv.value)
        elif tlv.tag == Tag.IGMP_SNOOPING:
            fields["igmp_snooping"] = parse_igmp_snooping(tlv.value)
        elif tlv.tag == Tag.BROADCAST_FILTERING and tlv.value:
            fields["broadcast_filtering"] = bool(tlv.value[0])
        elif tlv.tag == Tag.LOOP_DETECTION and tlv.value:
            fields["loop_detection"] = bool(tlv.value[0])
    if model is None:
        raise ValueError("no MODEL tag in NSDP response")
    if mac is None:
        mac = parse_mac(packet.server_mac)
    return NsdpDevice(
        model=model,
        mac=mac,
        port_status=tuple(port_status),
        port_statistics=tuple(port_stats),
        vlan_members=tuple(vlan_members),
        port_pvids=tuple(pvids),
        **fields,  # type: ignore[arg-type]
    )
