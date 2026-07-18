"""NSDP wire codec: 32-byte header, TLV entries, and packet encode/decode.

Lifted verbatim (field-for-field) from ``gdoc2netcfg/src/nsdp/protocol.py``.
The header is ``struct`` layout ``>BB H 4s 6s 6s HH 4s 4s`` (32 bytes): version
(always 0x01), operation, result, reserved(4), client MAC(6), server MAC(6),
reserved(2), sequence, signature ``b"NSDP"`` at offset 0x18, reserved(4). Each
TLV is ``>HH`` (tag, length) followed by ``length`` value bytes; a packet ends
with the ``0xFFFF 0x0000`` end-of-marker.

This module is a pure, zero-dependency codec: no sockets, no I/O. The write
path (``Op.WRITE_REQUEST``/``Op.WRITE_RESPONSE`` and ``NSDPPacket.add_tlv``
with a non-empty value) is new relative to the read-only prior-art client,
but uses the exact same wire layout.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

NSDP_SIGNATURE = b"NSDP"
HEADER_SIZE = 32
HEADER_FORMAT = ">BB H 4s 6s 6s HH 4s 4s"
END_MARKER = struct.pack(">HH", 0xFFFF, 0x0000)  # b"\xff\xff\x00\x00"


class Op(IntEnum):
    """NSDP operation codes (header byte 1).

    READ_REQUEST/RESPONSE are used for discovery and property queries.
    WRITE_REQUEST/RESPONSE are used to modify switch configuration
    (requires authentication via Tag.PASSWORD or Tag.AUTH_V2_PASSWORD).
    """

    READ_REQUEST = 0x01
    READ_RESPONSE = 0x02
    WRITE_REQUEST = 0x03
    WRITE_RESPONSE = 0x04


class Tag(IntEnum):
    """NSDP TLV tag identifiers.

    Each tag represents a switch property. Tags are 16-bit unsigned integers
    encoded big-endian in the packet. See
    ``gdoc2netcfg/docs/nsdp-protocol.md`` (TLV Tag Registry) for byte-level
    encoding details of each tag's value field.
    """

    # Packet markers
    START_OF_MARK = 0x0000
    END_OF_MARK = 0xFFFF

    # Device identity
    MODEL = 0x0001
    HOSTNAME = 0x0003
    MAC = 0x0004
    LOCATION = 0x0005
    IP_ADDRESS = 0x0006
    NETMASK = 0x0007
    GATEWAY = 0x0008
    DHCP_MODE = 0x000B
    FIRMWARE_VER_1 = 0x000D
    FIRMWARE_VER_2 = 0x000E
    PORT_COUNT = 0x6000
    SERIAL_NUMBER = 0x7800

    # Authentication
    PASSWORD = 0x000A
    AUTH_V2_SALT = 0x0017
    AUTH_V2_PASSWORD = 0x001A

    # Port information
    PORT_STATUS = 0x0C00
    PORT_STATISTICS = 0x1000

    # VLAN
    VLAN_ENGINE = 0x2000
    VLAN_MEMBERS = 0x2800
    PORT_PVID = 0x3000

    # QoS
    QOS_ENGINE = 0x3400
    PORT_QOS_PRIORITY = 0x3800

    # Traffic control
    INGRESS_RATE_LIMIT = 0x4C00
    EGRESS_RATE_LIMIT = 0x5000
    BROADCAST_FILTERING = 0x5400
    BROADCAST_BANDWIDTH = 0x5800
    PORT_MIRRORING = 0x5C00

    # IGMP
    IGMP_SNOOPING = 0x6800
    BLOCK_UNKNOWN_MULTICAST = 0x6C00
    IGMPV3_HEADER_VALIDATION = 0x7000
    IGMP_STATIC_ROUTER_PORTS = 0x8000

    # Other
    LOOP_DETECTION = 0x9000
    ACTIVE_FIRMWARE = 0x000C

    # Actions (write-only)
    REBOOT = 0x0013
    FACTORY_RESET = 0x0400


@dataclass(frozen=True)
class TLVEntry:
    """One NSDP TLV: a 2-byte tag, 2-byte length, then that many value bytes."""

    tag: Tag | int
    value: bytes = b""

    def encode(self) -> bytes:
        return struct.pack(">HH", int(self.tag), len(self.value)) + self.value

    @classmethod
    def decode(cls, data: bytes) -> tuple[TLVEntry, int]:
        if len(data) < 4:
            raise ValueError("NSDP TLV shorter than its 4-byte header")
        tag_raw, length = struct.unpack_from(">HH", data, 0)
        if len(data) < 4 + length:
            raise ValueError(
                f"NSDP TLV declares {length} value bytes but only "
                f"{len(data) - 4} are present"
            )
        value = data[4 : 4 + length]
        tag: Tag | int
        try:
            tag = Tag(tag_raw)
        except ValueError:
            tag = tag_raw  # unknown/uncatalogued tag: keep the raw int
        return cls(tag=tag, value=value), 4 + length


@dataclass
class NSDPPacket:
    """A full NSDP datagram: a fixed header plus a list of TLVs."""

    op: Op
    client_mac: bytes
    server_mac: bytes = b"\x00" * 6
    sequence: int = 0
    result: int = 0
    tlvs: list[TLVEntry] = field(default_factory=list)

    def add_tlv(self, tag: Tag | int, value: bytes = b"") -> None:
        self.tlvs.append(TLVEntry(tag=tag, value=value))

    def encode(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            0x01,
            int(self.op),
            self.result,
            b"\x00" * 4,
            self.client_mac,
            self.server_mac,
            0,
            self.sequence,
            NSDP_SIGNATURE,
            b"\x00" * 4,
        )
        body = b"".join(t.encode() for t in self.tlvs)
        return header + body + END_MARKER

    @classmethod
    def decode(cls, data: bytes) -> NSDPPacket:
        if len(data) < HEADER_SIZE:
            raise ValueError(f"NSDP packet shorter than {HEADER_SIZE}-byte header")
        (
            _version,
            op_raw,
            result,
            _reserved1,
            client_mac,
            server_mac,
            _reserved2,
            sequence,
            signature,
            _reserved3,
        ) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        if signature != NSDP_SIGNATURE:
            raise ValueError(f"bad NSDP signature {signature!r}")
        tlvs: list[TLVEntry] = []
        offset = HEADER_SIZE
        while offset + 4 <= len(data):
            entry, consumed = TLVEntry.decode(data[offset:])
            if entry.tag == Tag.END_OF_MARK:
                break
            tlvs.append(entry)
            offset += consumed
        return cls(
            op=Op(op_raw),
            client_mac=client_mac,
            server_mac=server_mac,
            sequence=sequence,
            result=result,
            tlvs=tlvs,
        )
