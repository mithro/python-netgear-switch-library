"""NSDP wire codec: 32-byte header, TLV entries, and packet encode/decode.

Lifted (field-for-field) from ``gdoc2netcfg/src/nsdp/protocol.py``, with the
header's old opaque 4-byte reserved blob split once hardware showed what is in
it. The header is ``struct`` layout ``>BB H H 2s 6s 6s I 4s 4s`` (32 bytes):
version (always 0x01), operation, result, error-attr(2), reserved(2), client
MAC(6), server MAC(6), sequence(4), signature ``b"NSDP"`` at offset 0x18,
reserved(4). Each TLV is ``>HH`` (tag, length) followed by ``length`` value
bytes; a packet ends with the ``0xFFFF 0x0000`` end-of-marker.

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
# The sequence number is a FULL 4-byte field (">...I..."), not a 2-byte value
# preceded by 2 reserved bytes. Cross-checking the mock against ngadmin
# (herveboisse/ngadmin, whose `struct nsdp_header` is the authoritative NSDP
# layout) surfaced this: its `unsigned int seqnum` spans the two bytes this
# format previously treated as reserved. Observationally identical for the
# small sequence numbers real clients/switches use (the high 2 bytes are 0),
# but a seqnum > 0xFFFF would have been silently truncated on decode and
# mis-echoed by the mock.
# Header bytes 4-5 are NOT reserved: they carry the TLV TAG that caused the
# error reported in bytes 2-3. Two independent investigations of this repo's
# GS110EMX fleet landed on the same field (one from an exhaustive tag sweep, one
# from cracking the v2 write auth), and ngadmin's `struct nsdp_header` names it
# (`unsigned short attr; /* attribute code which caused error */`). Real
# hardware (10.1.5.25, fw 1.0.2.8, 2026-07-29/30) fills it in: a read of an
# unanswerable tag comes back error=3 with this field set to that very tag; a
# write rejected for sending v1 auth comes back with 0x000A (ATTR_PASSWORD);
# a write rejected for a bad v2 token blames the packet's leading TLV. Splitting
# the old opaque ``4s`` reserved field into ``H 2s`` is what lets ``NsdpError``
# name the thing that failed instead of just "the request failed" (principle 1).
HEADER_FORMAT = ">BB H H 2s 6s 6s I 4s 4s"
END_MARKER = struct.pack(">HH", 0xFFFF, 0x0000)  # b"\xff\xff\x00\x00"

# Header error codes (byte 2). Named by ngadmin's protocol.h; codes 13/14 are
# NOT in that list and were MEASURED on a GS110EMX fw 1.0.2.8 -- see
# ``ERROR_NAMES`` and ``client.check_result``.
ERROR_NONE = 0
ERROR_READONLY = 3  # "this attribute cannot be read" on a read request
ERROR_WRITEONLY = 4
ERROR_INVALID_VALUE = 5
ERROR_DENIED = 7  # v1 (older-firmware) password denial
# LIVE-MEASURED on real GS110EMX units (10.1.5.25/.26/.27, fw 1.0.2.8,
# 2026-07-29/30). Neither code appears in ngadmin, which only ever spoke to the
# older v1 firmware. This firmware wants the v2 salted challenge-response
# (AUTH_V2_ENCPASS 0x0014 answers 0x10; AUTH_V2_SALT 0x0017 is readable and
# rotates on every read; AUTH_V2_PASSWORD 0x001A is write-only) -- an algorithm
# this library now IMPLEMENTS and has verified end to end against that hardware
# (see ``auth.auth_v2_password``), so neither code means "scheme unsupported":
#
#   13 -- the write's authentication was refused. Two causes share the code and
#         the error-attr field tells them apart: attr 0x000A (ATTR_PASSWORD)
#         means a v1-XOR/plaintext PASSWORD TLV was offered to a v2-only
#         firmware; any other attr means the v2 token itself was wrong (wrong
#         admin password, or a token folded against a stale salt).
#   14 -- write LOCKOUT after repeated rapid failures. The switch then stops
#         answering WRITE_REQUESTs at all for a cooldown; READs keep working.
ERROR_AUTH_REJECTED = 13
ERROR_LOCKED = 14

ERROR_NAMES = {
    ERROR_NONE: "none",
    ERROR_READONLY: "attribute not readable",
    ERROR_WRITEONLY: "attribute not writable",
    ERROR_INVALID_VALUE: "invalid value",
    ERROR_DENIED: "denied",
    ERROR_AUTH_REJECTED: "write authentication rejected",
    ERROR_LOCKED: "write locked out after repeated auth failures",
}


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
    # Encryption-type probe (ngadmin's ATTR_ENCPASS): a switch answers this
    # 4-byte value to advertise which write-auth scheme it wants. Value 1 =
    # legacy v1 XOR (Tag.PASSWORD); value 0x10 = v2 salted challenge-response
    # (AUTH_V2_SALT / AUTH_V2_PASSWORD). Observed 0x00000010 on a GS110EMX
    # (fw 1.0.2.8).
    AUTH_V2_ENCPASS = 0x0014
    AUTH_V2_SALT = 0x0017
    AUTH_V2_PASSWORD = 0x001A

    # Port information
    PORT_STATUS = 0x0C00
    PORT_STATISTICS = 0x1000
    # Per-port operator description ("Port Description" in the web UI).
    # LIVE-MEASURED on all three real GS110EMX units (10.1.5.25/.26/.27, fw
    # 1.0.2.8, 2026-07-30): one TLV per port, byte 0 = port number, the rest =
    # the description string (absent = a 1-byte TLV). Cross-checked byte-for-
    # byte against each switch's own /iss/specific/port_settings.html "Port
    # Description" column across all 30 ports -- e.g. 10.1.5.26 port 2 answers
    # ``02 7270692d7364722d6b72616b656e`` for the page's "rpi-sdr-kraken".
    # Absent from ngadmin/ProSafeLinux (both predate this firmware family).
    PORT_NAME = 0xB000

    # VLAN
    VLAN_ENGINE = 0x2000
    VLAN_PORT_CONF = 0x2400  # port-based (non-802.1Q) VLAN membership
    VLAN_MEMBERS = 0x2800
    # VLAN destroy (write-only action carrying the 2-byte VLAN id). GROUNDED in
    # ngadmin (herveboisse/ngadmin) ``lib/src/vlan.c::ngadmin_VLANDestroy``:
    #     pushBackList(attr, newShortAttr(ATTR_VLAN_DESTROY, vlan));
    #     return writeRequest(nga, attr);
    # with ``#define ATTR_VLAN_DESTROY 0x2C00`` in raw/include/nsdp/protocol.h.
    # A READ of 0x2C00 on a real GS110EMX (10.1.5.25, fw 1.0.2.8) answers
    # error=3 "attribute not readable" -- exactly what every other write-only
    # action tag answers there (REBOOT 0x0013, FACTORY_RESET 0x0400), so that
    # read error is consistent with the tag existing, not with it being absent.
    VLAN_DESTROY = 0x2C00
    MAX_VLAN = 0x6400  # max simultaneous VLANs; 0x40 (=64) measured on GS110EMX
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
    # The TLV tag the switch blamed for ``result`` (header bytes 4-5); 0 when
    # there is no error. Requests always send 0. ``result`` itself conflates the
    # error code with a trailing unk1 byte (always 0), so the code alone is
    # ``result >> 8`` -- see ``error_code`` below and ``client.check_result``.
    error_attr: int = 0

    @property
    def error_code(self) -> int:
        """The switch's error code alone (header byte 2).

        ``result`` is the 16-bit field bytes 2-3; only its high byte is the
        error code (byte 3 is always 0 on every real reply captured so far),
        so ``result == 0x0300`` means error code 3.
        """
        return (self.result >> 8) & 0xFF

    def add_tlv(self, tag: Tag | int, value: bytes = b"") -> None:
        self.tlvs.append(TLVEntry(tag=tag, value=value))

    def encode(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            0x01,
            int(self.op),
            self.result,
            self.error_attr,
            b"\x00" * 2,
            self.client_mac,
            self.server_mac,
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
            error_attr,
            _reserved1,
            client_mac,
            server_mac,
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
            error_attr=error_attr,
            tlvs=tlvs,
        )
