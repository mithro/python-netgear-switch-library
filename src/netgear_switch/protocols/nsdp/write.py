"""NSDP request framing + value-TLV encoders for the read and write paths.

Pure: builds ``NSDPPacket`` objects, no I/O. The write path (absent from the
lifted ``gdoc2netcfg`` package, which was read-only) prepends a v1 ``PASSWORD``
TLV — a real switch rejects an unauthenticated or wrongly-authenticated write
with result 0x0700, which the transport turns into an ``NsdpError`` (Task 4).

UNVERIFIED write path (mirrors ``snmp_write.py``'s house style for its
mgmt_write_* OIDs). This entire NSDP write path — the WRITE_REQUEST value-TLV
encodings here plus the v1 XOR auth in ``auth.py`` — is a from-scratch addition
with ZERO verification against real hardware: the lifted ``gdoc2netcfg/src/nsdp``
prior art is READ-ONLY, so nothing in it exercises writes. It stays UNVERIFIED
pending a real capture (Slice 7 capture utility / a real-hardware run);
verify-after-write in ``nsdp_write.py`` is the runtime guard against a silently
wrong encoding. Critically, the reference spec
(``gdoc2netcfg/docs/nsdp-protocol.md``) marks ``PORT_PVID`` (0x3000) and
``VLAN_MEMBERS`` (0x2800) as READ-ONLY (R), unlike hostname/ip/netmask/gateway/
dhcp_mode/vlan_engine (R/W). Writing PVID/VLAN membership via NSDP may therefore
be REJECTED by real hardware — the switch may only accept those changes via the
``vlan_engine`` (or other R/W) tags or via HTTP. Do NOT read the ``pvid_tlv`` /
``vlan_members_tlv`` encoders here as confirmation that those tags are writable;
their writability is unconfirmed and must be settled by a hardware capture.
"""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING

from .auth import encode_password_v1
from .parsers import ports_to_bitmap
from .protocol import NSDPPacket, Op, Tag, TLVEntry

if TYPE_CHECKING:
    from collections.abc import Iterable

RESULT_SUCCESS = 0x0000
RESULT_BAD_PASSWORD = 0x0700


def build_read_request(
    client_mac: bytes, server_mac: bytes, sequence: int, tags: list[Tag]
) -> NSDPPacket:
    pkt = NSDPPacket(
        op=Op.READ_REQUEST,
        client_mac=client_mac,
        server_mac=server_mac,
        sequence=sequence,
    )
    for tag in tags:
        pkt.add_tlv(tag)  # length-0 TLV = "please read this"
    return pkt


def build_write_request(
    client_mac: bytes,
    server_mac: bytes,
    sequence: int,
    password: str,
    tlvs: list[TLVEntry],
) -> NSDPPacket:
    pkt = NSDPPacket(
        op=Op.WRITE_REQUEST,
        client_mac=client_mac,
        server_mac=server_mac,
        sequence=sequence,
    )
    pkt.tlvs.append(TLVEntry(Tag.PASSWORD, encode_password_v1(password)))
    pkt.tlvs.extend(tlvs)
    return pkt


def pvid_tlv(port: int, vlan: int) -> TLVEntry:
    return TLVEntry(Tag.PORT_PVID, bytes([port]) + struct.pack(">H", vlan))


def vlan_members_tlv(
    vlan: int, members: Iterable[int], tagged: Iterable[int], port_count: int
) -> TLVEntry:
    width = (port_count + 7) // 8
    value = (
        struct.pack(">H", vlan)
        + ports_to_bitmap(members, width)
        + ports_to_bitmap(tagged, width)
    )
    return TLVEntry(Tag.VLAN_MEMBERS, value)


def vlan_destroy_tlv(vlan: int) -> TLVEntry:
    """The write-only VLAN-destroy action TLV (tag 0x2C00, 2-byte VLAN id).

    GROUNDED in ngadmin's independent C implementation --
    ``lib/src/vlan.c::ngadmin_VLANDestroy`` builds exactly
    ``newShortAttr(ATTR_VLAN_DESTROY, vlan)`` and sends it as a write request.
    That is the evidence that replaced this library's previous unproven claim
    that "NSDP has no VLAN create/destroy tag". It is NOT confirmed against
    hardware here: the only NSDP switch reachable from this repo (GS110EMX,
    fw 1.0.2.8) rejects every WRITE_REQUEST at the PASSWORD attribute because
    it wants the undocumented v2 salted auth (see protocol.ERROR_AUTH_VERSION),
    so no NSDP write of any kind -- not this one, not the pre-existing PVID /
    membership / mgmt-IP writes -- could be exercised on it. Verify-after-write
    in ``nsdp_write.py`` is the runtime guard.
    """
    return TLVEntry(Tag.VLAN_DESTROY, struct.pack(">H", vlan))


def port_name_tlv(port: int, name: str) -> TLVEntry:
    """Per-port description write TLV (tag 0xB000), mirroring the read shape.

    The READ encoding is measured (port byte + description bytes, see
    ``Tag.PORT_NAME``); the write is the same shape, unexercised for the same
    auth reason as ``vlan_destroy_tlv``.
    """
    return TLVEntry(Tag.PORT_NAME, bytes([port]) + name.encode("utf-8"))


def ipv4_tlv(tag: Tag, dotted: str) -> TLVEntry:
    return TLVEntry(tag, socket.inet_aton(dotted))


def dhcp_tlv(enabled: bool) -> TLVEntry:
    return TLVEntry(Tag.DHCP_MODE, b"\x01" if enabled else b"\x00")


def reboot_tlv() -> TLVEntry:
    return TLVEntry(Tag.REBOOT, b"")
