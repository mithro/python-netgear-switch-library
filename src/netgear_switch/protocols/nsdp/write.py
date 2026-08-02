"""NSDP request framing + value-TLV encoders for the read and write paths.

Pure: builds ``NSDPPacket`` objects, no I/O. Two authenticated WRITE builders
exist, one per scheme the transport auto-selects from AUTH_V2_ENCPASS:

* ``build_write_request`` — v1: prepend the XOR ``PASSWORD`` (0x000A) TLV.
* ``build_write_request_v2`` — v2: the 8-byte ``AUTH_V2_PASSWORD`` (0x001A)
  token FIRST, then the config TLVs (see ``auth.auth_v2_password``). The
  ordering is load-bearing: trailing the token is rejected error 13.

The v2 auth is LIVE-VERIFIED on a GS110EMX (fw 1.0.2.8): a correctly-authed
write returns header error 0 and reads back; a wrong token returns error 13.
``check_result`` maps the rejection codes; verify-after-write in
``nsdp_write.py`` remains the guard against a silently wrong value encoding.

Note on tag writability: the ``gdoc2netcfg`` reference spec marks ``PORT_PVID``
(0x3000) and ``VLAN_MEMBERS`` (0x2800) as READ-ONLY. The ProSafe utility does
configure both over NSDP, and ``nsdp_write.py``'s set_pvid / set_vlan_membership
drive them with verify-after-write; see those methods for the live-verified
status of each on the GS110EMX.
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

# The header's 2-byte ``result`` field is (error-byte << 8 | unk1); unk1 is
# always 0, so the error CODE is ``result >> 8``. These constants are the whole
# 2-byte value for convenience.
RESULT_SUCCESS = 0x0000
# v1 / older-firmware denial (ngadmin ERROR_DENIED == 7).
RESULT_BAD_PASSWORD = 0x0700
# v2 salted-auth rejection (error byte 13) -- LIVE on a GS110EMX (fw 1.0.2.8):
# a WRITE whose AUTH_V2_PASSWORD token is wrong comes back error 13.
RESULT_BAD_PASSWORD_V2 = 0x0D00
# v2 write lockout (error byte 14): after repeated rapid auth failures the same
# GS110EMX escalates 13 -> 14 and then goes SILENT (no write reply) for a
# cooldown. READ requests keep working throughout.
RESULT_LOCKED_V2 = 0x0E00
# Structural rejections (ngadmin ERROR_READONLY == 3 / ERROR_WRITEONLY == 4).
# A GS110EMX returns error 3 for a READ that names a write-only tag (e.g.
# AUTH_V2_PASSWORD 0x001A) and error 4 for a WRITE that LEADS with 0x001A.
RESULT_READONLY = 0x0300
RESULT_WRITEONLY = 0x0400


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
    """Build a v1-authenticated WRITE: the XOR ``PASSWORD`` TLV, then config."""
    pkt = NSDPPacket(
        op=Op.WRITE_REQUEST,
        client_mac=client_mac,
        server_mac=server_mac,
        sequence=sequence,
    )
    pkt.tlvs.append(TLVEntry(Tag.PASSWORD, encode_password_v1(password)))
    pkt.tlvs.extend(tlvs)
    return pkt


def build_write_request_v2(
    client_mac: bytes,
    server_mac: bytes,
    sequence: int,
    tlvs: list[TLVEntry],
    auth_token: bytes,
) -> NSDPPacket:
    """Build a v2-authenticated WRITE: the 8-byte ``AUTH_V2_PASSWORD`` token
    FIRST, then the config TLVs.

    Ordering is load-bearing and LIVE-VERIFIED on a GS110EMX: leading with the
    0x001A token authenticates and applies the write (header error 0);
    trailing it after the config change is rejected error 13. This matches
    yaamai/go-nsdp's ``WriteWithAuth`` (auth TLV prepended). The caller must
    have just read a fresh AUTH_V2_SALT so the token matches the switch's
    stored challenge.
    """
    pkt = NSDPPacket(
        op=Op.WRITE_REQUEST,
        client_mac=client_mac,
        server_mac=server_mac,
        sequence=sequence,
    )
    pkt.tlvs.append(TLVEntry(Tag.AUTH_V2_PASSWORD, auth_token))
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
    that "NSDP has no VLAN create/destroy tag". It is still NOT confirmed
    against hardware: authenticated NSDP writes DO work on the reachable
    GS110EMX (fw 1.0.2.8) now that v2 auth is implemented -- PORT_PVID and
    VLAN_MEMBERS were written and read back live -- but destroying a VLAN on a
    production switch was out of scope for that session, so this tag stayed
    un-exercised. Verify-after-write in ``nsdp_write.py`` is the runtime guard.
    """
    return TLVEntry(Tag.VLAN_DESTROY, struct.pack(">H", vlan))


def port_name_tlv(port: int, name: str) -> TLVEntry:
    """Per-port description write TLV (tag 0xB000), mirroring the read shape.

    The READ encoding is measured (port byte + description bytes, see
    ``Tag.PORT_NAME``); the write is the same shape and, like
    ``vlan_destroy_tlv``, was never exercised against hardware.
    """
    return TLVEntry(Tag.PORT_NAME, bytes([port]) + name.encode("utf-8"))


def hostname_tlv(name: str) -> TLVEntry:
    """Host-name write TLV (tag 0x0003), the same shape the read decodes.

    The read side is measured -- ``parsers`` decodes this tag as plain text and
    three live GS110EMX report their names through it -- so the write is that
    encoding with nothing added: the bare name, ASCII, no length prefix and no
    port byte (unlike ``port_name_tlv`` above, whose tag is indexed by port).
    """
    return TLVEntry(Tag.HOSTNAME, name.encode("ascii"))


def ipv4_tlv(tag: Tag, dotted: str) -> TLVEntry:
    return TLVEntry(tag, socket.inet_aton(dotted))


def dhcp_tlv(enabled: bool) -> TLVEntry:
    return TLVEntry(Tag.DHCP_MODE, b"\x01" if enabled else b"\x00")


def reboot_tlv() -> TLVEntry:
    return TLVEntry(Tag.REBOOT, b"")
