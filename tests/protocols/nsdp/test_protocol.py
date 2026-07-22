from __future__ import annotations

import struct

import pytest

from netgear_switch.protocols.nsdp.protocol import (
    END_MARKER,
    HEADER_SIZE,
    NSDP_SIGNATURE,
    NSDPPacket,
    Op,
    Tag,
    TLVEntry,
)


def test_tag_and_op_values_match_wire_constants():
    assert Op.READ_REQUEST == 0x01
    assert Op.WRITE_REQUEST == 0x03
    assert Op.WRITE_RESPONSE == 0x04
    assert Tag.MODEL == 0x0001
    assert Tag.PASSWORD == 0x000A
    assert Tag.REBOOT == 0x0013
    assert Tag.AUTH_V2_SALT == 0x0017
    assert Tag.AUTH_V2_PASSWORD == 0x001A
    assert Tag.PORT_STATUS == 0x0C00
    assert Tag.PORT_STATISTICS == 0x1000
    assert Tag.VLAN_MEMBERS == 0x2800
    assert Tag.PORT_PVID == 0x3000
    assert Tag.SERIAL_NUMBER == 0x7800


def test_tlv_encode_decode_roundtrip():
    tlv = TLVEntry(Tag.MODEL, b"GS110EMX")
    raw = tlv.encode()
    assert raw == struct.pack(">HH", 0x0001, 8) + b"GS110EMX"
    decoded, consumed = TLVEntry.decode(raw)
    assert consumed == 12
    assert decoded.tag == Tag.MODEL
    assert decoded.value == b"GS110EMX"


def test_tlv_decode_unknown_tag_kept_as_int():
    raw = struct.pack(">HH", 0xABCD, 0)
    decoded, consumed = TLVEntry.decode(raw)
    assert decoded.tag == 0xABCD
    assert consumed == 4


def test_tlv_decode_truncated_value_raises():
    with pytest.raises(ValueError, match="declares"):
        TLVEntry.decode(struct.pack(">HH", 0x0001, 8) + b"short")


def test_tlv_decode_truncated_header_raises():
    with pytest.raises(ValueError, match="4-byte header"):
        TLVEntry.decode(b"\x00\x01")


def test_packet_decode_short_data_raises():
    with pytest.raises(ValueError, match="32-byte header"):
        NSDPPacket.decode(b"\x00" * 10)


def test_packet_encode_has_signature_at_offset_0x18_and_end_marker():
    pkt = NSDPPacket(
        op=Op.READ_REQUEST,
        client_mac=b"\x00\x00\x00\x00\x00\x01",
        server_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        sequence=42,
    )
    pkt.add_tlv(Tag.MODEL)  # empty value = read request
    raw = pkt.encode()
    assert raw[0] == 0x01                          # version
    assert raw[1] == Op.READ_REQUEST
    assert raw[0x18:0x1C] == NSDP_SIGNATURE
    assert raw.endswith(END_MARKER)
    assert len(raw) == HEADER_SIZE + 4 + len(END_MARKER)  # one empty TLV


def test_packet_decode_reads_tlvs_until_end_marker_and_ignores_trailing():
    pkt = NSDPPacket(
        op=Op.READ_RESPONSE,
        client_mac=b"\x00\x00\x00\x00\x00\x01",
        server_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        sequence=7,
    )
    pkt.add_tlv(Tag.MODEL, b"GS110EMX")
    pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
    raw = pkt.encode() + b"garbage-after-eom"
    back = NSDPPacket.decode(raw)
    assert back.op == Op.READ_RESPONSE
    assert back.sequence == 7
    assert back.server_mac == b"\xaa\xbb\xcc\xdd\xee\xff"
    assert [(t.tag, t.value) for t in back.tlvs] == [
        (Tag.MODEL, b"GS110EMX"),
        (Tag.PORT_COUNT, b"\x0a"),
    ]


def test_packet_decode_bad_signature_raises():
    with pytest.raises(ValueError, match="signature"):
        NSDPPacket.decode(b"\x00" * 32)


def test_write_request_roundtrip():
    """The write path is new: the codec must build WRITE_REQUEST packets
    even though the prior-art (read-only) client never did."""
    pkt = NSDPPacket(
        op=Op.WRITE_REQUEST,
        client_mac=b"\x00\x00\x00\x00\x00\x01",
        server_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        sequence=99,
    )
    pkt.add_tlv(Tag.PASSWORD, b"secret")
    pkt.add_tlv(Tag.HOSTNAME, b"switch01")
    pkt.add_tlv(Tag.REBOOT)  # empty-value action TLV
    raw = pkt.encode()

    assert raw[1] == Op.WRITE_REQUEST
    assert raw[0x18:0x1C] == NSDP_SIGNATURE
    assert raw.endswith(END_MARKER)

    back = NSDPPacket.decode(raw)
    assert back.op == Op.WRITE_REQUEST
    assert back.sequence == 99
    assert back.client_mac == b"\x00\x00\x00\x00\x00\x01"
    assert back.server_mac == b"\xaa\xbb\xcc\xdd\xee\xff"
    assert [(t.tag, t.value) for t in back.tlvs] == [
        (Tag.PASSWORD, b"secret"),
        (Tag.HOSTNAME, b"switch01"),
        (Tag.REBOOT, b""),
    ]


def test_packet_decode_hand_built_fixture_independent_of_encode():
    """Decode a byte fixture built independently of NSDPPacket.encode(),
    modelled on a real WRITE_RESPONSE, to cross-check the wire layout
    (header field offsets, TLV framing, end marker) documented in
    gdoc2netcfg/docs/nsdp-protocol.md rather than relying solely on our
    own encoder producing symmetric bugs."""
    header = struct.pack(
        ">BB H 4s 6s 6s HH 4s 4s",
        0x01,  # version
        Op.WRITE_RESPONSE,
        0x0000,  # result: success
        b"\x00" * 4,
        b"\x00\x00\x00\x00\x00\x01",  # client_mac
        b"\xaa\xbb\xcc\xdd\xee\xff",  # server_mac
        0,
        123,  # sequence
        NSDP_SIGNATURE,
        b"\x00" * 4,
    )
    body = (
        struct.pack(">HH", Tag.HOSTNAME, 4) + b"sw01"
        + struct.pack(">HH", Tag.DHCP_MODE, 1) + b"\x01"
    )
    raw = header + body + END_MARKER

    pkt = NSDPPacket.decode(raw)
    assert pkt.op == Op.WRITE_RESPONSE
    assert pkt.result == 0
    assert pkt.client_mac == b"\x00\x00\x00\x00\x00\x01"
    assert pkt.server_mac == b"\xaa\xbb\xcc\xdd\xee\xff"
    assert pkt.sequence == 123
    assert [(t.tag, t.value) for t in pkt.tlvs] == [
        (Tag.HOSTNAME, b"sw01"),
        (Tag.DHCP_MODE, b"\x01"),
    ]


def test_sequence_number_is_a_full_4_byte_field() -> None:
    """NSDP's seqnum is 4 bytes (ngadmin's authoritative struct nsdp_header),
    not a 2-byte value with 2 reserved bytes before it. A seqnum > 0xFFFF must
    round-trip intact -- the old ">...HH..." layout silently truncated the high
    16 bits, which would make the mock echo the wrong seqnum and an independent
    client (ngadmin) reject the reply."""
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    pkt = NSDPPacket(
        op=Op.READ_REQUEST,
        client_mac=b"\x11" * 6,
        server_mac=b"\x22" * 6,
        sequence=0x12345678,
    )
    pkt.add_tlv(Tag.MODEL)
    wire = pkt.encode()
    assert len(wire) >= 32
    # the seqnum occupies header bytes 20..23, big-endian
    assert wire[20:24] == b"\x12\x34\x56\x78"
    assert NSDPPacket.decode(wire).sequence == 0x12345678
