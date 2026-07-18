from __future__ import annotations

import struct

import pytest

from netgear_switch.protocols.nsdp import parsers
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.protocols.nsdp.types import LinkSpeed, VLANEngine


def test_link_speed_from_byte_and_mbps():
    assert LinkSpeed.from_byte(0x05) is LinkSpeed.GIGABIT
    assert LinkSpeed.from_byte(0xFF) is LinkSpeed.TEN_GIGABIT
    assert LinkSpeed.from_byte(0x77) is LinkSpeed.DOWN  # unknown -> DOWN, no raise
    assert LinkSpeed.GIGABIT.speed_mbps == 1000
    assert LinkSpeed.TEN_GIGABIT.speed_mbps == 10000
    assert LinkSpeed.DOWN.speed_mbps == 0


def test_parse_ipv4_and_mac():
    assert parsers.parse_ipv4(b"\x0a\x01\x14\x01") == "10.1.20.1"
    assert parsers.parse_mac(b"\x00\x09\x5b\xaa\xbb\xcc") == "00:09:5b:aa:bb:cc"


def test_parse_port_status_3_bytes():
    st = parsers.parse_port_status(b"\x01\x05\x01")  # port 1, gigabit
    assert (st.port_id, st.speed) == (1, LinkSpeed.GIGABIT)
    down = parsers.parse_port_status(b"\x03\x00\x01")  # port 3, down
    assert down.speed is LinkSpeed.DOWN


def test_parse_port_statistics_49_bytes():
    data = (
        b"\x01"
        + struct.pack(">Q", 1000)
        + struct.pack(">Q", 500)
        + struct.pack(">Q", 3)
        + b"\x00" * 24
    )
    stats = parsers.parse_port_statistics(data)
    assert (stats.port_id, stats.bytes_received, stats.bytes_sent) == (1, 1000, 500)
    assert stats.crc_errors == 3


def test_parse_port_pvid_3_bytes():
    pv = parsers.parse_port_pvid(b"\x05\x00\x64")  # port 5, vlan 100
    assert (pv.port_id, pv.vlan_id) == (5, 100)


def test_bitmap_roundtrip_msb_first_1_based():
    assert parsers.bitmap_to_ports(bytes([0b1111_0000])) == frozenset({1, 2, 3, 4})
    assert parsers.bitmap_to_ports(bytes([0x00, 0x80])) == frozenset({9})
    assert parsers.ports_to_bitmap({1, 2, 3, 4}, width_bytes=1) == bytes([0b1111_0000])
    assert parsers.ports_to_bitmap({9}, width_bytes=2) == bytes([0x00, 0x80])


def test_parse_vlan_members_8_port():
    data = struct.pack(">H", 100) + bytes([0b1111_0000]) + bytes([0b0001_0000])
    m = parsers.parse_vlan_members(data, port_count=8)
    assert m.vlan_id == 100
    assert m.member_ports == frozenset({1, 2, 3, 4})
    assert m.tagged_ports == frozenset({4})
    assert m.untagged_ports == frozenset({1, 2, 3})


def test_parse_serial_requires_0x01_prefix():
    assert parsers.parse_serial(b"\x0153H6025EA0083") == "53H6025EA0083"
    with pytest.raises(ValueError, match="unexpected prefix byte"):
        parsers.parse_serial(b"\x0253H6025EA0083")


def test_parse_device_aggregates_read_response():
    pkt = NSDPPacket(op=Op.READ_RESPONSE, client_mac=b"\x00" * 6,
                     server_mac=b"\xaa\xbb\xcc\xdd\xee\xff")
    pkt.add_tlv(Tag.MODEL, b"GS110EMX")
    pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
    pkt.add_tlv(Tag.IP_ADDRESS, b"\x0a\x01\x05\x14")
    pkt.add_tlv(Tag.DHCP_MODE, b"\x00")
    pkt.add_tlv(Tag.VLAN_ENGINE, bytes([VLANEngine.ADVANCED_802_1Q]))
    pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
    pkt.add_tlv(Tag.PORT_PVID, b"\x01\x00\x5a")
    dev = parsers.parse_device(pkt)
    assert dev.model == "GS110EMX"
    assert dev.port_count == 10
    assert dev.ip == "10.1.5.20"
    assert dev.dhcp_enabled is False
    assert dev.vlan_engine is VLANEngine.ADVANCED_802_1Q
    assert dev.port_status[0].speed is LinkSpeed.GIGABIT
    assert dev.port_pvids[0].vlan_id == 90
    # No MAC tag: falls back to the header server_mac.
    assert dev.mac == "aa:bb:cc:dd:ee:ff"
