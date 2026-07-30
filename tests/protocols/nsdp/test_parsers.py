from __future__ import annotations

import struct

import pytest

from netgear_switch.protocols.nsdp import parsers
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.protocols.nsdp.types import LinkSpeed, VLANEngine


def test_link_speed_from_byte_and_mbps():
    assert LinkSpeed.from_byte(0x05) is LinkSpeed.GIGABIT
    # 0x06 is the REAL 10G code. Captured on a GS110EMX (10.1.5.25 and .26,
    # firmware 1.0.2.8, 2026-07-30): PORT_STATUS answers ``09 06 01`` /
    # ``0a 06 01`` for the two 10G/Multi-Gig uplinks while the switch's own
    # /iss/specific/port_settings.html shows them "Up ... 10G Full". Before
    # this, 0x06 was an unknown code and both uplinks were reported LINK DOWN.
    assert LinkSpeed.from_byte(0x06) is LinkSpeed.TEN_GIGABIT
    assert LinkSpeed.TEN_GIGABIT.speed_mbps == 10000
    # 0xFF is prior art that no real switch here has ever emitted; it stays
    # DECODABLE as 10G (never silently "down") but is a separate member so it
    # can't be mistaken for the measured value.
    assert LinkSpeed.from_byte(0xFF) is LinkSpeed.TEN_GIGABIT_PRIOR_ART
    assert LinkSpeed.TEN_GIGABIT_PRIOR_ART.speed_mbps == 10000
    assert LinkSpeed.from_byte(0x77) is LinkSpeed.DOWN  # unknown -> DOWN, no raise
    assert LinkSpeed.GIGABIT.speed_mbps == 1000
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


def test_parse_port_statistics_rejects_truncated():
    # Too short: 25 bytes instead of 49
    data = (
        b"\x01"
        + struct.pack(">Q", 1000)
        + struct.pack(">Q", 500)
        + struct.pack(">Q", 3)
    )
    with pytest.raises(
        ValueError, match="PORT_STATISTICS TLV must be 49 bytes, got 25"
    ):
        parsers.parse_port_statistics(data)


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


class TestParsePortMirroring:
    """Byte vectors lifted verbatim from
    ``gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParsePortMirroring``
    (same source bytes, same expected decode) to prove this port is faithful.
    """

    def test_disabled(self):
        result = parsers.parse_port_mirroring(b"\x00\x00\x00\x00")
        assert result.destination_port == 0
        assert result.source_ports == frozenset()

    def test_enabled_single_source(self):
        # Dest port 10, source port 1 (bitmap 0x80 = 10000000)
        result = parsers.parse_port_mirroring(b"\x0a\x80\x00\x00")
        assert result.destination_port == 10
        assert result.source_ports == frozenset({1})

    def test_enabled_multiple_sources(self):
        # Dest port 10, source ports 1,2 (bitmap 0xC0 = 11000000)
        result = parsers.parse_port_mirroring(b"\x0a\xc0\x00\x00")
        assert result.destination_port == 10
        assert result.source_ports == frozenset({1, 2})

    def test_enabled_many_sources(self):
        # Dest port 5, source ports 1-8 (bitmap 0xFF 0x00 0x00)
        result = parsers.parse_port_mirroring(b"\x05\xff\x00\x00")
        assert result.destination_port == 5
        assert result.source_ports == frozenset({1, 2, 3, 4, 5, 6, 7, 8})

    def test_short_bitmap_parses(self):
        # A 2-byte TLV (dest + 1-byte bitmap) is valid on a small switch, not an
        # error -- the bitmap width is model-dependent (see the GS105PE live
        # finding in test_port_mirroring_variable_width_bitmap).
        pm = parsers.parse_port_mirroring(b"\x0a\xc0")
        assert pm.destination_port == 10
        assert pm.source_ports == frozenset({1, 2})

    def test_long_bitmap_parses(self):
        # A wider (3-byte) bitmap is likewise valid, not an error.
        pm = parsers.parse_port_mirroring(b"\x0a\xc0\x00\x00")
        assert pm.destination_port == 10
        assert pm.source_ports == frozenset({1, 2})


class TestParseIgmpSnooping:
    """Byte vectors lifted verbatim from
    ``gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParseIGMPSnooping``.
    """

    def test_enabled(self):
        result = parsers.parse_igmp_snooping(b"\x00\x01\x00\x01")
        assert result.enabled is True

    def test_disabled(self):
        result = parsers.parse_igmp_snooping(b"\x00\x00\x00\x00")
        assert result.enabled is False

    def test_enabled_with_vlan(self):
        # enabled, vlan_id = 10 in byte 3
        result = parsers.parse_igmp_snooping(b"\x00\x01\x00\x0a")
        assert result.enabled is True
        assert result.vlan_id == 10

    def test_enabled_no_vlan(self):
        # enabled, vlan_id = 0 means None
        result = parsers.parse_igmp_snooping(b"\x00\x01\x00\x00")
        assert result.enabled is True
        assert result.vlan_id is None

    def test_invalid_length_too_short(self):
        with pytest.raises(ValueError, match="2 bytes"):
            parsers.parse_igmp_snooping(b"\x00")


class TestParseDeviceNewTags:
    """Byte vectors lifted verbatim from
    ``gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParseDiscoveryResponseNewTags``
    -- proves ``parse_device`` decodes QOS_ENGINE/PORT_MIRRORING/IGMP_SNOOPING/
    BROADCAST_FILTERING/LOOP_DETECTION identically to the gdoc2netcfg original.
    """

    @staticmethod
    def _pkt() -> NSDPPacket:
        return NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\x00\x09\x5b\xaa\xbb\xcc",
        )

    def test_qos_engine(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.QOS_ENGINE, b"\x02")  # 802.1p mode

        device = parsers.parse_device(pkt)
        assert device.qos_engine == 2

    def test_port_mirroring(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        # Dest port 10, source ports 1,2 (bitmap 0xC0)
        pkt.add_tlv(Tag.PORT_MIRRORING, b"\x0a\xc0\x00\x00")

        device = parsers.parse_device(pkt)
        assert device.port_mirroring is not None
        assert device.port_mirroring.destination_port == 10
        assert device.port_mirroring.source_ports == frozenset({1, 2})

    def test_port_mirroring_variable_width_bitmap(self):
        # A 5-port GS105PE returns a 3-byte PORT_MIRRORING (dest + 2-byte
        # bitmap), not the 10-port GS110EMX's 4-byte form -- captured live
        # 2026-07-21 as ``00 00 00`` (mirroring off). Must parse, not raise.
        off = parsers.parse_port_mirroring(b"\x00\x00\x00")
        assert off.destination_port == 0
        assert off.source_ports == frozenset()
        # dest port 5, source ports 1,2 in a 2-byte bitmap
        pm = parsers.parse_port_mirroring(b"\x05\xc0\x00")
        assert pm.destination_port == 5
        assert pm.source_ports == frozenset({1, 2})
        # an empty TLV is still rejected (no dest-port byte at all)
        with pytest.raises(ValueError, match="at least 1 byte"):
            parsers.parse_port_mirroring(b"")

    def test_igmp_snooping(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.IGMP_SNOOPING, b"\x00\x01\x00\x0a")  # enabled, vlan=10

        device = parsers.parse_device(pkt)
        assert device.igmp_snooping is not None
        assert device.igmp_snooping.enabled is True
        assert device.igmp_snooping.vlan_id == 10

    def test_broadcast_filtering(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.BROADCAST_FILTERING, b"\x01")  # enabled

        device = parsers.parse_device(pkt)
        assert device.broadcast_filtering is True

    def test_loop_detection(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.LOOP_DETECTION, b"\x00")  # disabled

        device = parsers.parse_device(pkt)
        assert device.loop_detection is False

    def test_all_new_tags_together(self):
        pkt = self._pkt()
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.MAC, b"\x00\x09\x5b\xaa\xbb\xcc")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")  # 10 ports
        pkt.add_tlv(Tag.QOS_ENGINE, b"\x01")  # port-based
        pkt.add_tlv(Tag.PORT_MIRRORING, b"\x05\x80\x00\x00")  # dest=5, source=1
        pkt.add_tlv(Tag.IGMP_SNOOPING, b"\x00\x01\x00\x00")  # enabled, no vlan
        pkt.add_tlv(Tag.BROADCAST_FILTERING, b"\x01")
        pkt.add_tlv(Tag.LOOP_DETECTION, b"\x01")

        device = parsers.parse_device(pkt)
        assert device.qos_engine == 1
        assert device.port_mirroring is not None
        assert device.port_mirroring.destination_port == 5
        assert device.igmp_snooping is not None
        assert device.igmp_snooping.enabled is True
        assert device.broadcast_filtering is True
        assert device.loop_detection is True


def test_parse_device_aggregates_read_response():
    pkt = NSDPPacket(
        op=Op.READ_RESPONSE,
        client_mac=b"\x00" * 6,
        server_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
    )
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
