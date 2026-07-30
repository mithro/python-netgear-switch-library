from __future__ import annotations

import asyncio
import struct

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import IpMode
from netgear_switch.nsdp_read import AsyncNsdpReader, NsdpReader
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.protocols.nsdp.types import LinkSpeed, VLANEngine
from netgear_switch.registry import get_model


def _canned_packet() -> NSDPPacket:
    pkt = NSDPPacket(
        op=Op.READ_RESPONSE,
        client_mac=b"\x00" * 6,
        server_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
    )
    pkt.add_tlv(Tag.MODEL, b"GS110EMX")
    pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
    pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")  # port 1, gigabit
    pkt.add_tlv(Tag.PORT_STATUS, b"\x03\x00\x01")  # port 3, down
    # Port 9 uses the MEASURED 10G code 0x06 (real GS110EMX 10.1.5.25/.26, fw
    # 1.0.2.8); port 10 uses the prior-art 0xFF, which no real switch here has
    # emitted but which must still decode as 10G rather than as link-down.
    pkt.add_tlv(Tag.PORT_STATUS, b"\x09\x06\x01")  # port 9, 10G (measured code)
    pkt.add_tlv(Tag.PORT_STATUS, b"\x0a\xff\x00")  # port 10, 10G, flow ctl off
    # Tag 0xB000: one TLV per port, port byte + description; a bare port byte
    # means "no description set" (how real hardware answers an unnamed port).
    pkt.add_tlv(Tag.PORT_NAME, b"\x01uplink")
    pkt.add_tlv(Tag.PORT_NAME, b"\x03")
    pkt.add_tlv(Tag.PORT_NAME, b"\x09Nicole's Room")
    pkt.add_tlv(
        Tag.PORT_STATISTICS,
        b"\x01"
        + struct.pack(">Q", 1000)
        + struct.pack(">Q", 500)
        + struct.pack(">Q", 2)
        + b"\x00" * 24,
    )
    pkt.add_tlv(
        Tag.VLAN_MEMBERS,
        struct.pack(">H", 90)
        + bytes([0b1100_0000, 0b0100_0000])
        + bytes([0b0000_0000, 0b0100_0000]),  # members {1,2,10} tagged {10}
    )
    pkt.add_tlv(Tag.PORT_PVID, b"\x01\x00\x5a")  # port 1 -> vlan 90
    pkt.add_tlv(Tag.IP_ADDRESS, b"\x0a\x01\x05\x14")
    pkt.add_tlv(Tag.NETMASK, b"\xff\xff\xff\x00")
    pkt.add_tlv(Tag.GATEWAY, b"\x0a\x01\x05\x01")
    pkt.add_tlv(Tag.DHCP_MODE, b"\x00")
    pkt.add_tlv(Tag.VLAN_ENGINE, bytes([VLANEngine.ADVANCED_802_1Q]))
    pkt.add_tlv(Tag.FIRMWARE_VER_1, b"1.0.0.7")
    pkt.add_tlv(Tag.SERIAL_NUMBER, b"\x0153H6025EA0083")
    pkt.add_tlv(Tag.HOSTNAME, b"plus-sw")
    pkt.add_tlv(Tag.QOS_ENGINE, b"\x01")  # port-based
    pkt.add_tlv(Tag.PORT_MIRRORING, b"\x0a\xc0\x00\x00")  # dest=10, src={1,2}
    pkt.add_tlv(Tag.IGMP_SNOOPING, b"\x00\x01\x00\x5a")  # enabled, vlan=90
    pkt.add_tlv(Tag.BROADCAST_FILTERING, b"\x01")
    pkt.add_tlv(Tag.LOOP_DETECTION, b"\x01")
    return pkt


class FakeNsdpClient:
    """Returns one canned READ_RESPONSE built from a seeded TLV list."""

    def __init__(self) -> None:
        self.requested: list[list[Tag]] = []

    def read(self, tags):
        self.requested.append(list(tags))
        return _canned_packet()


class FakeAsyncNsdpClient:
    """Async twin of FakeNsdpClient: identical canned packet, async method."""

    def __init__(self) -> None:
        self.requested: list[list[Tag]] = []

    async def read(self, tags):
        self.requested.append(list(tags))
        return _canned_packet()


class _TagFilteringNsdpClient:
    """Mimics REAL Plus hardware: answers a read with ONLY the tags requested
    (never MODEL unsolicited), unlike the virtual face which over-served MODEL.
    Exposes the bug where a per-op read omitting MODEL yields a response
    ``parse_device`` rejects (confirmed live on a GS105PE, 2026-07-21)."""

    def __init__(self) -> None:
        self.last: list[Tag] = []

    def read(self, tags):
        self.last = list(tags)
        canned = _canned_packet()
        by_tag: dict[Tag, list[bytes]] = {}
        for tlv in canned.tlvs:
            by_tag.setdefault(tlv.tag, []).append(tlv.value)
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
        )
        for t in tags:
            for value in by_tag.get(t, []):
                pkt.add_tlv(t, value)
        return pkt


def test_per_op_reads_request_model_for_real_hardware() -> None:
    # Real Plus hardware returns ONLY the requested tags and parse_device
    # requires MODEL, so every per-op read must request MODEL -- else it fails
    # on real switches (the virtual face over-served MODEL, hiding this).
    client = _TagFilteringNsdpClient()
    reader = NsdpReader(client, get_model("gs110emx"))
    reader.get_ports()
    assert Tag.MODEL in client.last
    reader.get_stats()
    assert Tag.MODEL in client.last
    reader.get_vlans()
    assert Tag.MODEL in client.last
    reader.get_pvids()
    assert Tag.MODEL in client.last
    reader.get_mgmt_ip()
    assert Tag.MODEL in client.last


def _reader() -> NsdpReader:
    return NsdpReader(FakeNsdpClient(), get_model("gs110emx"))


def _async_reader() -> AsyncNsdpReader:
    return AsyncNsdpReader(FakeAsyncNsdpClient(), get_model("gs110emx"))


def test_get_ports_maps_speed_and_link():
    ports = {p.port: p for p in _reader().get_ports()}
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 1000
    assert ports[1].admin_enabled is True  # NSDP can't read admin; documented True
    assert ports[3].link_up is False
    assert ports[3].speed_mbps is None
    # 0x06 is the code a real GS110EMX sends for a 10G link (measured against
    # that switch's own "10G Full" page); before this it fell through
    # LinkSpeed.from_byte's unknown branch and the port read back LINK DOWN.
    assert ports[9].speed_mbps == 10000
    assert ports[9].link_up is True
    assert ports[10].speed_mbps == 10000  # 0xFF prior-art code still decodes


def test_get_ports_reports_port_descriptions_from_tag_b000():
    """NSDP DOES carry per-port names -- ``name=None`` was a missing read.

    Tag 0xB000 was found by an exhaustive tag sweep and confirmed against three
    real GS110EMX units' own Port Status pages (2026-07-30). ``get_ports`` asks
    for it alongside PORT_STATUS in the same round trip.
    """
    ports = {p.port: p for p in _reader().get_ports()}
    assert ports[1].name == "uplink"
    assert ports[9].name == "Nicole's Room"
    # A bare 1-byte TLV means "no description", which must stay None rather than
    # becoming an "" a caller cannot tell apart from a real empty description.
    assert ports[3].name is None
    # A port with no PORT_NAME TLV at all is also None, never a KeyError.
    assert ports[10].name is None


def test_get_ports_requests_the_name_tag_in_the_same_round_trip():
    client = FakeNsdpClient()
    NsdpReader(client, get_model("gs110emx")).get_ports()
    assert Tag.PORT_NAME in client.requested[0]


def test_port_status_carries_flow_control():
    """PORT_STATUS byte 2 is flow control, not a constant.

    Measured across three real GS110EMX units: 10.1.5.25/.26 answer 0x01 on all
    ten ports and their web UI says "Flow Control: Enable"; 10.1.5.27 answers
    0x00 on all ten and says "Disable".
    """
    dev = _reader().get_device()
    flow = {s.port_id: s.flow_control for s in dev.port_status}
    assert flow[1] is True
    assert flow[10] is False


def test_get_stats_maps_bytes_and_crc_errors():
    stats = {s.port: s for s in _reader().get_stats()}
    assert stats[1].rx_bytes == 1000
    assert stats[1].tx_bytes == 500
    assert stats[1].rx_errors == 2
    assert stats[1].rx_packets is None  # NSDP does not report packet counts
    assert stats[1].tx_errors is None


def test_get_vlans_and_pvids():
    vlans = _reader().get_vlans()
    v90 = next(v for v in vlans if v.vlan_id == 90)
    assert v90.member_ports == frozenset({1, 2, 10})
    assert v90.tagged_ports == frozenset({10})
    assert v90.untagged_ports == frozenset({1, 2})
    assert v90.name is None  # NSDP VLAN_MEMBERS carries no VLAN name
    assert (1, 90) in _reader().get_pvids()


def test_get_mgmt_ip_static():
    mgmt = _reader().get_mgmt_ip()
    assert mgmt.address == "10.1.5.20"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.mode is IpMode.STATIC


def test_get_device_returns_full_device():
    dev = _reader().get_device()
    assert dev.model == "GS110EMX"
    assert dev.port_count == 10
    assert dev.firmware_version == "1.0.0.7"
    assert dev.serial_number == "53H6025EA0083"
    assert dev.hostname == "plus-sw"
    assert dev.dhcp_enabled is False
    assert dev.ip == "10.1.5.20"
    assert dev.vlan_engine is VLANEngine.ADVANCED_802_1Q
    # Raw port-status speed byte is NOT pre-converted to Mbps here.
    assert dev.port_status[0].speed is LinkSpeed.GIGABIT
    assert dev.qos_engine == 1
    assert dev.port_mirroring is not None
    assert dev.port_mirroring.destination_port == 10
    assert dev.port_mirroring.source_ports == frozenset({1, 2})
    assert dev.igmp_snooping is not None
    assert dev.igmp_snooping.enabled is True
    assert dev.igmp_snooping.vlan_id == 90
    assert dev.broadcast_filtering is True
    assert dev.loop_detection is True


def test_async_get_device_matches_sync():
    async def _call():
        return await _async_reader().get_device()

    assert asyncio.run(_call()) == _reader().get_device()


@pytest.mark.parametrize("op", ["get_macs", "get_lldp", "get_sensors", "get_poe"])
def test_unsupported_ops_raise(op):
    with pytest.raises(UnsupportedCapabilityError):
        getattr(_reader(), op)()


@pytest.mark.parametrize("op", ["get_macs", "get_lldp", "get_sensors", "get_poe"])
def test_unsupported_read_refusals_carry_the_measurement(op):
    """These four refusals must cite the sweep, not merely assert a limit.

    CLAUDE.md principle 4: a limitation may only be recorded with captured
    device output as proof, naming the firmware it applies to. Each message
    therefore names the host and firmware version whose exhaustive tag sweep
    established that no such tag exists.
    """
    with pytest.raises(UnsupportedCapabilityError) as exc:
        getattr(_reader(), op)()
    message = str(exc.value)
    assert "GS110EMX" in message
    assert "10.1.5.25" in message
    assert "1.0.2.8" in message
    assert "tag sweep" in message


def test_reader_rejects_non_nsdp_model():
    with pytest.raises(UnsupportedCapabilityError):
        NsdpReader(FakeNsdpClient(), get_model("gsm7252ps"))  # SNMP-only


def test_async_reader_rejects_non_nsdp_model():
    with pytest.raises(UnsupportedCapabilityError):
        AsyncNsdpReader(FakeAsyncNsdpClient(), get_model("gsm7252ps"))  # SNMP-only


@pytest.mark.parametrize("op", ["get_macs", "get_lldp", "get_sensors", "get_poe"])
def test_async_unsupported_ops_raise(op):
    async def _call():
        await getattr(_async_reader(), op)()

    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(_call())


def test_async_reader_matches_sync_reader_for_every_method():
    # Structural-parity pin: the same canned packet fed through NsdpReader and
    # AsyncNsdpReader must yield identical model objects for every supported
    # read method -- the only difference is await.
    sync_reader = _reader()
    async_reader = _async_reader()

    async def _collect_async():
        return {
            "ports": await async_reader.get_ports(),
            "stats": await async_reader.get_stats(),
            "vlans": await async_reader.get_vlans(),
            "pvids": await async_reader.get_pvids(),
            "mgmt_ip": await async_reader.get_mgmt_ip(),
        }

    async_results = asyncio.run(_collect_async())
    sync_results = {
        "ports": sync_reader.get_ports(),
        "stats": sync_reader.get_stats(),
        "vlans": sync_reader.get_vlans(),
        "pvids": sync_reader.get_pvids(),
        "mgmt_ip": sync_reader.get_mgmt_ip(),
    }
    assert async_results == sync_results
    # Sanity: not vacuously equal -- some real data actually came through.
    assert sync_results["ports"]
    assert sync_results["mgmt_ip"].mode is IpMode.STATIC
