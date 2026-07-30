from __future__ import annotations

import struct

from netgear_switch.protocols.nsdp import write
from netgear_switch.protocols.nsdp.auth import encode_password_v1
from netgear_switch.protocols.nsdp.parsers import bitmap_to_ports, parse_port_pvid
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

_MAC = b"\x00\x00\x00\x00\x00\x01"


def test_build_read_request_has_empty_tlvs_and_read_op():
    pkt = write.build_read_request(_MAC, b"\xaa" * 6, 5, [Tag.MODEL, Tag.PORT_STATUS])
    assert pkt.op == Op.READ_REQUEST
    assert [t.tag for t in pkt.tlvs] == [Tag.MODEL, Tag.PORT_STATUS]
    assert all(t.value == b"" for t in pkt.tlvs)  # read = length-0 TLVs


def test_build_write_request_prepends_v1_password_tlv():
    body = [write.pvid_tlv(1, 90)]
    pkt = write.build_write_request(_MAC, b"\xaa" * 6, 9, "admin", body)
    assert pkt.op == Op.WRITE_REQUEST
    assert pkt.tlvs[0].tag == Tag.PASSWORD
    assert pkt.tlvs[0].value == encode_password_v1("admin")
    # The value TLVs follow the auth TLV, unchanged.
    assert pkt.tlvs[1].tag == Tag.PORT_PVID
    # And it round-trips on the wire.
    back = NSDPPacket.decode(pkt.encode())
    assert back.tlvs[0].tag == Tag.PASSWORD


def test_pvid_tlv_encoding():
    tlv = write.pvid_tlv(5, 100)
    assert tlv.tag == Tag.PORT_PVID
    assert tlv.value == b"\x05\x00\x64"
    assert parse_port_pvid(tlv.value).vlan_id == 100


def test_vlan_members_tlv_encoding_10_port():
    tlv = write.vlan_members_tlv(90, members={1, 2, 10}, tagged={10}, port_count=10)
    assert tlv.tag == Tag.VLAN_MEMBERS
    vlan_id = struct.unpack_from(">H", tlv.value, 0)[0]
    assert vlan_id == 90
    member_bitmap = tlv.value[2:4]  # ceil(10/8) = 2 bytes
    tagged_bitmap = tlv.value[4:6]
    assert bitmap_to_ports(member_bitmap) == frozenset({1, 2, 10})
    assert bitmap_to_ports(tagged_bitmap) == frozenset({10})


def test_ipv4_and_dhcp_and_reboot_tlvs():
    assert write.ipv4_tlv(Tag.IP_ADDRESS, "10.1.5.20").value == b"\x0a\x01\x05\x14"
    assert write.dhcp_tlv(enabled=True).value == b"\x01"
    assert write.dhcp_tlv(enabled=False).value == b"\x00"
    assert write.reboot_tlv().tag == Tag.REBOOT
    assert write.reboot_tlv().value == b""


def test_result_constants():
    assert write.RESULT_SUCCESS == 0x0000
    assert write.RESULT_BAD_PASSWORD == 0x0700
