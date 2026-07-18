from __future__ import annotations

import socket
import struct

import pytest

from netgear_switch.errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.models import VlanMode
from netgear_switch.nsdp_write import NsdpWriter
from netgear_switch.protocols.nsdp.parsers import ports_to_bitmap
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.registry import get_model


class FakeNsdpWriteClient:
    """A tiny stateful NSDP mock: applies writes so verify-after-write passes.

    ``apply=False`` makes writes a no-op (device ignores them) so the writer's
    verify step is forced to raise WriteVerificationError.
    """

    def __init__(self, *, apply: bool = True) -> None:
        self.pvids: dict[int, int] = {1: 1, 2: 1}
        self.vlans: dict[int, tuple[set[int], set[int]]] = {90: ({1, 2}, set())}
        self.mgmt = {"ip": "10.1.5.20", "mask": "255.255.255.0",
                     "gw": "10.1.5.1", "dhcp": False}
        self.writes: list[list[Tag]] = []
        self._apply = apply

    def read(self, tags):
        pkt = NSDPPacket(op=Op.READ_RESPONSE, client_mac=b"\x00" * 6,
                         server_mac=b"\xaa" * 6)
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
        for port, vlan in self.pvids.items():
            pkt.add_tlv(Tag.PORT_PVID, bytes([port]) + struct.pack(">H", vlan))
        for vlan, (members, tagged) in self.vlans.items():
            pkt.add_tlv(
                Tag.VLAN_MEMBERS,
                struct.pack(">H", vlan)
                + ports_to_bitmap(members, 2) + ports_to_bitmap(tagged, 2),
            )
        pkt.add_tlv(Tag.IP_ADDRESS, socket.inet_aton(self.mgmt["ip"]))
        pkt.add_tlv(Tag.NETMASK, socket.inet_aton(self.mgmt["mask"]))
        pkt.add_tlv(Tag.GATEWAY, socket.inet_aton(self.mgmt["gw"]))
        pkt.add_tlv(Tag.DHCP_MODE, b"\x01" if self.mgmt["dhcp"] else b"\x00")
        return pkt

    def write(self, tlvs, *, password):
        self.writes.append([t.tag for t in tlvs])
        if self._apply:
            for t in tlvs:
                self._apply_tlv(t)
        return NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=b"\x00" * 6, result=0)

    def _apply_tlv(self, t):
        if t.tag == Tag.PORT_PVID:
            self.pvids[t.value[0]] = struct.unpack_from(">H", t.value, 1)[0]
        elif t.tag == Tag.VLAN_MEMBERS:
            from netgear_switch.protocols.nsdp.parsers import parse_vlan_members
            m = parse_vlan_members(t.value, 10)
            self.vlans[m.vlan_id] = (set(m.member_ports), set(m.tagged_ports))
        elif t.tag == Tag.IP_ADDRESS:
            self.mgmt["ip"] = socket.inet_ntoa(t.value)
        elif t.tag == Tag.NETMASK:
            self.mgmt["mask"] = socket.inet_ntoa(t.value)
        elif t.tag == Tag.GATEWAY:
            self.mgmt["gw"] = socket.inet_ntoa(t.value)


def _writer(client=None, **kw) -> NsdpWriter:
    return NsdpWriter(client or FakeNsdpWriteClient(), get_model("gs110emx"),
                      password="admin", **kw)


def test_set_pvid_writes_and_verifies():
    client = FakeNsdpWriteClient()
    _writer(client).set_pvid(1, 90)
    assert client.pvids[1] == 90
    assert [Tag.PORT_PVID] in client.writes


def test_set_pvid_verification_failure_raises():
    client = FakeNsdpWriteClient(apply=False)  # device ignores the write
    with pytest.raises(WriteVerificationError):
        _writer(client).set_pvid(1, 90)


def test_set_vlan_membership_rmw_tagged():
    client = FakeNsdpWriteClient()
    _writer(client).set_vlan_membership(90, 10, VlanMode.TAGGED)
    members, tagged = client.vlans[90]
    assert 10 in members
    assert 10 in tagged
    assert {1, 2} <= members   # existing members preserved (read-modify-write)


def test_set_vlan_membership_excluded_removes_port():
    client = FakeNsdpWriteClient()
    _writer(client).set_vlan_membership(90, 1, VlanMode.EXCLUDED)
    members, _ = client.vlans[90]
    assert 1 not in members
    assert 2 in members


def test_protected_port_blocks_pvid_without_force():
    client = FakeNsdpWriteClient()
    w = _writer(client, protected_ports=frozenset({1}))
    with pytest.raises(ProtectedPortError):
        w.set_pvid(1, 90)
    assert client.writes == []            # nothing sent
    w.set_pvid(1, 90, force=True)         # force bypasses
    assert client.pvids[1] == 90


def test_set_mgmt_ip_requires_force_and_verifies_all_three():
    client = FakeNsdpWriteClient()
    w = _writer(client)
    with pytest.raises(ProtectedPortError):
        w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
    w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    assert client.mgmt["ip"] == "10.9.9.9"
    assert client.mgmt["gw"] == "10.9.9.1"


@pytest.mark.parametrize(
    ("op", "args"),
    [
        ("set_poe", (1, True)),
        ("set_port_enabled", (1, False)),
        ("cycle_poe", (1,)),
        ("clear_poe_fault", (1,)),
        ("create_vlan", (200, "guests")),
        ("delete_vlan", (200,)),
    ],
)
def test_unsupported_writes_raise(op, args):
    with pytest.raises(UnsupportedCapabilityError):
        getattr(_writer(), op)(*args)
