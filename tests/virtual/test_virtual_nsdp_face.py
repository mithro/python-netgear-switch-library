from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from netgear_switch.protocols.nsdp import write
from netgear_switch.protocols.nsdp.client import NsdpError
from netgear_switch.protocols.nsdp.parsers import parse_device
from netgear_switch.protocols.nsdp.protocol import Tag
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
from netgear_switch.virtual.server import VirtualSwitch

if TYPE_CHECKING:
    from collections.abc import Iterator

_MAC = b"\x00\x00\x00\x00\x00\x01"


@pytest.fixture
def virtual_gs110emx() -> Iterator[VirtualSwitch]:
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


def _client(sw: VirtualSwitch) -> UdpNsdpClient:
    return UdpNsdpClient(sw.host, client_port=0, server_port=sw.port,
                         client_mac=_MAC, timeout=2.0)


def test_face_read_returns_seed_ports(virtual_gs110emx: VirtualSwitch) -> None:
    tags = [Tag.MODEL, Tag.PORT_COUNT, Tag.PORT_STATUS]
    dev = parse_device(_client(virtual_gs110emx).read(tags))
    assert dev.model == "GS110EMX"
    assert {p.port_id for p in dev.port_status} == set(range(1, 11))


def test_face_authenticated_write_is_read_back(virtual_gs110emx: VirtualSwitch) -> None:
    client = _client(virtual_gs110emx)
    client.write([write.pvid_tlv(5, 90)], password=virtual_gs110emx.nsdp_password)
    # MODEL must be requested explicitly: the face (like real hardware) answers
    # with only the requested tags, and parse_device requires a MODEL tag.
    dev = parse_device(client.read([Tag.MODEL, Tag.PORT_PVID]))
    assert (5, 90) in {(p.port_id, p.vlan_id) for p in dev.port_pvids}


def test_face_wrong_password_raises_bad_password(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    client = _client(virtual_gs110emx)
    with pytest.raises(NsdpError, match="bad password"):
        client.write([write.pvid_tlv(5, 90)], password="wrong-password")
