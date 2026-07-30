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
    return UdpNsdpClient(
        sw.host, client_port=0, server_port=sw.port, client_mac=_MAC, timeout=2.0
    )


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


def test_face_advertises_v2_and_client_auto_detects(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    # The gs110emx mock advertises AUTH_V2_ENCPASS 0x10; an "auto" client must
    # resolve to v2 and send an AUTH_V2_PASSWORD (not a v1 PASSWORD) token.
    client = _client(virtual_gs110emx)
    enc = client.read([Tag.AUTH_V2_ENCPASS])
    assert enc.tlvs[0].tag == Tag.AUTH_V2_ENCPASS
    assert enc.tlvs[0].value == b"\x00\x00\x00\x10"
    client.write([write.pvid_tlv(6, 41)], password=virtual_gs110emx.nsdp_password)
    assert client._auth_scheme == "v2"


def test_face_salt_rotates_every_read(virtual_gs110emx: VirtualSwitch) -> None:
    client = _client(virtual_gs110emx)
    salts = {
        client.read([Tag.AUTH_V2_SALT]).tlvs[0].value for _ in range(5)
    }
    assert len(salts) > 1  # a fresh 4-byte challenge each read
    assert all(len(s) == 4 for s in salts)


def test_face_reading_write_only_auth_tag_is_refused(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    # AUTH_V2_PASSWORD (0x001A) is write-only: a real GS110EMX answers error 3.
    resp = _client(virtual_gs110emx).read([Tag.AUTH_V2_PASSWORD])
    assert resp.result == 0x0300  # error byte 3 (read-only)
    assert resp.errattr == int(Tag.AUTH_V2_PASSWORD)
    assert resp.tlvs == []


def test_face_v2_repeated_failures_escalate_then_lock(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    # Faithful to the observed GS110EMX lockout: a few wrong tokens come back
    # "bad password" (error 13), then the switch escalates to a lockout (14) and
    # finally goes silent. A short client timeout keeps the silence test fast.
    client = UdpNsdpClient(
        virtual_gs110emx.host,
        client_port=0,
        server_port=virtual_gs110emx.port,
        client_mac=_MAC,
        timeout=0.4,
    )
    saw_bad = saw_locked = saw_silent = False
    for _ in range(10):
        try:
            client.write([write.pvid_tlv(5, 90)], password="wrong")
        except NsdpError as exc:
            msg = str(exc)
            if "bad password" in msg:
                saw_bad = True
            elif "locked out" in msg:
                saw_locked = True
            elif "timed out" in msg:
                saw_silent = True
                break
    assert saw_bad
    assert saw_locked
    assert saw_silent


def test_face_lockout_counter_resets_after_success(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    client = _client(virtual_gs110emx)
    for _ in range(3):
        with pytest.raises(NsdpError, match="bad password"):
            client.write([write.pvid_tlv(5, 90)], password="wrong")
    # A correct write still succeeds (counter had not yet reached lockout) and
    # clears the failure count.
    client.write([write.pvid_tlv(5, 90)], password=virtual_gs110emx.nsdp_password)
    assert virtual_gs110emx.state.nsdp_auth_failures == 0


def test_gs105pe_face_uses_v1_and_round_trips() -> None:
    # A v1 model (gs105pe) still authenticates over the legacy XOR PASSWORD path
    # via the same "auto"-detecting client -- ENCPASS advertises 1, not 0x10.
    sw = VirtualSwitch(model="gs105pe")
    sw.start()
    try:
        client = UdpNsdpClient(
            sw.host, client_port=0, server_port=sw.port, client_mac=_MAC, timeout=2.0
        )
        enc = client.read([Tag.AUTH_V2_ENCPASS])
        assert enc.tlvs[0].value == b"\x00\x00\x00\x01"
        client.write([write.pvid_tlv(2, 90)], password=sw.nsdp_password)
        assert client._auth_scheme == "v1"
        dev = parse_device(client.read([Tag.MODEL, Tag.PORT_PVID]))
        assert (2, 90) in {(p.port_id, p.vlan_id) for p in dev.port_pvids}
    finally:
        sw.stop()
