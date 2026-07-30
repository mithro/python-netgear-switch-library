from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from netgear_switch.protocols.nsdp import write
from netgear_switch.protocols.nsdp.client import NsdpError
from netgear_switch.protocols.nsdp.parsers import parse_device
from netgear_switch.protocols.nsdp.protocol import Tag
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
from netgear_switch.virtual.seed import seed_gs110emx_fw1028
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


@pytest.fixture
def virtual_gs110emx_fw1028() -> Iterator[VirtualSwitch]:
    """The GS110EMX as it really behaves on firmware 1.0.2.8 (10.1.5.25)."""
    sw = VirtualSwitch(model="gs110emx")
    sw.state = seed_gs110emx_fw1028()
    sw.nsdp_password = sw.state.nsdp_password
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


def test_face_reports_the_real_10g_speed_byte(
    virtual_gs110emx_fw1028: VirtualSwitch,
) -> None:
    """Ports 9/10 must go out as speed byte 0x06, not the prior-art 0xFF.

    MEASURED on 10.1.5.25 / .26 (fw 1.0.2.8, 2026-07-30): PORT_STATUS answers
    ``09 06 01`` / ``0a 06 01`` while those switches' own Port Status page shows
    both uplinks "Up ... 10G Full". This asserts the RAW TLV bytes on purpose --
    a round-trip through LinkSpeed would pass even if encoder and decoder shared
    the same wrong constant, which is precisely how the 0xFF guess survived.
    """
    resp = _client(virtual_gs110emx_fw1028).read([Tag.MODEL, Tag.PORT_STATUS])
    raw = {t.value[0]: t.value for t in resp.tlvs if t.tag == Tag.PORT_STATUS}
    assert raw[9] == b"\x09\x06\x01"
    assert raw[10] == b"\x0a\x06\x01"
    assert raw[8] == b"\x08\x05\x01"  # 1G port, for contrast
    assert raw[1] == b"\x01\x00\x01"  # link down


def test_face_serves_port_descriptions_on_tag_b000(
    virtual_gs110emx_fw1028: VirtualSwitch,
) -> None:
    """Tag 0xB000 carries the per-port description: port byte + the string.

    MEASURED on all three real GS110EMX units; 10.1.5.25 answers ``01``..``05``
    for its undescribed ports, then ``06`` + "Nicole's Room" and ``08`` +
    "TV Room" -- one TLV per port, ALWAYS, even for an undescribed one.
    """
    resp = _client(virtual_gs110emx_fw1028).read([Tag.MODEL, Tag.PORT_NAME])
    raw = [t.value for t in resp.tlvs if t.tag == Tag.PORT_NAME]
    assert len(raw) == 10  # every port answers, described or not
    assert raw[5] == b"\x06Nicole's Room"
    assert raw[7] == b"\x08TV Room"
    assert raw[0] == b"\x01"  # undescribed port: bare port byte, no padding


def test_face_refuses_every_nsdp_write_on_firmware_1_0_2_8(
    virtual_gs110emx_fw1028: VirtualSwitch,
) -> None:
    """This firmware rejects v1 auth outright -- even with the RIGHT password.

    MEASURED on 10.1.5.25 (fw 1.0.2.8, 2026-07-30): an empty WRITE_REQUEST
    carrying the v1 repeating-XOR PASSWORD TLV comes back error=13 (error=14 on
    the retry) with the header's error-attribute set to 0x000A/ATTR_PASSWORD,
    and a plaintext password does the same. The error must NOT read as "bad
    password": an operator who believes that rotates a credential that was never
    wrong. It has to say the auth VERSION is the problem.
    """
    client = _client(virtual_gs110emx_fw1028)
    with pytest.raises(NsdpError) as exc:
        client.write(
            [write.pvid_tlv(5, 90)], password=virtual_gs110emx_fw1028.nsdp_password
        )
    message = str(exc.value)
    assert "PASSWORD" in message  # names the blamed attribute (header bytes 4-5)
    assert "v2" in message
    assert "bad password" not in message


def test_face_read_of_a_sole_unserved_tag_is_an_error_not_an_empty_success(
    virtual_gs110emx_fw1028: VirtualSwitch,
) -> None:
    """Asking for one tag the model does not serve -> error 3 naming that tag.

    MEASURED on 10.1.5.25: LOOP_DETECTION (0x9000) is absent from this
    firmware's tag inventory and a read of it alone answers error code 3 with
    the error attribute set to 0x9000. Mixed into a larger read it is merely
    omitted -- also measured, and asserted below -- which is why the whole
    ``_FULL_DEVICE_TAGS`` request still succeeds on this model.
    """
    client = _client(virtual_gs110emx_fw1028)
    sole = client.read([Tag.LOOP_DETECTION])
    assert sole.error_code == 3
    assert sole.error_attr == int(Tag.LOOP_DETECTION)

    mixed = client.read([Tag.MODEL, Tag.LOOP_DETECTION])
    assert mixed.error_code == 0
    assert [int(t.tag) for t in mixed.tlvs] == [int(Tag.MODEL)]


def test_face_applies_vlan_destroy_and_resets_orphaned_pvids(
    virtual_gs110emx: VirtualSwitch,
) -> None:
    """Tag 0x2C00 removes the VLAN; ports whose PVID named it fall back to 1.

    The tag itself is grounded in ngadmin's ``ngadmin_VLANDestroy``; the PVID
    fallback is what a switch must do, since a PVID cannot name a VLAN that no
    longer exists.
    """
    client = _client(virtual_gs110emx)
    client.write([write.pvid_tlv(3, 90)], password=virtual_gs110emx.nsdp_password)
    assert virtual_gs110emx.state.pvids[3] == 90

    client.write([write.vlan_destroy_tlv(90)], password=virtual_gs110emx.nsdp_password)
    dev = parse_device(client.read([Tag.MODEL, Tag.PORT_COUNT, Tag.VLAN_MEMBERS]))
    assert 90 not in {v.vlan_id for v in dev.vlan_members}
    assert virtual_gs110emx.state.pvids[3] == 1
