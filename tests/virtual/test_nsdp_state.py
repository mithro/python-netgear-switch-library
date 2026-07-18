from __future__ import annotations

import struct

from netgear_switch.protocols.nsdp.parsers import parse_device
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.protocols.nsdp.types import LinkSpeed
from netgear_switch.virtual.seed import seed_gs110emx


def _device_from(tlvs):
    pkt = NSDPPacket(
        op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\x00" * 6
    )
    pkt.tlvs = list(tlvs)
    return parse_device(pkt)


def test_seed_has_plus_shape():
    st = seed_gs110emx()
    assert st.model_key == "gs110emx"
    assert st.serial
    assert st.firmware
    assert len(st.ports) == 10
    assert st.pvids[1] == 90


def test_nsdp_tlvs_projects_ports_and_identity():
    st = seed_gs110emx()
    tlvs = st.nsdp_tlvs({Tag.PORT_STATUS})
    tags = [t.tag for t in tlvs]
    assert Tag.MODEL in tags  # identity always present
    assert Tag.PORT_COUNT in tags
    dev = _device_from(tlvs)
    ports = {p.port_id: p for p in dev.port_status}
    assert ports[1].speed is LinkSpeed.GIGABIT
    assert ports[3].speed is LinkSpeed.DOWN     # link-down projects DOWN
    assert ports[9].speed is LinkSpeed.TEN_GIGABIT


def test_nsdp_tlvs_projects_vlans_and_pvids_and_mgmt():
    st = seed_gs110emx()
    dev = _device_from(st.nsdp_tlvs({Tag.VLAN_MEMBERS, Tag.PORT_PVID,
                                     Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY,
                                     Tag.DHCP_MODE}))
    v90 = next(v for v in dev.vlan_members if v.vlan_id == 90)
    assert v90.member_ports == frozenset({1, 2, 10})
    assert v90.untagged_ports == frozenset({1, 2})
    assert dev.ip == "10.1.5.20"
    assert dev.dhcp_enabled is False
    assert (1, 90) in {(p.port_id, p.vlan_id) for p in dev.port_pvids}


def test_apply_nsdp_write_pvid_and_membership_and_mgmt():
    st = seed_gs110emx()
    st.apply_nsdp_write(Tag.PORT_PVID, b"\x05" + struct.pack(">H", 90))
    assert st.pvids[5] == 90
    # move port 10 to untagged on vlan 90 (members {1,2,10}, untagged {1,2,10})
    from netgear_switch.protocols.nsdp.write import vlan_members_tlv
    tlv = vlan_members_tlv(90, members={1, 2, 10}, tagged=set(), port_count=10)
    st.apply_nsdp_write(Tag.VLAN_MEMBERS, tlv.value)
    assert st.vlans[90].untagged == {1, 2, 10}
    import socket
    st.apply_nsdp_write(Tag.IP_ADDRESS, socket.inet_aton("10.9.9.9"))
    assert st.mgmt.address == "10.9.9.9"
