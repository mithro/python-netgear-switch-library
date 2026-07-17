from __future__ import annotations

from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import encode_port_bitmap
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_gsm7252ps


def test_apply_write_poe_admin_off_sets_detect_and_link_down():
    st = seed_gsm7252ps()
    assert st.poe[1].admin is True
    assert st.poe[1].detect == 3
    st.apply_write(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 2)  # admin disable
    assert st.poe[1].admin is False
    assert st.poe[1].detect == 1        # unused/disabled
    assert st.ports[1].link is False    # coherence: link drops
    st.apply_write(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 1)  # admin enable
    assert st.poe[1].admin is True
    assert st.poe[1].detect == 3        # delivering


def test_apply_write_ifadmin_and_pvid():
    st = seed_gsm7252ps()
    st.apply_write(f"{oids.IF_ADMIN_STATUS}.3", 2)
    assert st.ports[3].admin is False
    st.apply_write(f"{oids.DOT1Q_PVID}.10", 90)
    assert st.pvids[10] == 90


def test_apply_write_vlan_membership_rmw_and_rowstatus():
    st = seed_gsm7252ps()
    new_egress = encode_port_bitmap({1, 2, 10, 25})  # add port 25 to vlan 90
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90", new_egress)
    member_bitmap = encode_port_bitmap(st.vlans[90].member)
    assert decode_port_bitmap(member_bitmap) == frozenset({1, 2, 10, 25})
    # create VLAN 200 via RowStatus + name.
    row_status_oid = f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.200"
    st.apply_write(row_status_oid, oids.ROW_STATUS_CREATE_AND_GO)
    st.apply_write(f"{oids.DOT1Q_VLAN_STATIC_NAME}.200", b"guests")
    assert st.vlans[200].name == "guests"
    # destroy it.
    st.apply_write(row_status_oid, oids.ROW_STATUS_DESTROY)
    assert 200 not in st.vlans


def test_apply_write_mgmt_ip_updates_read_projection():
    st = seed_gsm7252ps()
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    st.apply_write(vo.mgmt_write_addr_unverified, "10.9.9.9")
    assert st.mgmt.address == "10.9.9.9"
    # read projection now advertises the new address in ipAddrTable.
    assert any(k.startswith(f"{oids.IP_ADENT_ADDR}.10.9.9.9") for k in st.oid_map())


def test_apply_write_dhcp_mode_updates_read_projection():
    st = seed_gsm7252ps()
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    assert st.mgmt.mode == "static"
    assert st.oid_map()[f"{vo.dhcp_mode_unverified}.0"] == ("INTEGER", "2")

    st.apply_write(f"{vo.dhcp_mode_unverified}.0", 1)  # 1 = dhcp
    assert st.mgmt.mode == "dhcp"
    assert st.oid_map()[f"{vo.dhcp_mode_unverified}.0"] == ("INTEGER", "1")

    st.apply_write(f"{vo.dhcp_mode_unverified}.0", 2)  # 2 = static
    assert st.mgmt.mode == "static"
    assert st.oid_map()[f"{vo.dhcp_mode_unverified}.0"] == ("INTEGER", "2")


def test_apply_write_unhandled_oid_is_a_silent_no_op():
    """Documented contract: an OID that matches no dispatch branch (or a
    known column whose instance doesn't exist) is a no-op at the state
    layer -- a verify-after-write (GET after SET) is what must catch it. The
    SNMP face adds its own stricter gate (``is_writable_oid``) in front of
    this so a genuinely unknown OID never even reaches here in practice; see
    ``test_write_variables_rejects_unknown_oid`` below."""
    st = seed_gsm7252ps()
    before = dict(st.oid_map())
    st.apply_write("1.2.3.4.5", 1)  # nothing matches
    st.apply_write(f"{oids.IF_ADMIN_STATUS}.9999", 2)  # known column, absent port
    assert st.oid_map() == before


def test_is_writable_oid_recognizes_known_columns_and_scalars():
    st = seed_gsm7252ps()
    vo = oids.vendor_oids(get_model("gsm7252ps"))

    assert st.is_writable_oid(f"{oids.IF_ADMIN_STATUS}.3")
    assert st.is_writable_oid(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1")
    assert st.is_writable_oid(f"{oids.DOT1Q_PVID}.10")
    assert st.is_writable_oid(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90")
    assert st.is_writable_oid(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.90")
    # A not-yet-existing VLAN row is still a recognized writable column
    # (RowStatus createAndGo must be allowed through).
    assert st.is_writable_oid(f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.300")
    assert st.is_writable_oid(f"{oids.DOT1Q_VLAN_STATIC_NAME}.300")
    assert st.is_writable_oid(vo.mgmt_write_addr_unverified)
    assert st.is_writable_oid(vo.mgmt_write_netmask_unverified)
    assert st.is_writable_oid(vo.mgmt_write_gateway_unverified)
    assert st.is_writable_oid(f"{vo.dhcp_mode_unverified}.0")

    assert not st.is_writable_oid("1.2.3.4.5")
    assert not st.is_writable_oid(f"{oids.IF_OPER_STATUS}.1")  # read-only counter
