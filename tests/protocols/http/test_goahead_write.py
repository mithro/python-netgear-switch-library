# tests/protocols/http/test_goahead_write.py
"""The GoAhead ``wcd`` write bodies must match what the switch's own pages send.

Each expectation below is transcribed from JavaScript captured verbatim from
the live GS728TPP (10.2.5.10, firmware 6.0.1.30) -- the page builds a ``post``
object and the framework serialises it, so the page IS the specification.
"""

from __future__ import annotations

from netgear_switch.models import VlanMode
from netgear_switch.protocols.http import goahead


def test_write_body_envelope() -> None:
    body = goahead.write_body("SomeList", "set", [{"Entry": {"a": "1"}}])
    assert body == (
        "<?xml version='1.0' encoding='utf-8'?>"
        '<DeviceConfiguration><SomeList action="set">'
        "<Entry><a>1</a></Entry>"
        "</SomeList></DeviceConfiguration>"
    )


def test_write_body_nests_and_repeats() -> None:
    body = goahead.write_body(
        "L",
        "set",
        [{"P": {"id": "5", "Kids": [{"K": {"n": "a"}}, {"K": {"n": "b"}}]}}],
    )
    assert "<P><id>5</id><Kids><K><n>a</n></K><K><n>b</n></K></Kids></P>" in body


def test_write_body_escapes_text() -> None:
    body = goahead.write_body("L", "set", [{"E": {"name": "a&b<c>\"d'"}}])
    assert "<name>a&amp;b&lt;c&gt;&quot;d&apos;</name>" in body


def test_membership_tagged_matches_the_pages_own_post_object() -> None:
    """post.VLANMembershipList['set'] = [{VLAN:{VLANID, MembershipList:[...]}}]"""
    body = goahead.vlan_membership_body(4001, "g17", VlanMode.TAGGED)
    assert '<VLANMembershipList action="set">' in body
    assert (
        "<VLAN><VLANID>4001</VLANID><MembershipList><VLANMember>"
        "<interfaceName>g17</interfaceName><interfaceType>1</interfaceType>"
        "<membershipType>2</membershipType><taggingMode>2</taggingMode>"
        "</VLANMember></MembershipList></VLAN>"
    ) in body


def test_membership_untagged_only_changes_the_tagging_mode() -> None:
    body = goahead.vlan_membership_body(4001, "g17", VlanMode.UNTAGGED)
    assert "<taggingMode>1</taggingMode>" in body
    assert '<VLANMembershipList action="set">' in body


def test_membership_excluded_is_a_delete_action_not_a_tagging_mode() -> None:
    """The page routes "Remove" to post.VLANMembershipList['delete'].

    Its delete entries carry ONLY interfaceName/interfaceType -- no
    membershipType, no taggingMode. Sending taggingMode 0 as a ``set`` instead
    would be asking the firmware for a mode it does not have.
    """
    body = goahead.vlan_membership_body(4001, "g17", VlanMode.EXCLUDED)
    assert '<VLANMembershipList action="delete">' in body
    assert (
        "<VLANMember><interfaceName>g17</interfaceName>"
        "<interfaceType>1</interfaceType></VLANMember>"
    ) in body
    assert "membershipType" not in body
    assert "taggingMode" not in body


def test_poe_admin_body() -> None:
    """adminEnable 1 = enabled, 2 = disabled -- the codes the reader decodes."""
    on = goahead.poe_admin_body("g17", True)
    off = goahead.poe_admin_body("g17", False)
    assert '<PoEPSEInterfaceList action="set">' in on
    assert (
        "<Interface><interfaceName>g17</interfaceName>"
        "<interfaceType>1</interfaceType><adminEnable>1</adminEnable></Interface>"
    ) in on
    assert "<adminEnable>2</adminEnable>" in off


def test_vlan_create_uses_set_not_add() -> None:
    """There is no "add" verb: js/home.js defines only set/delete/restore, and
    the framework stamps a NEW row with ACTION_SET like any other edit."""
    body = goahead.vlan_create_body(4001, "ngsw-tmp")
    assert '<VLANList action="set">' in body
    assert "add" not in body
    assert (
        "<VLAN><VLANID>4001</VLANID><VLANName>ngsw-tmp</VLANName></VLAN>"
    ) in body


def test_vlan_delete_body_matches_the_pages_literal_envelope() -> None:
    """VlanConfig.Reset posts this shape as a literal string, so it is exact."""
    body = goahead.vlan_delete_body(4001)
    assert '<VLANList action="delete">' in body
    assert "<VLAN><VLANID>4001</VLANID></VLAN>" in body
    # Deleting ONE VLAN must not carry the page's "restore everything" section.
    assert "VLANInterfaceList" not in body
    assert "restoreAll" not in body


def test_pvid_body() -> None:
    body = goahead.pvid_body("g17", 4001)
    assert '<VLANInterfaceList action="set">' in body
    assert (
        "<Interface><interfaceName>g17</interfaceName>"
        "<interfaceType>1</interfaceType><PVID>4001</PVID></Interface>"
    ) in body


def test_port_config_body_sends_admin_state_codes() -> None:
    """The ports page sends adminState 1 (up) / 2 (down)."""
    up = goahead.port_config_body("g17", 17, admin_enabled=True)
    down = goahead.port_config_body("g17", 17, admin_enabled=False)
    assert '<Standard802_3List action="set">' in up
    assert "<adminState>1</adminState>" in up
    assert "<adminState>2</adminState>" in down
    assert "<interfaceName>g17</interfaceName><interfaceType>1</interfaceType>" in up


def test_port_config_body_omits_fields_it_was_not_asked_to_change() -> None:
    """The page sets untouched fields to ``undefined`` and the serialiser drops
    them; sending an empty element instead would rewrite real config."""
    body = goahead.port_config_body("g17", 17)
    assert "adminState" not in body
    assert "speedAdmin" not in body
    assert "interfaceDescription" not in body
