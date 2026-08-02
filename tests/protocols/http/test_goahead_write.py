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
