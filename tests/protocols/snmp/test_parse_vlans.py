# tests/protocols/snmp/test_parse_vlans.py
from __future__ import annotations

import re

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_decode_port_bitmap_bit7_is_port1():
    # 0b10100000 -> ports 1 and 3. Bitmaps arrive as bytes over the wire (both
    # transports normalize non-printable OCTET STRINGs to bytes).
    assert parse.decode_port_bitmap(bytes([0b10100000])) == frozenset({1, 3})
    # second byte, bit7 -> port 9
    assert parse.decode_port_bitmap(bytes([0, 0b10000000])) == frozenset({9})
    assert parse.decode_port_bitmap(b"") == frozenset()
    assert parse.decode_port_bitmap("") == frozenset()


def test_decode_port_bitmap_accepts_printable_str():
    # If a bitmap ever arrives as a printable str, it's latin-1 encoded first.
    assert parse.decode_port_bitmap(chr(0b11000000)) == frozenset({1, 2})


def test_decode_port_bitmap_raises_on_non_latin1_str():
    with pytest.raises(SnmpError):
        parse.decode_port_bitmap(chr(300))


def test_parse_vlans_joins_names_egress_untagged():
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    # egress ports 1,2 ; untagged port 2  -> tagged {1}, untagged {2}
    egress = [
        SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.5", bytes([0b11000000]), "OCTETSTR")
    ]
    untag = [
        SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.4.5", bytes([0b01000000]), "OCTETSTR")
    ]
    vlans = parse.parse_vlans(names, egress, untag)
    assert len(vlans) == 1
    v = vlans[0]
    assert v.vlan_id == 5
    assert v.name == "net"
    assert v.member_ports == frozenset({1, 2})
    assert v.untagged_ports == frozenset({2})
    assert v.tagged_ports == frozenset({1})


def test_parse_vlans_absent_bitmap_yields_no_ports():
    # A VLAN with a name but no egress/untagged rows at all (absent, not
    # malformed) -> empty port sets, not an error.
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.10", "empty", "OCTETSTR")]
    vlans = parse.parse_vlans(names, [], [])
    assert len(vlans) == 1
    assert vlans[0].member_ports == frozenset()
    assert vlans[0].untagged_ports == frozenset()
    assert vlans[0].tagged_ports == frozenset()


def test_parse_pvids_sorted_port_vlan_pairs():
    rows = [
        SnmpRow("1.3.6.1.2.1.17.7.1.4.5.1.1.2", "90", "Gauge32"),
        SnmpRow("1.3.6.1.2.1.17.7.1.4.5.1.1.1", "90", "Gauge32"),
    ]
    assert parse.parse_pvids(rows) == [(1, 90), (2, 90)]


def test_parse_vlans_raises_on_present_but_malformed_index():
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    # egress row IS present but its VLAN index is non-numeric -> SnmpError.
    egress = [
        SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.x", bytes([0b11000000]), "OCTETSTR")
    ]
    with pytest.raises(SnmpError):
        parse.parse_vlans(names, egress, [])


def test_parse_vlans_raises_on_present_but_malformed_bitmap_type():
    # egress row IS present but its value is neither bytes nor str (wrong
    # SNMP type on the wire) -> SnmpError naming the OID, not silently dropped.
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.5", 42, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.17.7.1.4.3.1.2.5")):
        parse.parse_vlans(names, egress, [])
