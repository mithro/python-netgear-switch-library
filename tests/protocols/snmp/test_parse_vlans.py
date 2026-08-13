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
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.5", bytes([0b11000000]), "OCTETSTR")]
    untag = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.4.5", bytes([0b01000000]), "OCTETSTR")]
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
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.x", bytes([0b11000000]), "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_vlans(names, egress, [])


def test_parse_vlans_raises_on_present_but_malformed_bitmap_type():
    # egress row IS present but its value is neither bytes nor str (wrong
    # SNMP type on the wire) -> SnmpError naming the OID, not silently dropped.
    names = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.1.5", "net", "OCTETSTR")]
    egress = [SnmpRow("1.3.6.1.2.1.17.7.1.4.3.1.2.5", 42, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.17.7.1.4.3.1.2.5")):
        parse.parse_vlans(names, egress, [])


# --- the two GS728TPP-measured behaviours -----------------------------------
# Both come from sw-netgear-gs728tpp.monarto.mithis.com (10.2.5.10, firmware
# 6.0.1.30) on 2026-08-02. Widths and bit positions below are the real ones.

_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
_CURRENT_EGRESS = "1.3.6.1.2.1.17.7.1.4.2.1.4"
_CURRENT_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.5"
_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"


def _bitmap(ports: set[int], width: int = 126) -> bytes:
    """A PortList of ``width`` bytes with ``ports`` set (bit 7 of byte 0 = 1)."""
    data = bytearray(width)
    for p in ports:
        data[(p - 1) // 8] |= 0x80 >> ((p - 1) % 8)
    return bytes(data)


def _if_types(physical: int, lags: range) -> list[SnmpRow]:
    return [
        SnmpRow(f"{_IF_TYPE}.{i}", "6", "INTEGER") for i in range(1, physical + 1)
    ] + [SnmpRow(f"{_IF_TYPE}.{i}", "161", "INTEGER") for i in lags]


def test_parse_vlans_drops_lag_bridge_ports_from_membership():
    """Bit 1000 in the PortList is ``po 1``, not a 1000th port.

    The live GS728TPP sets it in 11 of its 13 VLANs; its ifTable types that
    ifIndex 161 (ieee8023adLag) and dot1dBasePortIfIndex is identity-mapped, so
    the bit is a LAG. Reporting it made SNMP claim a member port the switch does
    not have and the HTTP backend never lists.
    """
    names = [SnmpRow(f"{_STATIC_NAME}.5", "net", "OCTETSTR")]
    egress = [
        SnmpRow(f"{_STATIC_EGRESS}.5", _bitmap({1, 2, 24, 1000}), "OCTETSTR"),
    ]
    untag = [SnmpRow(f"{_STATIC_UNTAGGED}.5", _bitmap({24}), "OCTETSTR")]

    unfiltered = parse.parse_vlans(names, egress, untag)
    assert 1000 in unfiltered[0].member_ports, "precondition: the bit really is set"

    [vlan] = parse.parse_vlans(names, egress, untag, _if_types(28, range(1000, 1008)))
    assert vlan.member_ports == frozenset({1, 2, 24})
    assert vlan.untagged_ports == frozenset({24})
    assert vlan.tagged_ports == frozenset({1, 2})


def test_parse_vlans_reports_a_vlan_that_has_no_static_row():
    """VLAN 1 exists ONLY in dot1qVlanCurrentTable on this switch.

    Its static table returns 12 rows (ids 2..99); the current table returns 13.
    The extra row is VLAN 1, untagged on the switch's own management ports --
    which the web UI lists, so a static-table-only read loses it outright.
    """
    names = [SnmpRow(f"{_STATIC_NAME}.5", "net", "OCTETSTR")]
    egress = [SnmpRow(f"{_STATIC_EGRESS}.5", _bitmap({1, 1000}), "OCTETSTR")]
    untag = [SnmpRow(f"{_STATIC_UNTAGGED}.5", _bitmap(set()), "OCTETSTR")]
    # Current table: VLAN 5 (same bytes as static) plus VLAN 1, indexed
    # <timeMark>.<vlanIndex> -- time mark 0 on every row of the real walk.
    cur_egress = [
        SnmpRow(f"{_CURRENT_EGRESS}.0.1", _bitmap({24, 25, 27, 1000}), "OCTETSTR"),
        SnmpRow(f"{_CURRENT_EGRESS}.0.5", _bitmap({1, 1000}), "OCTETSTR"),
    ]
    cur_untag = [
        SnmpRow(f"{_CURRENT_UNTAGGED}.0.1", _bitmap({24, 25, 27, 1000}), "OCTETSTR"),
        SnmpRow(f"{_CURRENT_UNTAGGED}.0.5", _bitmap(set()), "OCTETSTR"),
    ]
    vlans = {
        v.vlan_id: v
        for v in parse.parse_vlans(
            names,
            egress,
            untag,
            _if_types(28, range(1000, 1008)),
            cur_egress,
            cur_untag,
        )
    }
    assert sorted(vlans) == [1, 5]
    # No dot1qVlanStaticName row exists for it, so it has no name -- which is
    # exactly what the HTTP backend reports for this VLAN too.
    assert vlans[1].name is None
    assert vlans[1].untagged_ports == frozenset({24, 25, 27})
    assert vlans[5].name == "net"


def test_parse_vlans_prefers_the_static_bitmap_where_both_tables_have_the_vlan():
    """Static is the CONFIGURED membership and wins.

    On the live switch the two tables agreed byte-for-byte for all 12 shared
    VLANs, so this ordering was measured rather than assumed -- but it must stay
    pinned, because the current table can carry members the operator never
    configured.
    """
    names = [SnmpRow(f"{_STATIC_NAME}.5", "net", "OCTETSTR")]
    egress = [SnmpRow(f"{_STATIC_EGRESS}.5", _bitmap({1}), "OCTETSTR")]
    untag = [SnmpRow(f"{_STATIC_UNTAGGED}.5", _bitmap(set()), "OCTETSTR")]
    cur_egress = [SnmpRow(f"{_CURRENT_EGRESS}.0.5", _bitmap({1, 2}), "OCTETSTR")]
    cur_untag = [SnmpRow(f"{_CURRENT_UNTAGGED}.0.5", _bitmap(set()), "OCTETSTR")]
    [vlan] = parse.parse_vlans(
        names, egress, untag, _if_types(28, range(1000, 1008)), cur_egress, cur_untag
    )
    assert vlan.member_ports == frozenset({1})


def test_parse_vlans_raises_on_malformed_current_table_index():
    # The current table is indexed <timeMark>.<vlanIndex>; a one-component or
    # non-numeric suffix is drift, not absence.
    names = [SnmpRow(f"{_STATIC_NAME}.5", "net", "OCTETSTR")]
    bad = [SnmpRow(f"{_CURRENT_EGRESS}.5", _bitmap({1}), "OCTETSTR")]
    with pytest.raises(SnmpError, match=re.escape(f"{_CURRENT_EGRESS}.5")):
        parse.parse_vlans(names, [], [], (), bad, [])
