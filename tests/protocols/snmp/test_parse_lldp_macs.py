from __future__ import annotations

import re

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_parse_lldp_groups_columns_by_local_port():
    base = "1.0.8802.1.1.2.1.4.1.1"
    rows = [
        SnmpRow(f"{base}.9.75.49.7", "sw-cisco-shed", "OCTETSTR"),
        SnmpRow(f"{base}.8.75.49.7", "eth0", "OCTETSTR"),
        SnmpRow(f"{base}.7.75.49.7", "1/xg51", "OCTETSTR"),
    ]
    n = parse.parse_lldp(rows)
    assert len(n) == 1
    assert n[0].local_port == 49
    assert n[0].remote_sys_name == "sw-cisco-shed"
    assert n[0].remote_port_desc == "eth0"
    # remote_port_id (lldpRemPortId, column 7) is a distinct field from
    # remote_port_desc (lldpRemPortDesc, column 8) -- surfaced, not discarded.
    assert n[0].remote_port_id == "1/xg51"
    assert n[0].remote_port_id != n[0].remote_port_desc


def test_parse_lldp_remote_port_id_absent_is_none():
    """A neighbour row group with no col-7 value yields remote_port_id=None,
    not a fabricated empty string."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    rows = [
        SnmpRow(f"{base}.9.75.49.7", "sw-cisco-shed", "OCTETSTR"),
    ]
    n = parse.parse_lldp(rows)
    assert len(n) == 1
    assert n[0].remote_port_id is None


def test_parse_lldp_remote_port_id_binary_mac_formats_as_hex():
    """A MAC-address-subtype (lldpPortIdSubtype 3) portId arrives as a raw
    6-byte OCTET STRING and must format as ``XX:XX:XX:XX:XX:XX`` -- exactly
    like a MAC-subtype chassis-id -- not get UTF-8-mangled into U+FFFD
    replacement characters. This restores the binary-portId coverage that
    was lost with the old gdoc2netcfg helpers."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    rows = [
        SnmpRow(f"{base}.7.75.49.7", b"\x0c\xc4\x7a\x16\x3b\x4a", "OCTETSTR"),
    ]
    n = parse.parse_lldp(rows)
    assert len(n) == 1
    assert n[0].remote_port_id == "0C:C4:7A:16:3B:4A"


def test_parse_lldp_remote_port_id_ascii_stays_text():
    """An ASCII interface-name-subtype portId (e.g. a fleet portId like
    "gi24") is plain text and must NOT be reinterpreted as MAC bytes."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    rows = [
        SnmpRow(f"{base}.7.75.49.7", "gi24", "OCTETSTR"),
    ]
    n = parse.parse_lldp(rows)
    assert len(n) == 1
    assert n[0].remote_port_id == "gi24"


def test_parse_macs_maps_bridge_port_to_ifindex():
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    fdb = [SnmpRow(f"{fdb_base}.90.200.0.132.137.113.112", "10", "INTEGER")]
    # bridge 10 -> if 24
    bridge = [SnmpRow("1.3.6.1.2.1.17.1.4.1.2.10", "24", "INTEGER")]
    macs = parse.parse_macs(fdb, bridge)
    assert len(macs) == 1
    assert macs[0].mac == "C8:00:84:89:71:70"
    assert macs[0].vlan_id == 90
    assert macs[0].port == 24


def test_parse_macs_raises_on_non_integer_port():
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    bad = [SnmpRow(f"{fdb_base}.1.1.2.3.4.5.6", "learned", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_macs(bad, [])


def test_parse_lldp_raises_on_present_but_malformed_local_port():
    base = "1.0.8802.1.1.2.1.4.1.1"
    # Row IS present with a non-empty sysName column but a non-integer local port.
    rows = [SnmpRow(f"{base}.9.75.xx.7", "sw-cisco-shed", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_lldp(rows)


def test_parse_lldp_raises_on_wrong_index_arity():
    """parse_lldp raises SnmpError when stripped index has wrong part count."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    # Index has 5 parts instead of exactly 4
    oid = f"{base}.9.75.49.7.extra"
    rows = [SnmpRow(oid, "sw-cisco-shed", "OCTETSTR")]
    with pytest.raises(SnmpError, match=re.escape(oid)):
        parse.parse_lldp(rows)


def test_parse_lldp_raises_on_non_integer_column():
    """parse_lldp raises SnmpError when column component is non-integer."""
    base = "1.0.8802.1.1.2.1.4.1.1"
    # Column is 'xx' (non-integer)
    oid = f"{base}.xx.75.49.7"
    rows = [SnmpRow(oid, "sw-cisco-shed", "OCTETSTR")]
    with pytest.raises(SnmpError, match=re.escape(oid)):
        parse.parse_lldp(rows)


def test_parse_macs_raises_on_wrong_index_arity():
    """parse_macs raises SnmpError when FDB index has wrong part count."""
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    # Index has 6 parts instead of exactly 7 (vlan + 6 MAC bytes)
    oid = f"{fdb_base}.90.200.0.132.137.113"
    rows = [SnmpRow(oid, "10", "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape(oid)):
        parse.parse_macs(rows, [])


def test_parse_macs_raises_on_non_integer_vlan():
    """parse_macs raises SnmpError when VLAN index component is non-integer."""
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
    # VLAN is 'xx' (non-integer)
    oid = f"{fdb_base}.xx.200.0.132.137.113.112"
    rows = [SnmpRow(oid, "10", "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape(oid)):
        parse.parse_macs(rows, [])
