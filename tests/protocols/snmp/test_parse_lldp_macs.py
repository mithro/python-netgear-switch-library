from __future__ import annotations

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
