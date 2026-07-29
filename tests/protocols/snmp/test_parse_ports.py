# tests/protocols/snmp/test_parse_ports.py
from __future__ import annotations

import pytest

from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def _rows(base: str, pairs: dict[int, str], typ: str) -> list[SnmpRow]:
    return [SnmpRow(f"{base}.{i}", v, typ) for i, v in pairs.items()]


def test_parse_port_status_joins_admin_oper_speed_name():
    admin = _rows("1.3.6.1.2.1.2.2.1.7", {1: "1", 2: "2"}, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", {1: "1", 2: "2"}, "INTEGER")
    speed = _rows("1.3.6.1.2.1.31.1.1.1.15", {1: "1000", 2: "0"}, "Gauge32")
    names = _rows("1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/1", 2: "1/0/2"}, "OCTETSTR")
    aliases = _rows("1.3.6.1.2.1.31.1.1.1.18", {1: "uplink"}, "OCTETSTR")

    ports = parse.parse_port_status(admin, oper, speed, names, aliases)
    assert [p.port for p in ports] == [1, 2]
    assert ports[0].admin_enabled is True
    assert ports[0].link_up is True
    assert ports[0].speed_mbps == 1000
    assert ports[0].name == "1/0/1"
    assert ports[0].description == "uplink"
    assert ports[1].admin_enabled is False
    assert ports[1].link_up is False
    assert ports[1].speed_mbps is None  # 0 Mbps -> None
    # No ifAlias row for port 2 -> honest None, not "".
    assert ports[1].description is None


def test_parse_port_status_filters_to_physical_ethernet_ports():
    """The M4300 ifTable carries 16 ethernetCsmacd(6) physical ports alongside
    ieee8023adLag(161) LAGs, a CPU(1) interface and an l2vlan(135) routing
    interface -- none of which the web UI's port page lists. Given an ifType
    walk, parse_port_status must keep ONLY the physical ports so SNMP get_ports
    agrees field-for-field with the HTTP backend (live: 16 vs 146 without this).
    """
    idx = {1: "1", 2: "1", 769: "1", 770: "1", 898: "1"}
    admin = _rows("1.3.6.1.2.1.2.2.1.7", idx, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", idx, "INTEGER")
    names = _rows(
        "1.3.6.1.2.1.31.1.1.1.1",
        {1: "1/0/1", 2: "1/0/2", 769: "CPU", 770: "lag 1", 898: "vlan 1"},
        "OCTETSTR",
    )
    if_types = _rows(
        "1.3.6.1.2.1.2.2.1.3",
        {1: "6", 2: "6", 769: "1", 770: "161", 898: "135"},
        "INTEGER",
    )
    ports = parse.parse_port_status(admin, oper, [], names, [], if_types)
    assert [p.port for p in ports] == [1, 2]  # LAG/CPU/VLAN dropped


def test_parse_port_status_keeps_all_when_no_iftype_walk():
    """With NO ifType walk (a transport/mock that does not surface ifType), every
    interface is kept -- backward-compatible, no silent drop."""
    admin = _rows("1.3.6.1.2.1.2.2.1.7", {1: "1", 770: "1"}, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", {1: "1", 770: "1"}, "INTEGER")
    ports = parse.parse_port_status(admin, oper, [], [], [])
    assert [p.port for p in ports] == [1, 770]


def test_parse_port_stats_filters_to_physical_ports():
    """ifHC counters are ifIndex-keyed; get_stats must drop the same non-physical
    interfaces get_ports does, or SNMP stats (146 rows) != HTTP stats (16)."""
    def _c(base, pairs):
        return _rows(base, pairs, "Counter64")
    in_o = _c("1.3.6.1.2.1.31.1.1.1.6", {1: "100", 770: "999"})
    out_o = _c("1.3.6.1.2.1.31.1.1.1.10", {1: "200", 770: "999"})
    if_types = _rows("1.3.6.1.2.1.2.2.1.3", {1: "6", 770: "161"}, "INTEGER")
    stats = parse.parse_port_stats(
        in_octets=in_o, out_octets=out_o, in_ucast=[], out_ucast=[],
        in_errors=[], out_errors=[], if_types=if_types,
    )
    assert [s.port for s in stats] == [1]  # LAG 770 dropped
    # No ifType walk -> keep all (backward-compatible).
    stats_all = parse.parse_port_stats(
        in_octets=in_o, out_octets=out_o, in_ucast=[], out_ucast=[],
        in_errors=[], out_errors=[],
    )
    assert [s.port for s in stats_all] == [1, 770]


def test_parse_pvids_filters_to_physical_ports():
    """PVIDs are reported for LAG interfaces too; filter them out via ifType so
    the SNMP PVID map matches the HTTP page's physical-only view."""
    pvid_rows = _rows(
        "1.3.6.1.2.1.17.7.1.4.5.1.1", {1: "10", 2: "20", 770: "1"}, "Gauge32"
    )
    if_types = _rows(
        "1.3.6.1.2.1.2.2.1.3", {1: "6", 2: "6", 770: "161"}, "INTEGER"
    )
    assert parse.parse_pvids(pvid_rows, if_types) == [(1, 10), (2, 20)]
    # No ifType walk -> keep all (backward-compatible).
    assert parse.parse_pvids(pvid_rows) == [(1, 10), (2, 20), (770, 1)]


def test_parse_pvids_translates_baseport_to_ifindex_before_filtering():
    """DOT1Q_PVID is keyed by dot1dBasePort, the physical set by ifIndex. On a
    switch where they DIFFER, the PVID filter must translate via
    dot1dBasePortIfIndex -- else it drops real physical PVIDs (or keeps LAGs).

    Here basePorts 1,2 map to physical ifIndex 4097,4098; basePort 3 maps to a
    LAG ifIndex 5000. Only 1,2 must survive."""
    pvid_rows = _rows(
        "1.3.6.1.2.1.17.7.1.4.5.1.1", {1: "10", 2: "20", 3: "30"}, "Gauge32"
    )
    if_types = _rows(
        "1.3.6.1.2.1.2.2.1.3", {4097: "6", 4098: "6", 5000: "161"}, "INTEGER"
    )
    base_map = _rows(
        "1.3.6.1.2.1.17.1.4.1.2", {1: "4097", 2: "4098", 3: "5000"}, "INTEGER"
    )
    assert parse.parse_pvids(pvid_rows, if_types, base_map) == [(1, 10), (2, 20)]


def test_parse_port_status_down_port_reports_no_speed():
    # A DOWN port whose ifHighSpeed still advertises the configured rate
    # (verified real behavior: gsm7252ps down 1/0/52 reports 10000) has NO
    # operational speed -> None, so the SNMP reader agrees field-for-field with
    # the web UI's "Unknown"/None for the same port.
    admin = _rows("1.3.6.1.2.1.2.2.1.7", {1: "1"}, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", {1: "2"}, "INTEGER")  # link down
    speed = _rows("1.3.6.1.2.1.31.1.1.1.15", {1: "10000"}, "Gauge32")
    names = _rows("1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/52"}, "OCTETSTR")

    ports = parse.parse_port_status(admin, oper, speed, names, [])
    assert ports[0].link_up is False
    assert ports[0].speed_mbps is None  # down -> no operational speed


def test_parse_port_status_empty_alias_is_none_not_empty_string():
    admin = _rows("1.3.6.1.2.1.2.2.1.7", {1: "1"}, "INTEGER")
    oper = _rows("1.3.6.1.2.1.2.2.1.8", {1: "1"}, "INTEGER")
    speed = _rows("1.3.6.1.2.1.31.1.1.1.15", {1: "1000"}, "Gauge32")
    names = _rows("1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/1"}, "OCTETSTR")
    # ifAlias column IS present for port 1 but with an empty value -- a switch
    # that has an ifAlias instance but no operator-set text.
    aliases = _rows("1.3.6.1.2.1.31.1.1.1.18", {1: ""}, "OCTETSTR")

    ports = parse.parse_port_status(admin, oper, speed, names, aliases)
    assert ports[0].description is None


def test_parse_port_stats_absent_counter_is_none():
    stats = parse.parse_port_stats(
        in_octets=_rows("1.3.6.1.2.1.31.1.1.1.6", {1: "100"}, "Counter64"),
        out_octets=_rows("1.3.6.1.2.1.31.1.1.1.10", {1: "200"}, "Counter64"),
        in_ucast=_rows("1.3.6.1.2.1.31.1.1.1.7", {1: "5"}, "Counter64"),
        out_ucast=_rows("1.3.6.1.2.1.31.1.1.1.11", {1: "6"}, "Counter64"),
        in_errors=_rows("1.3.6.1.2.1.2.2.1.14", {1: "0"}, "Counter32"),
        out_errors=[],  # switch didn't expose ifOutErrors for port 1
    )
    assert len(stats) == 1
    assert stats[0].rx_bytes == 100
    assert stats[0].tx_bytes == 200
    assert stats[0].rx_packets == 5
    assert stats[0].tx_packets == 6
    assert stats[0].rx_errors == 0
    assert stats[0].tx_errors is None


def test_index_int_column_raises_on_non_integer():
    with pytest.raises(SnmpError):
        parse.index_int_column(
            [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", "up", "OCTETSTR")],
            "1.3.6.1.2.1.2.2.1.8",
        )


def test_index_str_column_raises_on_present_but_malformed_index():
    # Column IS present under base but its index component is non-integer:
    # drift, not absence -> SnmpError (an absent column would just be {}).
    with pytest.raises(SnmpError):
        parse.index_str_column(
            [SnmpRow("1.3.6.1.2.1.31.1.1.1.1.x", "eth", "OCTETSTR")],
            "1.3.6.1.2.1.31.1.1.1.1",
        )


def test_index_str_column_raises_on_non_string_value():
    """index_str_column raises SnmpError when a present row has a non-str/bytes
    value (e.g. an int) — a genuine wrong-type reply."""
    with pytest.raises(SnmpError, match="non-string value"):
        parse.index_str_column(
            [SnmpRow("1.3.6.1.2.1.31.1.1.1.1.1", 42, "INTEGER")],
            "1.3.6.1.2.1.31.1.1.1.1",
        )


def test_index_str_column_decodes_bytes_value():
    """A bytes OCTET STRING (pysnmp's non-printable heuristic, e.g. a name
    with a trailing NUL) decodes to the same str the CLI transport would
    yield for the same underlying value — transport parity."""
    rows = [
        SnmpRow("1.3.6.1.2.1.31.1.1.1.1.9", b"1/0/9", "OCTETSTR"),
        SnmpRow("1.3.6.1.2.1.31.1.1.1.1.10", b"eth1\x00", "OCTETSTR"),
    ]
    result = parse.index_str_column(rows, "1.3.6.1.2.1.31.1.1.1.1")
    assert result[9] == "1/0/9"
    assert result[10] == "eth1\x00"


def test_index_int_column_raises_on_malformed_index():
    """index_int_column raises SnmpError for non-numeric OID suffix."""
    with pytest.raises(SnmpError, match="malformed index"):
        parse.index_int_column(
            [SnmpRow("1.3.6.1.2.1.2.2.1.8.abc", "42", "INTEGER")],
            "1.3.6.1.2.1.2.2.1.8",
        )


def test_index_int_column_raises_on_non_integer_value():
    """index_int_column raises SnmpError for non-numeric value."""
    with pytest.raises(SnmpError, match="non-integer value"):
        parse.index_int_column(
            [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", "not_a_number", "OCTETSTR")],
            "1.3.6.1.2.1.2.2.1.8",
        )
