"""Unit tests for the FASTPATH CLI parsers against the REAL captured fixtures.

Every expected value is transcribed from ``tests/fixtures/cli/gsm7252ps_*.txt``
(split from the live SSH transcript of 10.1.5.22), never invented.
"""
from __future__ import annotations

from pathlib import Path

from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.protocols.cli import parse
from netgear_switch.registry import MODELS

_FIX = Path(__file__).parents[2] / "fixtures" / "cli"


def _read(name: str) -> str:
    return (_FIX / f"gsm7252ps_{name}.txt").read_text()


def test_parse_version_identifies_gsm7252ps() -> None:
    det = parse.parse_version(_read("show_version"), MODELS)
    assert det.key == "gsm7252ps"
    assert det.sys_object_id is None
    assert "GSM7252PS" in (det.sys_descr or "")


def test_parse_port_status_columns() -> None:
    ports = {p.port: p for p in parse.parse_port_status(_read("show_port_all"))}
    assert len(ports) == 52  # 52 physical ports, lag rows dropped
    assert ports[1].admin_enabled is True
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 1000
    assert ports[1].name == "1/0/1"
    # A down port: no negotiated speed -> None, never 0.
    assert ports[6].link_up is False
    assert ports[6].speed_mbps is None
    # 100M and 10G ports.
    assert ports[9].speed_mbps == 100
    assert ports[49].speed_mbps == 10000
    # A "PC Mbr" Type value must not shift the Admin/Link columns.
    assert ports[50].admin_enabled is True
    assert ports[50].link_up is True
    assert ports[50].speed_mbps == 10000
    # No CLI ifAlias column -> description honestly None.
    assert ports[1].description is None


def test_parse_vlan_brief_lists_every_vlan() -> None:
    brief = parse.parse_vlan_brief(_read("show_vlan_brief"))
    assert [v for v, _ in brief] == [
        1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141
    ]
    assert dict(brief)[90] == "iot"
    assert dict(brief)[1] == "default"


def test_parse_vlan_detail_membership_and_tagging() -> None:
    info = parse.parse_vlan_detail(_read("show_vlan_90"), name="iot")
    assert info.vlan_id == 90
    assert info.name == "iot"
    # Tagged ports on VLAN 90 (Include + Tagged in the fixture).
    assert info.tagged_ports == frozenset({11, 12, 46, 47, 49})
    # A few untagged members.
    assert {1, 2, 5, 13} <= info.untagged_ports
    # Excluded ports are not members.
    assert 6 not in info.member_ports
    assert 8 not in info.member_ports
    # lag rows are dropped (physical ports only).
    assert all(p <= 52 for p in info.member_ports)


def test_parse_pvids_uses_configured_column() -> None:
    pvids = dict(parse.parse_pvids(_read("show_vlan_port_all")))
    assert len(pvids) == 52
    assert pvids[1] == 90
    assert pvids[45] == 20
    assert pvids[46] == 4
    assert pvids[47] == 5
    # Configured 1 / Current 0 -> the persistent PVID 1 is used.
    assert pvids[50] == 1


def test_parse_mac_table_ifindex_is_port() -> None:
    macs = parse.parse_mac_table(_read("show_mac_addr_table"))
    by_mac = {m.mac: m for m in macs}
    # Physical port.
    assert by_mac["02:00:0A:01:01:01"].port == 49
    assert by_mac["02:00:0A:01:01:01"].vlan_id == 1
    # A LAG entry: the IfIndex column (418), not the interface text.
    assert by_mac["E0:91:F5:0C:D5:C9"].port == 418
    # The CPU/Management row (interface text has internal spaces) -> ifIndex 417.
    assert by_mac["E0:91:F5:0C:D6:DB"].port == 417
    assert by_mac["E0:91:F5:0C:D6:DB"].vlan_id == 5


def test_parse_lldp_neighbours() -> None:
    parsed = parse.parse_lldp(_read("show_lldp_remote_device_all"))
    nbrs = {n.local_port: n for n in parsed}
    # A local interface printed with no neighbour (1/0/6) is skipped.
    assert 6 not in nbrs
    assert nbrs[1].remote_sys_name == "rpi5-pmod"
    assert nbrs[1].remote_chassis_id == "88:A2:9E:80:87:9B"
    assert nbrs[1].remote_port_id == "88:A2:9E:80:87:9B"
    # No port-description column on this command.
    assert nbrs[1].remote_port_desc is None
    # A neighbour whose Port ID is a plain interface name, not a MAC.
    assert nbrs[33].remote_port_id == "eth0"
    assert nbrs[49].remote_port_id == "1/0/2"


def test_parse_poe_status_and_inferred_admin() -> None:
    poe = {p.port: p for p in parse.parse_poe(_read("show_poe_port_info_all"))}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 3600
    assert poe[1].admin_enabled is True
    # A searching PSE port: admin still enabled (inferred), no power.
    assert poe[6].detect is PoEDetect.SEARCHING
    assert poe[6].power_mw == 0
    assert poe[6].admin_enabled is True


def test_parse_environment_sensors() -> None:
    sensors = parse.parse_environment(_read("show_environment"))
    temps = {s.name: s.value for s in sensors if s.kind == "temperature"}
    assert temps == {"CPU": 49.0, "System": 30.0, "MAC-A": 33.0, "MAC-B": 31.0}
    for s in sensors:
        if s.kind == "temperature":
            assert s.unit == "C"
    fans = {s.name: s.value for s in sensors if s.kind == "fan"}
    # Fan-2 reports "Not Supported" -> absent, not zero.
    assert fans == {"Fan-1": 3150.0, "Fan-3": 2750.0}
    psus = {s.name: s.value for s in sensors if s.kind == "power"}
    assert psus == {"AC": 1.0, "PS-2": 1.0}


def test_parse_mgmt_ip() -> None:
    mgmt = parse.parse_mgmt_ip(_read("show_network"))
    assert mgmt.address == "10.1.5.22"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
    # "Configured IPv4 Protocol: DHCP" on the real device.
    assert mgmt.mode is IpMode.DHCP


def test_parse_interface_counters() -> None:
    stats = parse.parse_interface_counters(
        _read("show_interface_ethernet_1_0_1"), port=1
    )
    assert stats.port == 1
    assert stats.rx_bytes == 7114270
    assert stats.tx_bytes == 139445046
    assert stats.rx_packets == 32835
    assert stats.tx_packets == 34679
    assert stats.rx_errors == 0
    assert stats.tx_errors == 0


def test_ruler_spans_keep_spaces_in_one_cell() -> None:
    """A cell that legitimately contains spaces must not be split -- the whole
    point of ruler-based slicing over str.split()."""
    macs = parse.parse_mac_table(_read("show_mac_addr_table"))
    # The management row's interface is "CPU Interface:  0/5/1"; its MAC and
    # ifIndex still parse correctly around that spaced cell.
    mgmt_row = next(m for m in macs if m.port == 417)
    assert mgmt_row.mac == "E0:91:F5:0C:D6:DB"


# ---------------------------------------------------------------------------
# M4300-24X (FASTPATH 12.0.13.8) real captures, live from 10.1.5.13 2026-07-29.
# The M4300 firmware renames two commands ("show vlan", "show ip management") and
# labels a couple of fields differently ("Method", "Power Modules:"), but the
# table/scalar shapes are the same, so the SAME parsers apply. Every expected
# value is transcribed from tests/fixtures/cli/m4300_24x_*.txt.
# ---------------------------------------------------------------------------


def _read_m4300(name: str) -> str:
    return (_FIX / f"m4300_24x_{name}.txt").read_text()


def test_m4300_parse_version_identifies_model() -> None:
    det = parse.parse_version(_read_m4300("show_version"), MODELS)
    assert det.key == "m4300-24x"
    assert det.sys_object_id is None
    assert "M4300-24X" in (det.sys_descr or "")


def test_m4300_parse_port_status_24_physical_ports() -> None:
    ports = {p.port: p for p in parse.parse_port_status(_read_m4300("show_port_all"))}
    # 24 physical ports; the 128 "lag N" and the "vlan N" pseudo-interfaces are
    # dropped -- there is no port 25-28.
    assert set(ports) == set(range(1, 25))
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 10000  # "10G Full"
    assert ports[3].speed_mbps == 1000
    # A down port: no negotiated speed -> None.
    assert ports[4].link_up is False
    assert ports[4].speed_mbps is None
    # A "PC Mbr" Type value must not shift the Admin/Link columns.
    assert ports[21].admin_enabled is True
    assert ports[21].link_up is True
    assert ports[21].speed_mbps == 10000


def test_m4300_parse_vlan_list_via_show_vlan() -> None:
    # "show vlan" on 12.0 (not "show vlan brief"): identical table shape.
    brief = parse.parse_vlan_brief(_read_m4300("show_vlan"))
    assert [v for v, _ in brief] == [
        1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141
    ]
    assert dict(brief)[1] == "default"
    assert dict(brief)[90] == "iot"


def test_m4300_parse_vlan_detail_membership() -> None:
    info = parse.parse_vlan_detail(_read_m4300("show_vlan_90"), name="iot")
    assert info.vlan_id == 90
    assert info.name == "iot"
    assert info.tagged_ports == frozenset({1, 2, 5})
    assert info.untagged_ports == frozenset({6})


def test_m4300_parse_pvids_24_ports() -> None:
    pvids = dict(parse.parse_pvids(_read_m4300("show_vlan_port_all")))
    assert set(pvids) == set(range(1, 25))
    assert pvids[1] == 1
    assert pvids[3] == 5
    assert pvids[6] == 90
    assert pvids[24] == 10


def test_m4300_parse_mgmt_ip_via_show_ip_management() -> None:
    # "show ip management" on 12.0 labels the mode "Method" (not "Configured
    # IPv4 Protocol"); the parser accepts either.
    mgmt = parse.parse_mgmt_ip(_read_m4300("show_ip_management"))
    assert mgmt.address == "10.1.5.13"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.base_mac == "8C:3B:AD:6B:BB:E0"
    assert mgmt.mode is IpMode.DHCP


def test_m4300_parse_environment_sensors() -> None:
    sensors = parse.parse_environment(_read_m4300("show_environment"))
    temps = {s.name: s.value for s in sensors if s.kind == "temperature"}
    assert temps == {"MAC": 46.0}
    fans = {s.name: s.value for s in sensors if s.kind == "fan"}
    assert fans == {"Fan-1": 5280.0, "Fan-2": 4560.0}
    # PSU sub-table is headed "Power Modules:" on this firmware, not
    # "Power supplies:" -- still parsed.
    psus = {s.name: s.value for s in sensors if s.kind == "power"}
    assert psus == {"Internal AC-1": 1.0}


def test_m4300_parse_lldp_neighbours() -> None:
    nbrs = {n.local_port: n for n in parse.parse_lldp(_read_m4300(
        "show_lldp_remote_device_all"
    ))}
    assert set(nbrs) == {1, 2, 9, 10, 19, 20, 21, 22, 23, 24}  # 10 neighbours
    assert nbrs[1].remote_chassis_id == "8C:3B:AD:69:1C:38"
    assert nbrs[1].remote_port_id == "1/0/14"
    assert nbrs[1].remote_port_desc is None


def test_m4300_parse_interface_counters() -> None:
    stats = parse.parse_interface_counters(
        _read_m4300("show_interface_ethernet_1_0_1"), port=1
    )
    assert stats.port == 1
    assert stats.rx_bytes == 15294247267585
    assert stats.tx_bytes == 11908661422462
    assert stats.rx_packets == 17643540356
    assert stats.tx_packets == 16762689317
    assert stats.rx_errors == 6
    assert stats.tx_errors == 0


def test_m4300_parse_mac_table_nonempty() -> None:
    macs = parse.parse_mac_table(_read_m4300("show_mac_addr_table"))
    assert len(macs) > 100  # 630+ live entries in the capture
    # A physical-port entry parses to its ifIndex.
    first = macs[0]
    assert first.mac == "02:00:0A:01:01:01"
    assert first.port == 1
    assert first.vlan_id == 1
