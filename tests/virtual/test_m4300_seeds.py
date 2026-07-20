# tests/virtual/test_m4300_seeds.py
"""Ground the M4300-24X/16X virtual-mock seeds in the committed real-hardware
captures (``tests/fixtures/captures/m4300-*.json``): the headline capability
contrast (24X has NO PoE, 16X has PoE on all 16 ports) plus port/VLAN/sensor/
mgmt-IP fidelity, cross-checked directly against the capture JSON so a future
edit to either seed or fixture that drifts them apart is caught here.
"""
from __future__ import annotations

import json
from pathlib import Path

from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_m4300_16x, seed_m4300_24x

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "captures"


def _capture(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())["snapshot"]


def _rows(m: dict[str, tuple[str, str]], base: str) -> list[SnmpRow]:
    return [
        SnmpRow(k, v[1], v[0])
        for k, v in m.items()
        if k == base or k.startswith(base + ".")
    ]


# --- M4300-24X: non-PoE ------------------------------------------------------


def test_m4300_24x_has_no_poe_matching_capture():
    capture = _capture("m4300-24x")
    assert capture["poe"] == []  # ground truth: real device has no PoE

    state = seed_m4300_24x()
    assert state.poe == {}
    m = state.oid_map()
    poe = parse.parse_poe(
        _rows(m, oids.PETH_PSE_PORT_TABLE),
        _rows(m, oids.vendor_oids(get_model("m4300-24x")).poe_power_mw),
    )
    assert poe == []


def test_m4300_24x_ports_names_speeds_match_capture():
    capture = _capture("m4300-24x")
    real_by_port = {p["port"]: p for p in capture["ports"] if p["port"] <= 24}

    state = seed_m4300_24x()
    m = state.oid_map()
    ports = parse.parse_port_status(
        _rows(m, oids.IF_ADMIN_STATUS), _rows(m, oids.IF_OPER_STATUS),
        _rows(m, oids.IF_HIGH_SPEED), _rows(m, oids.IF_NAME), _rows(m, oids.IF_ALIAS),
    )
    seeded_by_port = {p.port: p for p in ports if p.port <= 24}
    assert set(seeded_by_port) == set(real_by_port)
    for port, real in real_by_port.items():
        seeded = seeded_by_port[port]
        assert seeded.name == real["name"]
        assert seeded.admin_enabled == real["admin_enabled"]
        assert seeded.link_up == real["link_up"]
        assert seeded.speed_mbps == (real["speed_mbps"] or None)
        assert seeded.description == real["description"]


def test_m4300_24x_vlans_and_pvids_match_capture():
    capture = _capture("m4300-24x")
    state = seed_m4300_24x()
    m = state.oid_map()
    vlans = parse.parse_vlans(
        _rows(m, oids.DOT1Q_VLAN_STATIC_NAME), _rows(m, oids.DOT1Q_VLAN_STATIC_EGRESS),
        _rows(m, oids.DOT1Q_VLAN_STATIC_UNTAGGED),
    )
    assert {v.vlan_id for v in vlans} == {v["vlan_id"] for v in capture["vlans"]}
    by_id = {v.vlan_id: v for v in vlans}
    for real in capture["vlans"]:
        seeded = by_id[real["vlan_id"]]
        assert seeded.name == real["name"]
        assert seeded.member_ports == frozenset(real["member_ports"])
        assert seeded.untagged_ports == frozenset(real["untagged_ports"])
        assert seeded.tagged_ports == frozenset(real["tagged_ports"])

    pvids = dict(parse.parse_pvids(_rows(m, oids.DOT1Q_PVID)))
    real_pvids = dict(capture["pvids"])
    for port in range(1, 25):
        assert pvids[port] == real_pvids[port]


def test_m4300_24x_sensors_match_capture():
    capture = _capture("m4300-24x")
    state = seed_m4300_24x()
    m = state.oid_map()
    v = oids.vendor_oids(get_model("m4300-24x"))
    sensors = parse.parse_box_sensors(
        [
            ("fan", "RPM", _rows(m, v.box_fan)),
            ("power", "W", _rows(m, v.box_psu_power)),
            ("temperature", "C", _rows(m, v.box_temp)),
        ]
    )
    seeded = {(s.kind, s.name): s.value for s in sensors}
    for real in capture["sensors"]:
        assert seeded[(real["kind"], real["name"])] == real["value"]


def test_m4300_24x_mgmt_ip_and_ascii_base_mac_match_capture():
    """CRUCIAL: this model's dot1dBaseBridgeAddress is VERIFIED to come back
    as ASCII colon-hex TEXT on real hardware (see parse.py's
    _mac_from_ascii_text) -- prove that quirk round-trips end-to-end through
    the mock, not just via a synthetic unit-test row."""
    capture = _capture("m4300-24x")
    state = seed_m4300_24x()
    m = state.oid_map()

    # The wire value itself is the 17-char ASCII text, not 6 raw bytes.
    wire_type, wire_value = m[f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0"]
    assert wire_type == "OCTETSTR"
    assert wire_value == capture["mgmt_ip"]["base_mac"]
    assert len(wire_value) == 17

    mgmt = parse.parse_mgmt_ip(
        _rows(m, oids.IP_ADENT_ADDR), _rows(m, oids.IP_ADENT_NETMASK),
        _rows(m, oids.IP_ROUTE_DEST), _rows(m, oids.IP_ROUTE_NEXTHOP),
        _rows(m, oids.vendor_oids(get_model("m4300-24x")).dhcp_mode_unverified),
        _rows(m, oids.DOT1D_BASE_BRIDGE_ADDRESS),
    )
    assert mgmt.address == capture["mgmt_ip"]["address"] == "10.1.5.13"
    assert mgmt.netmask == capture["mgmt_ip"]["netmask"]
    assert mgmt.gateway == capture["mgmt_ip"]["gateway"]
    assert mgmt.base_mac == capture["mgmt_ip"]["base_mac"] == "8C:3B:AD:6B:BB:E0"


# --- M4300-16X: PoE on all 16 ports ------------------------------------------


def test_m4300_16x_has_poe_on_all_16_ports_matching_capture():
    capture = _capture("m4300-16x")
    assert len(capture["poe"]) == 16  # ground truth: all 16 ports PoE-capable

    state = seed_m4300_16x()
    assert len(state.poe) == 16
    m = state.oid_map()
    v = oids.vendor_oids(get_model("m4300-16x"))
    poe = parse.parse_poe(_rows(m, oids.PETH_PSE_PORT_TABLE), _rows(m, v.poe_power_mw))
    seeded_by_port = {p.port: p for p in poe}
    for real in capture["poe"]:
        seeded = seeded_by_port[real["port"]]
        assert seeded.admin_enabled == real["admin_enabled"]
        assert seeded.detect.value == real["detect"]
        assert (seeded.power_mw or 0) == real["power_mw"]
    delivering = [p for p in poe if p.delivering]
    assert len(delivering) == 2  # ports 11+12, verified live


def test_m4300_16x_ports_and_sensors_match_capture():
    capture = _capture("m4300-16x")
    real_by_port = {p["port"]: p for p in capture["ports"] if p["port"] <= 16}

    state = seed_m4300_16x()
    m = state.oid_map()
    ports = parse.parse_port_status(
        _rows(m, oids.IF_ADMIN_STATUS), _rows(m, oids.IF_OPER_STATUS),
        _rows(m, oids.IF_HIGH_SPEED), _rows(m, oids.IF_NAME), _rows(m, oids.IF_ALIAS),
    )
    seeded_by_port = {p.port: p for p in ports if p.port <= 16}
    assert set(seeded_by_port) == set(real_by_port)
    for port, real in real_by_port.items():
        seeded = seeded_by_port[port]
        assert seeded.name == real["name"]
        assert seeded.link_up == real["link_up"]
        assert seeded.speed_mbps == (real["speed_mbps"] or None)

    v = oids.vendor_oids(get_model("m4300-16x"))
    sensors = parse.parse_box_sensors(
        [
            ("fan", "RPM", _rows(m, v.box_fan)),
            ("power", "W", _rows(m, v.box_psu_power)),
            ("temperature", "C", _rows(m, v.box_temp)),
        ]
    )
    seeded_sensors = {(s.kind, s.name): s.value for s in sensors}
    for real in capture["sensors"]:
        assert seeded_sensors[(real["kind"], real["name"])] == real["value"]


def test_m4300_16x_base_mac_matches_capture_raw_bytes_form():
    """Unlike the 24X, no ASCII-text quirk is captured for this model --
    the standard raw-6-bytes encoding must still parse to the same real MAC."""
    capture = _capture("m4300-16x")
    state = seed_m4300_16x()
    assert state.dot1d_base_mac_ascii is False
    m = state.oid_map()
    mgmt = parse.parse_mgmt_ip(
        _rows(m, oids.IP_ADENT_ADDR), _rows(m, oids.IP_ADENT_NETMASK),
        _rows(m, oids.IP_ROUTE_DEST), _rows(m, oids.IP_ROUTE_NEXTHOP),
        _rows(m, oids.vendor_oids(get_model("m4300-16x")).dhcp_mode_unverified),
        _rows(m, oids.DOT1D_BASE_BRIDGE_ADDRESS),
    )
    assert mgmt.base_mac == capture["mgmt_ip"]["base_mac"] == "8C:3B:AD:69:1C:38"


def test_m4300_16x_vlans_match_capture():
    capture = _capture("m4300-16x")
    state = seed_m4300_16x()
    m = state.oid_map()
    vlans = parse.parse_vlans(
        _rows(m, oids.DOT1Q_VLAN_STATIC_NAME), _rows(m, oids.DOT1Q_VLAN_STATIC_EGRESS),
        _rows(m, oids.DOT1Q_VLAN_STATIC_UNTAGGED),
    )
    assert {v.vlan_id for v in vlans} == {v["vlan_id"] for v in capture["vlans"]}
    by_id = {v.vlan_id: v for v in vlans}
    for real in capture["vlans"]:
        seeded = by_id[real["vlan_id"]]
        assert seeded.member_ports == frozenset(real["member_ports"])
        assert seeded.untagged_ports == frozenset(real["untagged_ports"])
