# tests/virtual/test_state_seed.py
from __future__ import annotations

from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_gsm7252ps


def test_seed_builds_coherent_oid_map():
    state = seed_gsm7252ps()
    m = state.oid_map()
    # ifOperStatus for port 1 present
    assert f"{oids.IF_OPER_STATUS}.1" in m
    # a delivering PoE port exists with vendor mW > 0
    poe_base = oids.vendor_oids(get_model("gsm7252ps")).poe_power_mw + "."
    assert any(
        k.startswith(poe_base) and int(v[1]) > 0 for k, v in m.items()
    )


def test_seed_roundtrips_through_parsers():
    from netgear_switch.protocols.snmp.client import SnmpRow

    state = seed_gsm7252ps()
    m = state.oid_map()

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, v[1], v[0])
            for k, v in m.items()
            if k == base or k.startswith(base + ".")
        ]

    vlans = parse.parse_vlans(
        rows(oids.DOT1Q_VLAN_STATIC_NAME),
        rows(oids.DOT1Q_VLAN_STATIC_EGRESS),
        rows(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
    )
    assert {v.vlan_id for v in vlans} >= {1, 90}
    mgmt = parse.parse_mgmt_ip(
        rows(oids.IP_ADENT_ADDR), rows(oids.IP_ADENT_NETMASK),
        rows(oids.IP_ROUTE_DEST), rows(oids.IP_ROUTE_NEXTHOP),
        rows(oids.vendor_oids(get_model("gsm7252ps")).dhcp_mode_unverified),
        rows(oids.DOT1D_BASE_BRIDGE_ADDRESS),
    )
    assert mgmt.address == "10.1.5.20"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.base_mac == "28:C6:8E:00:00:01"


def test_seed_emits_nonempty_stats_macs_lldp():
    from netgear_switch.protocols.snmp.client import SnmpRow

    state = seed_gsm7252ps()
    m = state.oid_map()

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, v[1], v[0])
            for k, v in m.items()
            if k == base or k.startswith(base + ".")
        ]

    stats = parse.parse_port_stats(
        in_octets=rows(oids.IF_HC_IN_OCTETS), out_octets=rows(oids.IF_HC_OUT_OCTETS),
        in_ucast=rows(oids.IF_HC_IN_UCAST), out_ucast=rows(oids.IF_HC_OUT_UCAST),
        in_errors=rows(oids.IF_IN_ERRORS), out_errors=rows(oids.IF_OUT_ERRORS),
    )
    assert len([s for s in stats if s.rx_bytes is not None]) >= 2

    macs = parse.parse_macs(
        rows(oids.DOT1Q_TP_FDB_PORT), rows(oids.DOT1D_BASE_PORT_IF_INDEX)
    )
    assert len(macs) >= 2

    lldp = parse.parse_lldp(rows(oids.LLDP_REM_TABLE))
    assert len(lldp) >= 1
    assert lldp[0].remote_sys_name == "sw-cisco-shed"
    # Seed distinguishes remote_port_id ("1/xg51") from remote_port_desc
    # ("eth0") so the two LLDP-MIB columns provably don't collapse together.
    assert lldp[0].remote_port_id == "1/xg51"
    assert lldp[0].remote_port_desc == "eth0"
    assert lldp[0].remote_port_id != lldp[0].remote_port_desc


def test_seed_emits_nonempty_ports_pvids_poe_sensors():
    """The remaining four read ops (ports, pvids, poe, sensors) also
    reconstruct non-empty, coherent objects from the seed's oid_map(), so
    all nine SNMP read ops (Task 5-9) are proven non-vacuous here before the
    SNMP face (Task 15) exists."""
    from netgear_switch.protocols.snmp.client import SnmpRow

    state = seed_gsm7252ps()
    m = state.oid_map()
    v = oids.vendor_oids(get_model("gsm7252ps"))

    def rows(base: str) -> list[SnmpRow]:
        return [
            SnmpRow(k, v[1], v[0])
            for k, v in m.items()
            if k == base or k.startswith(base + ".")
        ]

    ports = parse.parse_port_status(
        rows(oids.IF_ADMIN_STATUS), rows(oids.IF_OPER_STATUS),
        rows(oids.IF_HIGH_SPEED), rows(oids.IF_NAME), rows(oids.IF_ALIAS),
    )
    assert len(ports) == 52
    port1 = next(p for p in ports if p.port == 1)
    assert port1.admin_enabled is True
    assert port1.link_up is True
    assert port1.speed_mbps == 1000
    assert port1.description == "uplink-to-core"
    port3 = next(p for p in ports if p.port == 3)
    assert port3.link_up is False
    assert port3.description is None  # ifAlias never set on port 3

    pvids = parse.parse_pvids(rows(oids.DOT1Q_PVID))
    assert len(pvids) == 52
    assert (1, 90) in pvids

    poe = parse.parse_poe(rows(oids.PETH_PSE_PORT_TABLE), rows(v.poe_power_mw))
    assert len(poe) == 48
    poe1 = next(p for p in poe if p.port == 1)
    assert poe1.delivering is True
    assert poe1.power_mw == 12_800

    sensors = parse.parse_box_sensors(
        [
            ("fan", "RPM", rows(v.box_fan)),
            ("power", "W", rows(v.box_psu_power)),
            ("temperature", "C", rows(v.box_temp)),
        ]
    )
    kinds = {s.kind for s in sensors}
    assert kinds == {"fan", "power", "temperature"}
    assert len(sensors) >= 4  # 2 real fans (Not Supported skipped) + psu + temp
