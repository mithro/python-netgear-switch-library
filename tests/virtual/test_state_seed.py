# tests/virtual/test_state_seed.py
from __future__ import annotations

from pathlib import Path

from capture_parity import load_capture_snapshot
from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.registry import get_model
from netgear_switch.virtual.seed import seed_gsm7252ps

_GSM7252PS_CAPTURE = (
    Path(__file__).parent.parent / "fixtures" / "captures" / "gsm7252ps.json"
)


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


def test_seed_gsm7252ps_iot_vlan_concept_matches_the_real_capture():
    """``gsm7252ps.json`` is a committed real-hardware capture (see
    ``tests/fixtures/captures/gsm7252ps.json``'s own ``note``) that, until
    now, no test ever read -- an orphaned fixture. Unlike the M4300 seeds
    (literal transcriptions of their own captures -- see
    ``tests/virtual/test_m4300_seeds.py``, which uses the strict, generic
    ``capture_parity.assert_seed_matches_capture`` for those), ``seed_gsm7252ps``
    is explicitly documented (see its own docstring in ``virtual/seed.py``) as
    a HAND-AUTHORED illustrative seed, not a transcription of any one capture.
    Running it through that same strict per-key helper would fail loudly and
    dishonestly: this specific real capture is a live, in-service 52-port unit
    whose per-port link state, PoE load, sensor readings and management IP are
    simply a different real device's snapshot in time, not a ground truth the
    illustrative seed ever claimed to reproduce (confirmed empirically: most
    per-port link/speed/description and every PoE/sensor/mgmt-IP value differ).

    What genuinely IS shared between the two -- and clearly the actual
    inspiration for the seed's "iot"/VLAN-90 example -- is the VLAN 90 "iot"
    concept itself: named "iot" in both, with ports 1 and 2 both untagged
    members carrying PVID 90. This test pins exactly that genuine overlap
    (fixing the orphan by actually reading and using the capture), without
    the dishonesty of claiming full reproduction the seed's own docstring
    never claimed.
    """
    capture = load_capture_snapshot(_GSM7252PS_CAPTURE)
    state = seed_gsm7252ps()

    real_vlan_90 = next(v for v in capture["vlans"] if v["vlan_id"] == 90)
    assert real_vlan_90["name"] == "iot"
    assert state.vlans[90].name == "iot"

    for port in (1, 2):
        assert port in real_vlan_90["member_ports"]
        assert port in real_vlan_90["untagged_ports"]
        assert port in state.vlans[90].member
        assert port in state.vlans[90].untagged

    real_pvids = dict(capture["pvids"])
    assert real_pvids[1] == real_pvids[2] == 90
    assert state.pvids[1] == state.pvids[2] == 90

    # Structural (not per-value) PoE/sensor facts that DO hold: same PoE port
    # count, and fan slot "1" reports no numeric value in either (the seed's
    # "Not Supported" placeholder; the real capture simply omits that slot).
    assert len(state.poe) == 48 == len(capture["poe"])
    real_fan_instances = {
        s["name"][len(s["kind"]):] for s in capture["sensors"] if s["kind"] == "fan"
    }
    assert "1" not in real_fan_instances
    fan1 = next(s for s in state.sensors if s.kind == "fan" and s.instance == "1")
    assert fan1.raw == "Not Supported"
