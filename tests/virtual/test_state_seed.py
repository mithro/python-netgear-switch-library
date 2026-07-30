# tests/virtual/test_state_seed.py
from __future__ import annotations

from pathlib import Path

from capture_parity import assert_seed_matches_capture, load_capture_snapshot
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
    assert any(k.startswith(poe_base) and int(v[1]) > 0 for k, v in m.items())


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
        rows(oids.IP_ADENT_ADDR),
        rows(oids.IP_ADENT_NETMASK),
        rows(oids.IP_ROUTE_DEST),
        rows(oids.IP_ROUTE_NEXTHOP),
        rows(oids.vendor_oids(get_model("gsm7252ps")).dhcp_mode_unverified),
        rows(oids.DOT1D_BASE_BRIDGE_ADDRESS),
    )
    assert mgmt.address == "10.1.5.22"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"  # captured System MAC


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
        in_octets=rows(oids.IF_HC_IN_OCTETS),
        out_octets=rows(oids.IF_HC_OUT_OCTETS),
        in_ucast=rows(oids.IF_HC_IN_UCAST),
        out_ucast=rows(oids.IF_HC_OUT_UCAST),
        in_errors=rows(oids.IF_IN_ERRORS),
        out_errors=rows(oids.IF_OUT_ERRORS),
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
        rows(oids.IF_ADMIN_STATUS),
        rows(oids.IF_OPER_STATUS),
        rows(oids.IF_HIGH_SPEED),
        rows(oids.IF_NAME),
        rows(oids.IF_ALIAS),
    )
    # 52 physical ports + the two non-physical interfaces the seed carries
    # from the capture (ifIndex 417 CPU, 418 lag 1) -- SNMP reports every
    # ifIndex; only the web UI is limited to physical ports.
    assert len(ports) == 54
    port1 = next(p for p in ports if p.port == 1)
    assert port1.admin_enabled is True
    assert port1.link_up is True
    assert port1.speed_mbps == 1000
    assert port1.description == "eth0.rpi5-pmod"  # captured ifAlias
    # 1/0/6 is admin-up but link-down on the captured switch, and has no
    # ifAlias configured -- the absent-instance path for both columns.
    port6 = next(p for p in ports if p.port == 6)
    assert port6.link_up is False
    assert port6.description is None

    pvids = parse.parse_pvids(rows(oids.DOT1Q_PVID))
    assert len(pvids) == 52
    assert (1, 90) in pvids

    poe = parse.parse_poe(rows(oids.PETH_PSE_PORT_TABLE), rows(v.poe_power_mw))
    assert len(poe) == 48
    poe1 = next(p for p in poe if p.port == 1)
    assert poe1.delivering is True
    assert poe1.power_mw == 3_500  # captured live draw

    sensors = parse.parse_box_sensors(
        [
            ("fan", "RPM", rows(v.box_fan)),
            ("power", "W", rows(v.box_psu_power)),
            ("temperature", "C", rows(v.box_temp)),
        ]
    )
    # The SNMP face reports exactly the captured box sensors: two fan RPMs and
    # four PSU wattages -- and NO temperature (that sensor lives only on the
    # HTTP sysInfo page for this device). Matches captures/gsm7252ps.json.
    assert {(s.name, s.value) for s in sensors} == {
        ("fan0", 2850.0),
        ("fan2", 2350.0),
        ("power0", 49.0),
        ("power1", 30.0),
        ("power2", 32.0),
        ("power3", 31.0),
    }
    assert {s.kind for s in sensors} == {"fan", "power"}


def test_seed_gsm7252ps_matches_capture_strictly():
    """``seed_gsm7252ps`` is a LITERAL transcription of the committed
    real-hardware capture ``tests/fixtures/captures/gsm7252ps.json`` -- exactly
    like the M4300 seeds -- so it is held to the same strict, generic per-key
    parity helper the M4300 seeds use (see ``tests/virtual/test_m4300_seeds.py``
    and ``capture_parity.assert_seed_matches_capture``). Every port
    (name/admin/link/speed/ifAlias), every PVID, all 14 VLANs' member+untagged
    ifIndex sets, all 48 PoE ports (admin/detect/power), the box SENSORS the
    SNMP face reports, and the management IP/base-MAC are checked against the
    capture in one pass.

    Documented carve-outs (each a genuine property of this device, not a
    fudge):

    * The SENSOR check covers the SNMP face's ``state.sensors`` only (fan RPM +
      PSU watts). This switch's web UI exposes a DIFFERENT set -- temperatures +
      fan/PSU health -- carried in ``state.http_sensors`` and validated against
      the HTTP capture in ``test_virtual_http_face`` /
      ``test_cross_backend_equivalence``, not against this SNMP capture.
    * The harness deliberately excludes the volatile MAC/FDB, LLDP and per-port
      byte/packet counters (see its module docstring); the seed's MAC/LLDP rows
      are deliberate regression traps, not transcriptions, and are covered
      separately in ``test_seed_emits_nonempty_stats_macs_lldp``. Per-port
      counters ARE transcribed and are pinned below.
    """
    assert_seed_matches_capture(seed_gsm7252ps(), _GSM7252PS_CAPTURE)


def test_seed_gsm7252ps_stats_match_capture():
    """Per-port byte/packet counters are transcribed from the capture too
    (the generic harness skips them as generally-volatile, but this seed IS a
    snapshot of this exact fixed fixture, so pinning them is deterministic).
    Checked one-way: every physical port the seed carries counters for matches
    the capture; the two non-physical placeholders (CPU 417, lag 418) are not
    required to."""
    capture = load_capture_snapshot(_GSM7252PS_CAPTURE)
    real = {s["port"]: s for s in capture["stats"]}
    state = seed_gsm7252ps()
    checked = 0
    for port, sim in state.ports.items():
        if sim.rx_octets is None:
            continue  # CPU/lag placeholders carry no seeded counters
        r = real[port]
        assert (sim.rx_octets, sim.tx_octets, sim.rx_ucast, sim.tx_ucast) == (
            r["rx_bytes"],
            r["tx_bytes"],
            r["rx_packets"],
            r["tx_packets"],
        ), f"port {port} counters"
        checked += 1
    assert checked == 52  # all 52 physical ports pinned


def test_seed_gsm7252ps_iot_vlan_90_matches_capture():
    """A focused spot-check of the seed's "iot"/VLAN-90 example against the
    capture: ports 1 and 2 are untagged members carrying PVID 90 on both."""
    capture = load_capture_snapshot(_GSM7252PS_CAPTURE)
    state = seed_gsm7252ps()

    real_vlan_90 = next(v for v in capture["vlans"] if v["vlan_id"] == 90)
    assert real_vlan_90["name"] == "iot" == state.vlans[90].name
    for port in (1, 2):
        assert port in real_vlan_90["untagged_ports"]
        assert port in state.vlans[90].untagged
    assert dict(capture["pvids"])[1] == state.pvids[1] == 90
    assert dict(capture["pvids"])[2] == state.pvids[2] == 90


def test_seed_emits_real_fixed_vlan_portlist_width():
    """Every VLAN's egress/untagged PortList is the device's REAL fixed byte
    width, LIVE-measured read-only on each switch, NOT the physical-port-only
    vlan_bitmap_width(). This is what makes the mock an independent source of
    truth for the wire width (github issue #3): the historical writer bug --
    re-encoding the decoded member set at max(8, port_count/8) -- sent a SET
    narrower than this, which the mock now models faithfully so a round-trip
    test can catch it.

    Widths: gsm7252ps=79B @10.1.5.22, m4300-24x=131B @10.1.5.13,
    m4300-16x=131B @10.1.5.20 (dot1qVlanStaticEgressPorts, community public).
    """
    from netgear_switch.virtual.seed import (
        seed_gsm7252ps,
        seed_m4300_16x,
        seed_m4300_24x,
    )

    for seed, expected in (
        (seed_gsm7252ps, 79),
        (seed_m4300_24x, 131),
        (seed_m4300_16x, 131),
    ):
        state = seed()
        m = state.oid_map()
        egress = [
            v for k, v in m.items() if k.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS + ".")
        ]
        untagged = [
            v
            for k, v in m.items()
            if k.startswith(oids.DOT1Q_VLAN_STATIC_UNTAGGED + ".")
        ]
        assert egress, f"{seed.__name__}: no VLAN egress rows emitted"
        for _typ, value in egress + untagged:
            raw = value if isinstance(value, (bytes, bytearray)) else value.encode(
                "latin-1"
            )
            assert len(raw) == expected, (
                f"{seed.__name__}: PortList {len(raw)}B, expected fixed {expected}B"
            )
