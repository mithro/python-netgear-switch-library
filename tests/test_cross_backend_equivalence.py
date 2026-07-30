"""Cross-backend equivalence: a switch reachable over two backends must report
the SAME data through both.

The user requirement (2026-07-21): "Any functionality supportable via both HTTP
and NSDP must be supported by both, and the output cross-verified against each
other." This drives both faces of one ``VirtualSwitch`` from a single shared
``VirtualSwitchState``, then asserts the HTTP reader and the NSDP reader return
equal ports / PVIDs / VLANs / mgmt-IP.

Only the fields BOTH protocols expose are compared: NSDP ``PORT_STATUS`` carries
no port name and cannot distinguish admin-down from link-down (``nsdp_read``
reports ``admin_enabled=True``, ``name=None``), so port equality is on
``(link_up, speed_mbps)``; VLAN equality is on the member/tagged/untagged sets
(neither backend's VLAN name is compared -- both are ``None`` here anyway).
A real HTTP<->NSDP diff against live hardware is the same comparison run against
``10.1.5.25``; it is not a CI test because that switch rate-limits NSDP hard
(see the live-hardware memory notes)."""

from __future__ import annotations

import math

import pytest

from http_specs import reads_verified
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.http_read import HttpReader
from netgear_switch.nsdp_read import NsdpReader
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.virtual.server import VirtualSwitch


class _StateNsdpClient:
    """An NSDP read client answering from a ``VirtualSwitchState`` in-memory
    (the state's own ``nsdp_tlvs`` builder -- the same one the UDP NSDP face
    serves), so the NSDP and HTTP readers observe one identical device state
    without juggling the privileged NSDP UDP ports."""

    def __init__(self, state: object) -> None:
        self._state = state

    def read(self, tags: object) -> NSDPPacket:
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=self._state.nsdp_mac,  # type: ignore[attr-defined]
        )
        for tlv in self._state.nsdp_tlvs(set(tags)):  # type: ignore[attr-defined]
            pkt.add_tlv(tlv.tag, tlv.value)
        return pkt


def _port_pairs(ports: object) -> dict[int, tuple[bool, int | None]]:
    return {p.port: (p.link_up, p.speed_mbps) for p in ports}  # type: ignore[attr-defined]


def _vlan_sets(
    vlans: object,
) -> dict[int, tuple[frozenset[int], frozenset[int], frozenset[int]]]:
    return {  # type: ignore[attr-defined]
        v.vlan_id: (v.member_ports, v.tagged_ports, v.untagged_ports) for v in vlans
    }


def _stats_pairs(stats: object) -> dict[int, tuple[int | None, int | None]]:
    return {s.port: (s.rx_bytes, s.tx_bytes) for s in stats}  # type: ignore[attr-defined]


@pytest.mark.parametrize("model_key", ["gs110emx", "gs105pe"])
def test_http_and_nsdp_reads_agree(model_key: str) -> None:
    """Every model reachable over BOTH NSDP and HTTP must report the same data
    through both. gs105pe is included because its HTTP face once silently
    reported every port down while the seed had two ports up.

    (gs305ep is NOT parametrized here because two of these ops are genuine
    per-backend differences on that model -- HTTP has no mgmt-IP page and NSDP
    has no PoE op -- so it gets its own test,
    ``test_gs305ep_http_and_nsdp_reads_agree``, that pins those differences.)"""
    model = get_model(model_key)
    sw = VirtualSwitch(model=model_key)
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        http = HttpReader(client, model)
        nsdp = NsdpReader(_StateNsdpClient(sw.state), model)
        try:
            assert _port_pairs(http.get_ports()) == _port_pairs(nsdp.get_ports())
            assert dict(http.get_pvids()) == dict(nsdp.get_pvids())
            assert _vlan_sets(http.get_vlans()) == _vlan_sets(nsdp.get_vlans())
            # byte counters must agree too (previously never cross-verified)
            assert _stats_pairs(http.get_stats()) == _stats_pairs(nsdp.get_stats())
            hm, nm = http.get_mgmt_ip(), nsdp.get_mgmt_ip()
            assert (hm.address, hm.netmask, hm.gateway, hm.base_mac, hm.mode) == (
                nm.address,
                nm.netmask,
                nm.gateway,
                nm.base_mac,
                nm.mode,
            )
            assert http.get_ports()
            assert http.get_vlans()
        finally:
            client.close()
    finally:
        sw.stop()


def test_m4300_http_and_snmp_reads_agree() -> None:
    """The M4300 is reachable over BOTH SNMP and HTTP, so the two must report
    the same ports/PVIDs/VLAN-ids/base-MAC for one switch. Live against
    10.1.5.13 this comparison showed ZERO mismatches across 24 ports and 24
    PVIDs; this runs the same comparison deterministically against the mock.

    Only protocol-common ground is compared: this web UI reports FRAME counts
    (never octets) so byte counters are not comparable, and its VLAN page
    cannot distinguish tagged from untagged, so only VLAN IDs are compared.
    """
    from netgear_switch.snmp_read import SnmpReader
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    model = get_model("m4300-24x")
    sw = VirtualSwitch(model="m4300-24x")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        http = HttpReader(client, model)
        snmp = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
        try:
            http_ports = _port_pairs(http.get_ports())
            snmp_ports = _port_pairs(snmp.get_ports())
            # EXACT port-set equality: the mock SNMP face emits ifType, so
            # get_ports drops the seed's LAG/CPU/VLAN interfaces exactly as the
            # HTTP page does. (An intersection here previously MASKED the mock's
            # phantom-port over-report -- see the ifType physical-port filter.)
            assert set(http_ports) == set(snmp_ports), "port set differs"
            for port in sorted(http_ports):
                assert http_ports[port] == snmp_ports[port], f"port {port} differs"

            http_pvids, snmp_pvids = dict(http.get_pvids()), dict(snmp.get_pvids())
            assert set(http_pvids) == set(snmp_pvids), "pvid port set differs"
            for port in sorted(http_pvids):
                assert http_pvids[port] == snmp_pvids[port], f"pvid {port} differs"

            assert {v.vlan_id for v in http.get_vlans()} == {
                v.vlan_id for v in snmp.get_vlans()
            }
            assert http.get_mgmt_ip().base_mac == snmp.get_mgmt_ip().base_mac

            # Sensors: the HTTP page exposes only temperatures (fans are a
            # non-numeric OK/Fail this model cannot represent), so compare the
            # temperature readings both backends report. This once silently
            # returned [] because the mock rendered a numeric label the parser
            # could never match.
            http_temps = {
                (s.name, s.value) for s in http.get_sensors() if s.kind == "temperature"
            }
            snmp_temps = {
                s.value for s in snmp.get_sensors() if s.kind == "temperature"
            }
            assert http_temps, "HTTP reported no temperature sensors"
            assert {v for _n, v in http_temps} <= snmp_temps
        finally:
            client.close()
    finally:
        sw.stop()


def test_gs305ep_http_and_nsdp_reads_agree() -> None:
    """gs305ep (a {NSDP, HTTP} PoE switch) cross-verified with STRICT field
    equality on every op BOTH backends expose -- ports/PVIDs/VLANs/stats -- and
    TWO genuine per-backend differences pinned EXPLICITLY (not silently
    tolerated), which is exactly why gs305ep is not in the shared parametrized
    NSDP<->HTTP test:

    1. PoE is HTTP-only: the web UI serves per-port PoE status, but NSDP has NO
       PoE read op (NsdpReader.get_poe raises). Both sides pinned.
    2. mgmt-IP is NSDP-only: gs305ep's web UI exposes no system-info/mgmt-IP
       page (sysinfo_path is None), so HttpReader.get_mgmt_ip raises, while NSDP
       reports it. Both sides pinned.
    """
    model = get_model("gs305ep")
    sw = VirtualSwitch(model="gs305ep")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        http = HttpReader(client, model)
        nsdp = NsdpReader(_StateNsdpClient(sw.state), model)
        try:
            # Shared ops: STRICT equality (fields both protocols expose).
            assert _port_pairs(http.get_ports()) == _port_pairs(nsdp.get_ports())
            assert dict(http.get_pvids()) == dict(nsdp.get_pvids())
            assert _vlan_sets(http.get_vlans()) == _vlan_sets(nsdp.get_vlans())
            assert _stats_pairs(http.get_stats()) == _stats_pairs(nsdp.get_stats())
            assert http.get_ports()
            assert http.get_vlans()

            # Difference 1 -- PoE is HTTP-only. HTTP returns real rows; NSDP
            # RAISES (never a silent []).
            http_poe = http.get_poe()
            assert http_poe, "HTTP must serve real PoE rows for gs305ep"
            assert any(p.admin_enabled for p in http_poe)
            with pytest.raises(UnsupportedCapabilityError):
                nsdp.get_poe()

            # Difference 2 -- mgmt-IP is NSDP-only. NSDP returns it; HTTP RAISES
            # (this UI has no mgmt-IP page -- never a fabricated value).
            assert nsdp.get_mgmt_ip().address
            with pytest.raises(UnsupportedCapabilityError):
                http.get_mgmt_ip()
        finally:
            client.close()
    finally:
        sw.stop()


def test_m4300_16x_http_and_snmp_reads_agree() -> None:
    """The M4300-16X is reachable over BOTH SNMP and HTTP -- mirror of
    ``test_m4300_http_and_snmp_reads_agree`` (24X) for the 16X SKU, which had
    NO cross-backend test. Same protocol-common ground: this web UI reports
    FRAME counts (never octets) and its VLAN page cannot distinguish tagged
    from untagged, so only VLAN IDs are compared.

    PoE is compared field-for-field (admin/detect/power_mw): the 16X HTTP spec
    now reads the real /v1/poeInterfaceConfiguration.html (HTTPS:49152, SIDSSL),
    live cross-verified against SNMP on the real 16X (10.1.5.20) -- see
    endpoints.py's reads_verified=True note.
    """
    from netgear_switch.snmp_read import SnmpReader
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    model = get_model("m4300-16x")
    sw = VirtualSwitch(model="m4300-16x")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        # m4300-16x HTTP ships reads_verified=False (the real 16X FASTPATH web UI
        # is HTTPS-on-49152, unlike this inherited-from-24X http:80 spec -- see
        # endpoints.py). This is a MOCK parity test (the virtual HTTP face serves
        # the seed regardless), so force the flag to exercise the parsers.
        with reads_verified("m4300-16x"):
            http = HttpReader(client, model)
        snmp = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
        try:
            http_ports = _port_pairs(http.get_ports())
            snmp_ports = _port_pairs(snmp.get_ports())
            # EXACT port-set equality: the mock SNMP face emits ifType, so
            # get_ports drops the seed's LAG/CPU/VLAN interfaces exactly as the
            # HTTP page does. (An intersection here previously MASKED the mock's
            # phantom-port over-report -- see the ifType physical-port filter.)
            assert set(http_ports) == set(snmp_ports), "port set differs"
            for port in sorted(http_ports):
                assert http_ports[port] == snmp_ports[port], f"port {port} differs"

            http_pvids, snmp_pvids = dict(http.get_pvids()), dict(snmp.get_pvids())
            assert set(http_pvids) == set(snmp_pvids), "pvid port set differs"
            for port in sorted(http_pvids):
                assert http_pvids[port] == snmp_pvids[port], f"pvid {port} differs"

            assert {v.vlan_id for v in http.get_vlans()} == {
                v.vlan_id for v in snmp.get_vlans()
            }
            assert http.get_mgmt_ip().base_mac == snmp.get_mgmt_ip().base_mac

            # Sensors: like the 24X, the HTTP page exposes temperatures; compare
            # the temperature readings both backends can represent.
            http_temps = {
                (s.name, s.value) for s in http.get_sensors() if s.kind == "temperature"
            }
            snmp_temps = {
                s.value for s in snmp.get_sensors() if s.kind == "temperature"
            }
            assert http_temps, "HTTP reported no temperature sensors"
            assert {v for _n, v in http_temps} <= snmp_temps

            # PoE: the 16X genuinely HAS 16 PSE ports, and (unlike the earlier
            # inherited-24X spec that had no PoE page) HTTP now reads the real
            # /v1/poeInterfaceConfiguration.html. Both backends must agree on
            # admin state, detect and power_mw -- the last live-verified on the
            # real 16X (HTTP "4.60" W == SNMP 4600 mW). This is the parity that
            # the watts->mW fix and the M4300 PoE dispatch exist to guarantee.
            http_poe = {p.port: p for p in http.get_poe()}
            snmp_poe = {p.port: p for p in snmp.get_poe()}
            assert set(http_poe) == set(snmp_poe), "PoE port set differs"
            assert http_poe, "16X must report its real PoE ports"
            for port, hp in http_poe.items():
                sp = snmp_poe[port]
                assert (hp.admin_enabled, hp.detect, hp.power_mw) == (
                    sp.admin_enabled,
                    sp.detect,
                    sp.power_mw,
                ), f"PoE port {port} differs"
        finally:
            client.close()
    finally:
        sw.stop()


def test_gs110emx_http_and_nsdp_reads_agree() -> None:
    model = get_model("gs110emx")
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        http = HttpReader(client, model)
        nsdp = NsdpReader(_StateNsdpClient(sw.state), model)
        try:
            # ports: (link_up, speed_mbps) -- the fields both protocols expose
            assert _port_pairs(http.get_ports()) == _port_pairs(nsdp.get_ports())
            # PVIDs
            assert dict(http.get_pvids()) == dict(nsdp.get_pvids())
            # VLANs: member/tagged/untagged sets, keyed by VID
            assert _vlan_sets(http.get_vlans()) == _vlan_sets(nsdp.get_vlans())
            # mgmt-IP: every field both backends report
            hm = http.get_mgmt_ip()
            nm = nsdp.get_mgmt_ip()
            assert (hm.address, hm.netmask, hm.gateway, hm.base_mac, hm.mode) == (
                nm.address,
                nm.netmask,
                nm.gateway,
                nm.base_mac,
                nm.mode,
            )
            # the cross-check is only meaningful if it actually read something
            assert http.get_ports()
            assert http.get_vlans()
        finally:
            client.close()
    finally:
        sw.stop()


def test_m4300_mock_enforces_referer_csrf_guard() -> None:
    """The real M4300 /v1 UI answers 403 to any request lacking a Referer, and
    the mock must reproduce that -- otherwise a transport regression dropping
    the header would pass CI silently. The library's HttpClient sends it, so
    the reader above works; here we prove the guard is actually enforced."""
    import httpx

    sw = VirtualSwitch(model="m4300-24x")
    sw.start()
    try:
        base = f"http://127.0.0.1:{sw.http_port}"
        assert httpx.get(f"{base}/v1/portsConfiguration.html").status_code == 403
        ok = httpx.get(
            f"{base}/v1/portsConfiguration.html", headers={"Referer": f"{base}/"}
        )
        assert ok.status_code == 200
    finally:
        sw.stop()


def test_gsm7252ps_http_and_snmp_reads_agree() -> None:
    """The gsm7252ps is reachable over BOTH SNMP and HTTP, so both must report
    the same switch. This drives both faces of ONE VirtualSwitch whose state is
    transcribed from the real 10.1.5.22 captures, and compares every read op
    the two protocols share.

    Where they legitimately differ, the difference is asserted rather than
    papered over:
    - the web UI lists only PHYSICAL ports, SNMP every ifIndex, so ports/PVIDs
      are compared on the intersection;
    - VLAN membership is compared on physical ports only (the egress page
      renders aggregations as "lag N", which are not ports);
    - portStatistics.html has no octet column, so counters are compared as
      PACKETS;
    - the PoE page's fault TEXT is richer than RFC3621's detect enum (the real
      switch reports "Other Fault" where SNMP's code is outside 1-4 and reads
      UNKNOWN), so detect is compared only where SNMP knows it;
    - sysInfo.html has no DHCP indicator or gateway row, so mgmt-IP is compared
      on address/netmask/base-MAC;
    - the two interfaces expose DIFFERENT box sensors (SNMP: fan RPM + PSU
      watts, no temperature; HTTP sysInfo: temperatures + fan/PSU health text),
      so each face's real sensor set is pinned rather than cross-asserted.
    """
    from netgear_switch.models import PoEDetect
    from netgear_switch.snmp_read import SnmpReader
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    model = get_model("gsm7252ps")
    with reads_verified("gsm7252ps"):
        sw = VirtualSwitch(model="gsm7252ps")
        sw.start()
        try:
            client = HttpClient(
                f"127.0.0.1:{sw.http_port}", "password", http_spec(model)
            )
            client.login()
            http = HttpReader(client, model)
            snmp = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
            try:
                http_ports = _port_pairs(http.get_ports())
                snmp_ports = _port_pairs(snmp.get_ports())
                assert len(http_ports) == 52  # physical ports only
                # EXACT equality: the mock SNMP face emits ifType, so get_ports
                # drops the seed's CPU(417)/LAG(418) interfaces exactly as the
                # web UI does -- no phantom ports. (Was an intersection, which
                # masked the over-report.)
                assert set(http_ports) == set(snmp_ports)
                # STRICT: link AND speed must match field-for-field now. A DOWN
                # port has no operational speed on EITHER backend -- the SNMP
                # parser maps a down port's lingering ifHighSpeed to None (see
                # snmp.parse.parse_port_status), matching the web UI's
                # "Unknown"->None.
                for port in sorted(http_ports):
                    assert http_ports[port] == snmp_ports[port], f"port {port}"

                http_pvids, snmp_pvids = dict(http.get_pvids()), dict(snmp.get_pvids())
                assert set(http_pvids) == set(snmp_pvids)
                assert len(http_pvids) == 52
                for port in sorted(http_pvids):
                    assert http_pvids[port] == snmp_pvids[port], f"pvid {port} differs"

                # the once-divergent down port (1/0/52) now agrees on both
                assert http_ports[52] == (False, None)
                assert snmp_ports[52] == (False, None)

                http_vlans = {v.vlan_id: v for v in http.get_vlans()}
                snmp_vlans = {v.vlan_id: v for v in snmp.get_vlans()}
                assert set(http_vlans) == set(snmp_vlans)
                for vid, v in http_vlans.items():
                    physical = {p for p in snmp_vlans[vid].member_ports if p <= 52}
                    assert v.member_ports == physical, f"VLAN {vid} members differ"

                http_stats = {s.port: s for s in http.get_stats()}
                snmp_stats = {s.port: s for s in snmp.get_stats()}
                # EXACT stats port-set equality too: mock SNMP get_stats now
                # filters non-physical interfaces via ifType (was intersection).
                assert set(http_stats) == set(snmp_stats)
                for port in sorted(http_stats):
                    h, s = http_stats[port], snmp_stats[port]
                    assert (h.rx_packets, h.tx_packets) == (s.rx_packets, s.tx_packets)
                    assert h.rx_bytes is None  # this page reports no octets

                http_poe = {p.port: p for p in http.get_poe()}
                snmp_poe = {p.port: p for p in snmp.get_poe()}
                assert set(http_poe) == set(snmp_poe) == set(range(1, 49))
                for port, hp in http_poe.items():
                    sp = snmp_poe[port]
                    assert (hp.admin_enabled, hp.power_mw) == (
                        sp.admin_enabled,
                        sp.power_mw,
                    )
                    if sp.detect is not PoEDetect.UNKNOWN:
                        assert hp.detect is sp.detect, f"PoE {port} detect differs"
                # the real switch has exactly one such port (1/0/6, "Other
                # Fault"): HTTP names the fault, SNMP's enum cannot
                assert http_poe[6].detect is PoEDetect.FAULT
                assert snmp_poe[6].detect is PoEDetect.UNKNOWN

                assert {(m.mac, m.port, m.vlan_id) for m in http.get_macs()} == {
                    (m.mac, m.port, m.vlan_id) for m in snmp.get_macs()
                }

                assert [
                    (
                        n.local_port,
                        n.remote_sys_name,
                        n.remote_chassis_id,
                        n.remote_port_id,
                    )
                    for n in http.get_lldp()
                ] == [
                    (
                        n.local_port,
                        n.remote_sys_name,
                        n.remote_chassis_id,
                        n.remote_port_id,
                    )
                    for n in snmp.get_lldp()
                ]

                # Sensors: the two interfaces expose DIFFERENT real sensor
                # sets on this device, so this pins the difference rather than
                # asserting a fake agreement. SNMP reports numeric fan RPM + PSU
                # watts and NO temperature; the HTTP sysInfo page reports
                # temperatures (System/CPU/MAC-A/MAC-B) plus fan/PSU HEALTH
                # flags (unit "state") and no RPM/watt readings. Both match
                # their own captures (see gsm7252ps.json vs gsm7252ps_sysInfo.html).
                snmp_sensors = snmp.get_sensors()
                assert {(s.name, s.value) for s in snmp_sensors} == {
                    ("fan0", 2850.0),
                    ("fan2", 2350.0),
                    ("power0", 49.0),
                    ("power1", 30.0),
                    ("power2", 32.0),
                    ("power3", 31.0),
                }
                assert not [s for s in snmp_sensors if s.kind == "temperature"]

                http_sensors = http.get_sensors()
                http_temps = {
                    (s.name, s.value) for s in http_sensors if s.kind == "temperature"
                }
                assert http_temps == {
                    ("System", 29.0),
                    ("CPU", 49.0),
                    ("MAC-A", 32.0),
                    ("MAC-B", 31.0),
                }
                # the HTTP fan/PSU rows are health flags, never RPM/watts
                assert all(
                    s.unit == "state"
                    for s in http_sensors
                    if s.kind in ("fan", "power")
                )
                # ... so SNMP is the ONLY source of real fan RPM / PSU watts
                # here, and HTTP the only source of temperatures.
                assert {s.kind for s in snmp_sensors} == {"fan", "power"}
                assert {s.kind for s in http_sensors} == {
                    "temperature",
                    "fan",
                    "power",
                }

                hm, sm = http.get_mgmt_ip(), snmp.get_mgmt_ip()
                assert (hm.address, hm.netmask, hm.base_mac) == (
                    sm.address,
                    sm.netmask,
                    sm.base_mac,
                )
            finally:
                client.close()
        finally:
            sw.stop()


def test_gs728tpp_http_and_snmp_reads_agree() -> None:
    """The gs728tpp is reachable over BOTH SNMP and HTTP, so both must report
    the same switch. This is the model whose SNMP was BROKEN: registry.py wrongly
    put it on the S3300 vendor subtree (4526.11), but a real live walk (10.2.5.10)
    proved its agent implements ZERO Netgear vendor OIDs and serves EVERYTHING
    via standard MIBs (snmp_vendor_base=None). This drives both faces of one
    VirtualSwitch (seed transcribed from that capture + the HTTP ground truth)
    and cross-verifies every shared read op with STRICT field equality.

    ports / pvids / vlans / macs / lldp / mgmt-IP are IDENTICAL field-for-field
    (including LLDP chassis+port MACs, canonicalized uppercase in both parsers,
    and mgmt base_mac, which HTTP now reads from the SystemInfo page). PoE is
    identical on port+admin+detect. Only TWO fields are genuinely SNMP-absent
    (proven below, not silent tolerance): per-port PoE power_mw and the box
    sensors' live value/unit -- the switch's SNMP agent exposes neither.
    """
    from netgear_switch.protocols.snmp import oids
    from netgear_switch.snmp_read import SnmpReader
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    model = get_model("gs728tpp")
    # The crux of the fix: gs728tpp reads NO Netgear vendor OIDs.
    assert model.snmp_vendor_base is None
    assert oids.has_vendor_oids(model) is False

    sw = VirtualSwitch(model="gs728tpp")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", http_spec(model))
        client.login()
        http = HttpReader(client, model)
        snmp = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
        try:
            # ports: STRICT (link_up, speed_mbps) equality on all 28. A DOWN
            # port has no operational speed on EITHER backend (SNMP maps the
            # lingering ifHighSpeed to None -- see snmp.parse.parse_port_status).
            http_ports = {p.port: (p.link_up, p.speed_mbps) for p in http.get_ports()}
            snmp_ports = {p.port: (p.link_up, p.speed_mbps) for p in snmp.get_ports()}
            assert set(http_ports) == set(snmp_ports) == set(range(1, 29))
            assert http_ports == snmp_ports

            assert dict(http.get_pvids()) == dict(snmp.get_pvids())
            assert _vlan_sets(http.get_vlans()) == _vlan_sets(snmp.get_vlans())

            assert {(m.mac, m.port, m.vlan_id) for m in http.get_macs()} == {
                (m.mac, m.port, m.vlan_id) for m in snmp.get_macs()
            }

            # LLDP: STRICT field equality. Chassis AND port-id MACs are
            # canonicalized to upper-case in BOTH parsers (HTTP _canon_lldp_id /
            # SNMP _format_mac_octetstring), so there is no case difference.
            def _lldp(reader: object) -> list[tuple[object, ...]]:
                return [
                    (
                        n.local_port,
                        n.remote_sys_name,
                        n.remote_chassis_id,
                        n.remote_port_id,
                        n.remote_port_desc,
                    )
                    for n in reader.get_lldp()  # type: ignore[attr-defined]
                ]

            assert _lldp(http) == _lldp(snmp)
            # value pinned so a future case regression is caught, not hidden
            assert {n.remote_port_id for n in http.get_lldp()} == {
                "2C:CF:67:BB:49:A1",
                "00:0A:FA:24:28:D8",
                "00:0A:FA:24:28:D9",
                "00:0A:FA:24:28:DA",
            }

            # mgmt-IP: STRICT field equality including base_mac. The wcd IPConf
            # page has no MAC row, so HTTP get_mgmt_ip additionally reads the
            # SystemInfo page's DeviceBasicInfo/MacAddre -> same value the SNMP
            # dot1dBaseBridgeAddress reports.
            hm, sm = http.get_mgmt_ip(), snmp.get_mgmt_ip()
            assert (hm.address, hm.netmask, hm.gateway, hm.mode, hm.base_mac) == (
                sm.address,
                sm.netmask,
                sm.gateway,
                sm.mode,
                sm.base_mac,
            )
            assert hm.base_mac == "B0:39:56:77:54:29"

            # PoE: port + admin + detect are IDENTICAL. power_mw is the ONE
            # genuinely-absent PoE field over SNMP: pethPsePortTable
            # (1.3.6.1.2.1.105.1.1.1) has all 11 standard RFC-3621 columns and
            # NONE is per-port watts (col 11 = invalidSignatureCounter); only
            # aggregate pethMainPse power (105.1.3.1.1.2) exists, and this agent
            # exposes ZERO Netgear vendor OIDs. So SNMP power_mw = None is
            # correct and unavoidable, vs the web UI's live 0 mW on an idle port.
            http_poe = {p.port: p for p in http.get_poe()}
            snmp_poe = {p.port: p for p in snmp.get_poe()}
            assert set(http_poe) == set(snmp_poe) == set(range(1, 25))
            for port, hp2 in http_poe.items():
                sp2 = snmp_poe[port]
                assert (hp2.port, hp2.admin_enabled, hp2.detect) == (
                    sp2.port,
                    sp2.admin_enabled,
                    sp2.detect,
                ), f"PoE {port}"
            assert {p.power_mw for p in http_poe.values()} == {0}
            assert {p.power_mw for p in snmp_poe.values()} == {None}  # SNMP-absent

            # Sensors: NAME + KIND are now IDENTICAL across both backends (the
            # SNMP entPhysicalName is canonicalized to the web UI's PS labels).
            # The value/unit is the genuinely-SNMP-absent field: SNMP exposes
            # ONLY the ENTITY-MIB component inventory -- no live status/value
            # anywhere (ENTITY-SENSOR-MIB 99, ENTITY-STATE-MIB 131, and the
            # vendor 4526 tree ALL answer No Such Object), so value=NaN /
            # unit="inventory". The wcd DiagnosticsUnitList reports the live
            # health flag (value=1.0 / unit="state") for those same components.
            snmp_sensors = snmp.get_sensors()
            http_sensors = http.get_sensors()
            assert (
                {(s.name, s.kind) for s in snmp_sensors}
                == {(s.name, s.kind) for s in http_sensors}
                == {
                    ("Main PS", "power"),
                    ("Redundant PS", "power"),
                    ("Fan1", "fan"),
                    ("Fan2", "fan"),
                }
            )
            # value/unit: SNMP-absent (inventory, NaN) vs HTTP live (state, 1.0)
            assert all(
                s.unit == "inventory" and math.isnan(s.value) for s in snmp_sensors
            )
            assert all(s.unit == "state" and s.value == 1.0 for s in http_sensors)
        finally:
            client.close()
    finally:
        sw.stop()
