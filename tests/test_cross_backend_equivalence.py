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

import pytest

from http_specs import reads_verified
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
        v.vlan_id: (v.member_ports, v.tagged_ports, v.untagged_ports)
        for v in vlans
    }


def _stats_pairs(stats: object) -> dict[int, tuple[int | None, int | None]]:
    return {s.port: (s.rx_bytes, s.tx_bytes) for s in stats}  # type: ignore[attr-defined]


@pytest.mark.parametrize("model_key", ["gs110emx", "gs105pe"])
def test_http_and_nsdp_reads_agree(model_key: str) -> None:
    """Every model reachable over BOTH NSDP and HTTP must report the same data
    through both. gs105pe is included because its HTTP face once silently
    reported every port down while the seed had two ports up."""
    model = get_model(model_key)
    sw = VirtualSwitch(model=model_key)
    sw.start()
    try:
        client = HttpClient(
            f"127.0.0.1:{sw.http_port}", "password", http_spec(model)
        )
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
                nm.address, nm.netmask, nm.gateway, nm.base_mac, nm.mode,
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
        client = HttpClient(
            f"127.0.0.1:{sw.http_port}", "password", http_spec(model)
        )
        client.login()
        http = HttpReader(client, model)
        snmp = SnmpReader(NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model)
        try:
            http_ports = _port_pairs(http.get_ports())
            snmp_ports = _port_pairs(snmp.get_ports())
            common = set(http_ports) & set(snmp_ports)
            assert common, "no overlapping ports to compare"
            for port in sorted(common):
                assert http_ports[port] == snmp_ports[port], f"port {port} differs"

            http_pvids, snmp_pvids = dict(http.get_pvids()), dict(snmp.get_pvids())
            shared = set(http_pvids) & set(snmp_pvids)
            assert shared
            for port in sorted(shared):
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
                (s.name, s.value) for s in http.get_sensors()
                if s.kind == "temperature"
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


def test_gs110emx_http_and_nsdp_reads_agree() -> None:
    model = get_model("gs110emx")
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        client = HttpClient(
            f"127.0.0.1:{sw.http_port}", "password", http_spec(model)
        )
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
            snmp = SnmpReader(
                NetsnmpCliClient(f"{sw.host}:{sw.port}", "public"), model
            )
            try:
                http_ports = _port_pairs(http.get_ports())
                snmp_ports = _port_pairs(snmp.get_ports())
                assert len(http_ports) == 52  # physical ports only
                common = set(http_ports) & set(snmp_ports)
                assert len(common) == 52
                for port in sorted(common):
                    h_link, h_speed = http_ports[port]
                    s_link, s_speed = snmp_ports[port]
                    assert h_link == s_link, f"port {port} link differs"
                    # Speed is only comparable while the link is UP: SNMP's
                    # ifHighSpeed keeps reporting a DOWN port's configured rate
                    # (10000 on 1/0/52 in the real capture) while the web UI's
                    # Physical Status reads "Unknown" -> None. That is a real
                    # protocol difference on this device, not a parser bug.
                    if h_link:
                        assert h_speed == s_speed, f"port {port} speed differs"

                http_pvids, snmp_pvids = dict(http.get_pvids()), dict(snmp.get_pvids())
                shared = set(http_pvids) & set(snmp_pvids)
                assert len(shared) == 52
                for port in sorted(shared):
                    assert http_pvids[port] == snmp_pvids[port], f"pvid {port} differs"

                # pin that difference so it stays visible instead of silent
                assert http_ports[52] == (False, None)
                assert snmp_ports[52] == (False, 10000)

                http_vlans = {v.vlan_id: v for v in http.get_vlans()}
                snmp_vlans = {v.vlan_id: v for v in snmp.get_vlans()}
                assert set(http_vlans) == set(snmp_vlans)
                for vid, v in http_vlans.items():
                    physical = {p for p in snmp_vlans[vid].member_ports if p <= 52}
                    assert v.member_ports == physical, f"VLAN {vid} members differ"

                http_stats = {s.port: s for s in http.get_stats()}
                snmp_stats = {s.port: s for s in snmp.get_stats()}
                for port in sorted(set(http_stats) & set(snmp_stats)):
                    h, s = http_stats[port], snmp_stats[port]
                    assert (h.rx_packets, h.tx_packets) == (s.rx_packets, s.tx_packets)
                    assert h.rx_bytes is None  # this page reports no octets

                http_poe = {p.port: p for p in http.get_poe()}
                snmp_poe = {p.port: p for p in snmp.get_poe()}
                assert set(http_poe) == set(snmp_poe) == set(range(1, 49))
                for port, hp in http_poe.items():
                    sp = snmp_poe[port]
                    assert (hp.admin_enabled, hp.power_mw) == (
                        sp.admin_enabled, sp.power_mw,
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
                    (n.local_port, n.remote_sys_name, n.remote_chassis_id,
                     n.remote_port_id)
                    for n in http.get_lldp()
                ] == [
                    (n.local_port, n.remote_sys_name, n.remote_chassis_id,
                     n.remote_port_id)
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
                    ("fan0", 2850.0), ("fan2", 2350.0),
                    ("power0", 49.0), ("power1", 30.0),
                    ("power2", 32.0), ("power3", 31.0),
                }
                assert not [s for s in snmp_sensors if s.kind == "temperature"]

                http_sensors = http.get_sensors()
                http_temps = {
                    (s.name, s.value) for s in http_sensors
                    if s.kind == "temperature"
                }
                assert http_temps == {
                    ("System", 29.0), ("CPU", 49.0),
                    ("MAC-A", 32.0), ("MAC-B", 31.0),
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
                    "temperature", "fan", "power",
                }

                hm, sm = http.get_mgmt_ip(), snmp.get_mgmt_ip()
                assert (hm.address, hm.netmask, hm.base_mac) == (
                    sm.address, sm.netmask, sm.base_mac,
                )
            finally:
                client.close()
        finally:
            sw.stop()
