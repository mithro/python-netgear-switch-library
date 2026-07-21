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
