from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from http_specs import reads_verified
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.http_read import AsyncHttpReader, HttpReader
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.registry import get_model

_FIX = Path(__file__).parent / "fixtures" / "http"


class _FakeSession:
    """In-memory session returning captured fixtures per path.

    A page value may be a plain string OR a callable taking the POSTed form and
    returning the body. The callable form exists for the FASTPATH VLAN-Membership
    endpoint, which serves a DIFFERENT page per ``vlanId`` -- a fake that ignored
    the form would hand every VLAN the captured VLAN's membership, which is
    exactly the mislabelling the reader's wrong-VLAN guard exists to catch.
    """

    def __init__(self, pages: dict) -> None:
        self._pages = pages
        self.logged_in = False

    def login(self) -> None:
        self.logged_in = True

    def _resolve(self, path: str, data: dict[str, str] | None = None) -> str:
        page = self._pages[path]
        return page(data or {}) if callable(page) else page

    def get_page(self, path: str) -> str:
        return self._resolve(path)

    def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._resolve(path, data)


class _AsyncFakeSession(_FakeSession):
    async def login(self) -> None:  # type: ignore[override]
        self.logged_in = True

    async def get_page(self, path: str) -> str:  # type: ignore[override]
        return self._resolve(path)

    async def post_form(self, path: str, data: dict[str, str]) -> str:  # type: ignore[override]
        return self._resolve(path, data)


def _membership(*names: str):
    """A VLAN-Membership responder over the captured pages in ``names``.

    Keys the fixtures by the VLAN each capture actually shows, and serves the GET
    (no ``vlanId``) as the FIRST one -- which is what real firmware does: the GET
    renders whichever VLAN the session last selected. A VLAN with no capture
    raises ``KeyError`` rather than being faked, because inventing "VLAN N has no
    members" would let a membership regression pass.
    """
    from netgear_switch.protocols.http import parse

    bodies = [(_FIX / n).read_text() for n in names]
    by_vid = {parse.parse_fastpath_membership(b).vlan_id: b for b in bodies}

    def respond(data: dict[str, str]) -> str:
        requested = data.get("vlanId")
        if requested is None:
            return bodies[0]
        return by_vid[int(requested)]

    return respond


def _pages() -> dict[str, str]:
    return {
        "/dashboard.cgi": (_FIX / "gs305ep_dashboard.html").read_text(),
        "/portStatistics.cgi": (_FIX / "gs305ep_portstats.html").read_text(),
        "/getPoePortStatus.cgi": (_FIX / "gs305ep_poestatus.html").read_text(),
        "/portPVID.cgi": (_FIX / "gs305ep_pvid.html").read_text(),
        "/8021qCf.cgi": (_FIX / "gs305ep_vlancfg.html").read_text(),
        "/8021qMembe.cgi": (_FIX / "gs305ep_membership.html").read_text(),
    }


def test_get_ports_and_poe() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    ports = {p.port: p for p in reader.get_ports()}
    assert ports[1].link_up is True
    poe = {p.port: p for p in reader.get_poe()}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 12800


def test_get_pvids() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    assert dict(reader.get_pvids()) == {1: 90, 2: 1}


def test_get_stats() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    stats = {s.port: s for s in reader.get_stats()}
    assert stats[1].rx_bytes == 1000000
    assert stats[1].tx_bytes == 2000000
    assert stats[1].rx_errors == 0
    assert stats[2].rx_bytes == 500
    assert stats[2].tx_bytes == 750
    assert stats[2].rx_errors == 3


def test_get_vlans() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    vlans = {v.vlan_id: v for v in reader.get_vlans()}
    assert set(vlans) == {1, 90}
    vlan90 = vlans[90]
    assert vlan90.tagged_ports == frozenset({1})
    assert vlan90.untagged_ports == frozenset({2, 3})
    assert vlan90.member_ports == frozenset({1, 2, 3})


def test_mac_table_unsupported_on_plus() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_macs()
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_sensors()
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_lldp()


def _gsm7228ps_pages() -> dict[str, str]:
    return {
        "/portsConfiguration.html": (
            _FIX / "gsm7228ps_portsConfiguration.html"
        ).read_text(),
        "/portStatistics.html": (_FIX / "gsm7228ps_portStatistics.html").read_text(),
        "/poeInterfaceConfiguration.html": (
            _FIX / "gsm7228ps_poeInterfaceConfiguration.html"
        ).read_text(),
        "/vlanStatus.html": (_FIX / "gsm7228ps_vlanStatus.html").read_text(),
        "/portPvidConfiguration.html": (
            _FIX / "gsm7228ps_portPvidConfiguration.html"
        ).read_text(),
        "/basicAddressTable.html": (
            _FIX / "gsm7228ps_basicAddressTable.html"
        ).read_text(),
        "/lldpRemoteInventory.html": (
            _FIX / "gsm7228ps_lldpRemoteInventory.html"
        ).read_text(),
        "/base/system/management/sysInfo.html": (
            _FIX / "gsm7228ps_sysInfo.html"
        ).read_text(),
        # LIVE capture 2026-07-30 from 10.1.5.11. This page is why the old
        # "the S3300's mgmt IP is unreachable over HTTP" note was WRONG.
        "/ipConfiguration.html": (
            _FIX / "gsm7228ps_ipConfiguration.html"
        ).read_text(),
        # The VLAN-Membership page, captured 2026-07-30 -- only VLAN 5 was
        # captured on this switch, so get_vlans() (which needs all five VLANs)
        # is exercised against the MOCK instead; see
        # tests/test_http_vlan_membership.py.
        "/switching/dot1q/vlan_port_cfg.html": _membership(
            "gsm7228ps_vlanPortCfg_vlan5.html"
        ),
        "/switching/dot1q/vlan_port_cfg_rw.html": _membership(
            "gsm7228ps_vlanPortCfg_vlan5.html"
        ),
    }


def test_gsm7228ps_reads_are_grounded_not_refused() -> None:
    # gsm7228ps (S3300-52X) GRADUATED: its reads are grounded in real captures
    # (tests/fixtures/http/gsm7228ps_*.html) and cross-verified vs SNMP, so the
    # spec ships reads_verified=True and constructing a reader must succeed --
    # the same graduation gsm7252ps made. Ports/PVIDs/PoE/VLANs/LLDP/MACs are
    # served; sensors raise (SNMP-only on this model).
    reader = HttpReader(_FakeSession(_gsm7228ps_pages()), get_model("gsm7228ps"))
    assert {p.port for p in reader.get_ports()} == set(range(1, 53))
    assert len(reader.get_poe()) == 48
    # The VLAN LIST comes from vlanStatus.html; the per-VLAN tagged/untagged
    # split comes from the separate VLAN-Membership page, of which only VLAN 5
    # was captured on this switch -- so get_vlans() (which reads a membership
    # page per VLAN) is asserted against the mock in
    # tests/test_http_vlan_membership.py, and here we pin the two halves the
    # fixtures DO cover.
    from netgear_switch.protocols.http import parse as _parse

    vlan_status = (_FIX / "gsm7228ps_vlanStatus.html").read_text()
    assert {v.vlan_id for v in _parse.parse_s3300_vlans(vlan_status)} == {
        1,
        5,
        21,
        121,
        4089,
    }
    member5 = reader.read_fastpath_membership(5)
    assert member5.tagged_ports == frozenset({49, 50, 51, 52})
    assert member5.untagged_ports == frozenset({41})
    assert len(reader.get_macs()) == 17  # base MAC on CPU "c1" is skipped
    # CORRECTION (live 2026-07-30, 10.1.5.11): this model's mgmt IP is NOT
    # "unreachable over HTTP". /ipConfiguration.html serves the real address,
    # mask, gateway and addressing method; only the base MAC comes from sysInfo.
    mgmt = reader.get_mgmt_ip()
    assert mgmt.address == "10.1.5.11"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.mode is IpMode.DHCP
    assert mgmt.base_mac == "08:BD:43:6B:B8:D8"
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_sensors()  # S3300 sysInfo has no live fan/temp table


def _gs110emx_pages() -> dict[str, str]:
    return {
        "/iss/specific/sysInfo.html": (_FIX / "gs110emx_sysinfo.html").read_text(),
        "/iss/specific/interface_stats.html": (
            _FIX / "gs110emx_interface_stats.html"
        ).read_text(),
        "/iss/specific/port_settings.html": (
            _FIX / "gs110emx_port_settings.html"
        ).read_text(),
        "/iss/specific/vlan_pvidsetting.html": (
            _FIX / "gs110emx_pvid.html"
        ).read_text(),
        "/iss/specific/Cf8021q.html": (_FIX / "gs110emx_cf8021q.html").read_text(),
        # The fake session returns this same VLAN-1 membership page for every
        # VLAN_ID POST (only VLAN 1's membership was captured live -- see the
        # per-VLAN-select live gap in the memory notes); the flow + parser are
        # what this exercises.
        "/iss/specific/vlanMembership.html": (
            _FIX / "gs110emx_vlanmembership.html"
        ).read_text(),
    }


def test_gs110emx_reads_are_grounded_not_refused() -> None:
    # Login + sysInfo/interface_stats are GROUNDED in a real capture (see
    # protocols/http/endpoints.py), so constructing an HttpReader must
    # succeed (contrast gsm7228ps above, still UNVERIFIED).
    HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))


def test_gs110emx_get_stats_uses_real_hardware_row_shape() -> None:
    """gs110emx_interface_stats.html: real hardware never closes a
    ``<tr class="portID">`` with ``</tr>`` -- parse_interface_stats (not
    gs305ep's parse_port_stats) must be used, or this raises/mis-parses."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    stats = {s.port: s for s in reader.get_stats()}
    assert stats[1].rx_bytes == 0
    assert stats[1].tx_bytes == 0
    assert stats[6].tx_bytes == 70892018242
    assert stats[8].rx_bytes == 59921732691
    assert stats[8].tx_bytes == 78637274870
    assert stats[9].rx_bytes == 2963140428936
    assert stats[10].tx_bytes == 3027396511187
    assert all(s.rx_errors == 0 for s in stats.values())
    assert all(s.rx_packets is None and s.tx_packets is None for s in stats.values())


def test_gs110emx_get_mgmt_ip_from_sysinfo() -> None:
    """sysInfo.html device MAC/IP/netmask/gateway/DHCP-mode -> MgmtIpConfig,
    grounded in the real capture (gs110emx_sysinfo.html)."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    mgmt = reader.get_mgmt_ip()
    assert mgmt.address == "10.1.5.25"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.mode is IpMode.STATIC
    # Uppercased to match the SNMP/NSDP backends' base_mac formatting -- the
    # real captured page text itself is lowercase ("bc:a5:11:b8:ec:f1"; see
    # protocols/http/test_parse.py's parse_sysinfo test for that raw value).
    assert mgmt.base_mac == "BC:A5:11:B8:EC:F1"


def test_gs110emx_http_ports_grounded_in_real_capture() -> None:
    """port_settings.html (real capture): HTTP covers NSDP's port-status
    surface. Ports 6/8/9/10 up at 100/1000/10000/10000 Mbps; the rest down."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    ports = {p.port: p for p in reader.get_ports()}
    assert len(ports) == 10
    assert (ports[6].link_up, ports[6].speed_mbps) == (True, 100)
    assert (ports[8].link_up, ports[8].speed_mbps) == (True, 1000)
    assert (ports[9].link_up, ports[9].speed_mbps) == (True, 10000)
    assert (ports[10].link_up, ports[10].speed_mbps) == (True, 10000)
    assert (ports[1].link_up, ports[1].speed_mbps) == (False, None)
    # port 8's real description survives into the name field
    assert ports[8].name == "rumpus"


def test_gs110emx_http_pvids_grounded_in_real_capture() -> None:
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    assert dict(reader.get_pvids()) == dict.fromkeys(range(1, 11), 1)


def test_gs110emx_http_vlans_grounded_in_real_capture() -> None:
    """Cf8021q.html VLAN list + vlanMembership.html hiddenMem (real captures):
    the 12 configured VLAN IDs, and VLAN 1's real membership (ports 1-8
    untagged, 9-10 tagged)."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    vlans = {v.vlan_id: v for v in reader.get_vlans()}
    assert set(vlans) == {1, 4, 5, 6, 7, 10, 20, 21, 41, 90, 99, 121}
    v1 = vlans[1]
    assert v1.untagged_ports == frozenset(range(1, 9))
    assert v1.tagged_ports == frozenset({9, 10})
    assert v1.member_ports == frozenset(range(1, 11))


def _gs105pe_pages() -> dict[str, str]:
    """Real captures from a live GS105PE (10.1.5.30, 2026-07-21)."""
    return {
        "/status.cgi": (_FIX / "gs105pe_status.html").read_text(),
        "/portStatistics.cgi": (_FIX / "gs105pe_portstats.html").read_text(),
        "/portPVID.cgi": (_FIX / "gs105pe_pvid.html").read_text(),
        "/8021qCf.cgi": (_FIX / "gs105pe_vlancfg.html").read_text(),
        "/8021qMembe.cgi": (_FIX / "gs105pe_membership.html").read_text(),
        "/switch_info.cgi": (_FIX / "gs105pe_switch_info.html").read_text(),
    }


def test_gs105pe_http_ports_match_live_nsdp() -> None:
    """status.cgi (real capture): ports 3 (100M) and 5 (1G) up, rest down --
    IDENTICAL to what the NSDP backend reports for this same switch."""
    reader = HttpReader(_FakeSession(_gs105pe_pages()), get_model("gs105pe"))
    ports = {p.port: (p.link_up, p.speed_mbps) for p in reader.get_ports()}
    assert ports == {
        1: (False, None),
        2: (False, None),
        3: (True, 100),
        4: (False, None),
        5: (True, 1000),
    }


def test_gs105pe_http_pvids_match_live_nsdp() -> None:
    reader = HttpReader(_FakeSession(_gs105pe_pages()), get_model("gs105pe"))
    assert dict(reader.get_pvids()) == {1: 41, 2: 41, 3: 90, 4: 41, 5: 1}


def test_gs105pe_http_stats_decode_hidden_counter_halves() -> None:
    """portStatistics.cgi's VISIBLE cells are JS-populated and unreliable; the
    real counters are hidden (hi, lo) 32-bit pairs -- see parse_gs105pe_stats."""
    reader = HttpReader(_FakeSession(_gs105pe_pages()), get_model("gs105pe"))
    stats = {s.port: (s.rx_bytes, s.tx_bytes) for s in reader.get_stats()}
    assert stats[3] == (0, 11625519)
    assert stats[5] == (33619588, 495898)
    assert stats[1] == (0, 0)


def test_gs105pe_http_mgmt_ip_matches_live_nsdp() -> None:
    """switch_info.cgi -> mgmt-IP + base MAC, identical to the NSDP read."""
    reader = HttpReader(_FakeSession(_gs105pe_pages()), get_model("gs105pe"))
    mgmt = reader.get_mgmt_ip()
    assert mgmt.address == "10.1.5.30"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.mode is IpMode.DHCP
    assert mgmt.base_mac == "38:94:ED:B7:CD:E0"


def test_gs105pe_http_poe_unsupported_no_pse() -> None:
    """This model is PoE pass-through, not a PSE: getPoePortStatus.cgi 404s on
    real hardware, so the spec leaves poe_status_path None and the read raises."""
    reader = HttpReader(_FakeSession(_gs105pe_pages()), get_model("gs105pe"))
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_poe()


def _m4300_pages() -> dict[str, str]:
    """Real captures from a live M4300-24X (10.1.5.13, 2026-07-21)."""
    return {
        "/v1/portsConfiguration.html": (_FIX / "m4300_ports.html").read_text(),
        "/v1/portStatistics.html": (_FIX / "m4300_portstats.html").read_text(),
        "/v1/vlanStatus.html": (_FIX / "m4300_vlanstatus.html").read_text(),
        "/v1/portPvidConfiguration.html": (_FIX / "m4300_pvid.html").read_text(),
        "/v1/basicAddressTable.html": (_FIX / "m4300_addresstable.html").read_text(),
        "/v1/base/system/management/sysInfo.html": (
            _FIX / "m4300_sysinfo.html"
        ).read_text(),
        # LIVE capture 2026-07-31 from 10.1.5.13: the M4300 DOES have an LLDP
        # neighbour page (the same lldpRemoteInventory.html the XE models use).
        "/v1/lldpRemoteInventory.html": (
            _FIX / "m4300_lldpRemoteInventory.html"
        ).read_text(),
        # LIVE capture 2026-07-30 from 10.1.5.13. The MANAGEMENT-VLAN page, not
        # /v1/ipConfiguration.html -- that one exists too, but describes the
        # (unused) service port and reads 0.0.0.0 on both M4300 SKUs.
        "/v1/mgmtVlanIpv4Configuration.html": (
            _FIX / "m4300_mgmtVlanIpv4Configuration.html"
        ).read_text(),
        # VLAN-Membership, captured 2026-07-30 (VLAN 1 only on this switch).
        "/v1/switching/dot1q/vlan_port_cfg.html": _membership(
            "m4300_vlanportcfg_vlan1.html"
        ),
        "/v1/switching/dot1q/vlan_port_cfg_rw.html": _membership(
            "m4300_vlanportcfg_vlan1.html"
        ),
    }


def test_m4300_http_ports_match_live_snmp() -> None:
    """portsConfiguration.html: 24 physical ports with interface names and
    speeds. Live cross-check against this switch's SNMP backend showed ZERO
    mismatches on (link_up, speed_mbps) for all 24 ports."""
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    ports = {p.port: p for p in reader.get_ports()}
    assert len(ports) == 24
    assert ports[1].name == "1/0/1"
    assert (ports[1].link_up, ports[1].speed_mbps) == (True, 10000)
    assert (ports[3].link_up, ports[3].speed_mbps) == (True, 1000)
    assert (ports[4].link_up, ports[4].speed_mbps) == (False, None)


def test_m4300_http_stats_are_frames_not_bytes() -> None:
    """This UI reports FRAME counts, never octets -- so bytes stay honestly
    None and the counts land in rx_packets/tx_packets."""
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    stats = {s.port: s for s in reader.get_stats()}
    assert len(stats) == 24
    assert stats[1].rx_packets == 17057817472
    assert stats[1].rx_bytes is None
    assert stats[1].tx_bytes is None


def test_m4300_http_vlans_expand_physical_ports_only() -> None:
    """vlanStatus.html egress lists look like "1/0/1 - 1/0/2, lag 1 - lag 128";
    only physical unit/slot/port interfaces are ports -- expanding the LAG
    range would invent 128 ports on a 24-port switch."""
    from netgear_switch.protocols.http import parse as _parse

    vlans = {
        v.vlan_id: v
        for v in _parse.parse_m4300_vlans((_FIX / "m4300_vlanstatus.html").read_text())
    }
    assert len(vlans) == 14
    assert vlans[1].name == "default"
    assert vlans[1].member_ports == frozenset({1, 2, 5, 7, 8})
    assert max(max(v.member_ports) for v in vlans.values() if v.member_ports) <= 24
    # This page alone cannot split tagged from untagged -- that comes from the
    # VLAN-Membership page, and for VLAN 1 the live switch reports 1/0/5 tagged
    # and 1/0/1,2,7,8 untagged, whose union is exactly the member set above.
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    member1 = reader.read_fastpath_membership(1)
    assert member1.tagged_ports == frozenset({5})
    assert member1.untagged_ports == frozenset({1, 2, 7, 8})
    assert member1.tagged_ports | member1.untagged_ports == vlans[1].member_ports


def test_m4300_http_pvids_and_macs() -> None:
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    pvids = dict(reader.get_pvids())
    assert len(pvids) == 24
    assert pvids[3] == 5


def test_m4300_http_macs_refuse_truncated_page() -> None:
    from netgear_switch.errors import HttpUnexpectedPageError

    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    with pytest.raises(HttpUnexpectedPageError, match="paginates"):
        reader.get_macs()


def test_m4300_http_macs_skip_non_physical_interfaces() -> None:
    """The FDB's Intf cell is not always physical -- the real capture holds
    "lag 1", "vlan 1" and the 0/15/1 service port. Taking the trailing number
    reported every one of them as physical port 1, including the switch's own
    base MAC."""
    from netgear_switch.protocols.http import parse

    html = (_FIX / "m4300_addresstable.html").read_text()
    rows = [
        r
        for r in parse.parse_cheetah_rows(html)
        if "SwitchingmacAddrGroup_MacAddress" in r
    ]
    non_physical = [
        r
        for r in rows
        if not re.fullmatch(r"\d+/\d+/\d+", r.get("SwitchingmacAddrGroup_Intf", ""))
    ]
    assert non_physical, "fixture should contain lag/vlan entries"
    # strip the pagination guard so we can inspect the parsed rows themselves
    trimmed = html.replace('NAME=v_1_1_1 VALUE="1213"', 'NAME=v_1_1_1 VALUE="20"')
    parsed = parse.parse_m4300_macs(trimmed)
    skipped = {r["SwitchingmacAddrGroup_MacAddress"].upper() for r in non_physical}
    assert not (skipped & {m.mac for m in parsed})


def test_m4300_http_mgmt_and_sensors() -> None:
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    mgmt = reader.get_mgmt_ip()
    assert mgmt.address == "10.1.5.13"
    assert mgmt.netmask == "255.255.255.0"
    # From mgmtVlanIpv4Configuration.html, which -- unlike the sysInfo page this
    # used to read -- carries the gateway AND the addressing method, so neither
    # is None/UNKNOWN any more (live 2026-07-30, matches SNMP).
    assert mgmt.gateway == "10.1.5.1"
    assert mgmt.mode is IpMode.DHCP
    # The BASE MAC still comes from sysInfo: the mgmt page's own v_4_4_1 is the
    # management INTERFACE's MAC (…:BB:E3), one off from this.
    assert mgmt.base_mac == "8C:3B:AD:6B:BB:E0"
    temps = reader.get_sensors()
    assert any(s.kind == "temperature" and s.value > 0 for s in temps)


def test_m4300_http_lldp_matches_live_snmp() -> None:
    """CORRECTION of an absence-of-evidence claim. This used to assert that the
    M4300 web UI exposes only LLDP-MED data and that get_lldp must raise. It
    does have a neighbour table -- the same ``lldpRemoteInventory.html`` the XE
    models use, found via the firmware's own nav tree (2026-07-31, 10.1.5.13).
    The 11 neighbours below are byte-for-byte what that switch's SNMP
    lldpRemTable reported in the same session."""
    reader = HttpReader(_FakeSession(_m4300_pages()), get_model("m4300-24x"))
    lldp = reader.get_lldp()
    assert len(lldp) == 11
    by_port = {n.local_port: n for n in lldp}
    assert by_port[1].remote_sys_name == "manage-sw-netgear-m4300-16x-poe-s2"
    assert by_port[1].remote_chassis_id == "8C:3B:AD:69:1C:38"
    assert by_port[2].remote_sys_name.startswith("sw-netgear-gsm7252ps")
    assert by_port[19].remote_sys_name == "big-storage"


def test_gs110emx_http_poe_and_l2_tables_unsupported() -> None:
    """gs110emx genuinely has no PoE, and NSDP/HTTP expose no MAC/LLDP/sensor
    tables on this Plus model -- those ops must raise, not fabricate."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    for op in ("get_poe", "get_macs", "get_lldp", "get_sensors"):
        with pytest.raises(UnsupportedCapabilityError):
            getattr(reader, op)()


def test_async_gs110emx_get_stats_and_mgmt_ip() -> None:
    async def run() -> None:
        reader = AsyncHttpReader(
            _AsyncFakeSession(_gs110emx_pages()), get_model("gs110emx")
        )
        stats = {s.port: s for s in await reader.get_stats()}
        assert stats[9].rx_bytes == 2963140428936
        mgmt = await reader.get_mgmt_ip()
        assert mgmt.address == "10.1.5.25"
        assert mgmt.mode is IpMode.STATIC

    asyncio.run(run())


def test_async_reader_matches_sync() -> None:
    async def run() -> None:
        reader = AsyncHttpReader(_AsyncFakeSession(_pages()), get_model("gs305ep"))
        ports = {p.port: p for p in await reader.get_ports()}
        assert ports[2].link_up is False

    asyncio.run(run())


def test_async_get_vlans() -> None:
    async def run() -> None:
        reader = AsyncHttpReader(_AsyncFakeSession(_pages()), get_model("gs305ep"))
        vlans = {v.vlan_id: v for v in await reader.get_vlans()}
        assert set(vlans) == {1, 90}
        vlan90 = vlans[90]
        assert vlan90.tagged_ports == frozenset({1})
        assert vlan90.untagged_ports == frozenset({2, 3})
        assert vlan90.member_ports == frozenset({1, 2, 3})

    asyncio.run(run())


def test_m4300_async_reader_matches_sync() -> None:
    """The async reader had a real divergence: get_vlans() required the
    membership path BEFORE the m4300 early-return, so it raised while the sync
    twin worked. There was no async m4300 test at all, which is how that
    survived -- this pins parity for every m4300 async read."""

    async def run() -> None:
        pages = _m4300_pages()
        sync = HttpReader(_FakeSession(pages), get_model("m4300-24x"))
        aio = AsyncHttpReader(_AsyncFakeSession(pages), get_model("m4300-24x"))
        assert await aio.read_fastpath_membership(1) == (
            sync.read_fastpath_membership(1)
        )
        assert [(p.port, p.link_up, p.speed_mbps) for p in await aio.get_ports()] == [
            (p.port, p.link_up, p.speed_mbps) for p in sync.get_ports()
        ]
        assert dict(await aio.get_pvids()) == dict(sync.get_pvids())
        assert (await aio.get_mgmt_ip()).base_mac == sync.get_mgmt_ip().base_mac
        assert await aio.get_sensors() == sync.get_sensors()

    asyncio.run(run())


def test_plus_port_status_reports_admin_disabled_ports() -> None:
    """Both Plus port pages carry an admin/speed-MODE column that reads
    "Disable" on an administratively disabled port. These parsers once
    hardcoded admin_enabled=True on the false premise that the page showed only
    link state, which would report a disabled port as enabled."""
    from netgear_switch.protocols.http import parse

    gs105 = (_FIX / "gs105pe_status.html").read_text()
    assert all(p.admin_enabled for p in parse.parse_gs105pe_port_status(gs105))
    flipped = gs105.replace('sel="select">Auto', 'sel="select">Disable', 1)
    ports = parse.parse_gs105pe_port_status(flipped)
    assert ports[0].admin_enabled is False
    assert all(p.admin_enabled for p in ports[1:])

    emx = (_FIX / "gs110emx_port_settings.html").read_text()
    assert all(p.admin_enabled for p in parse.parse_gs110emx_port_status(emx))
    # target the DATA cell (the first ">Auto" is a template <option>)
    emx_off = emx.replace('sel="select">Auto', 'sel="select">Disable', 1)
    emx_ports = parse.parse_gs110emx_port_status(emx_off)
    assert emx_ports[0].admin_enabled is False


# --- gsm7252ps (XE_FASTPATH) ------------------------------------------------


def _gsm7252ps_pages() -> dict[str, str]:
    """Every read page of the real 10.1.5.22 capture, keyed by its spec path."""
    return {
        "/portsConfiguration.html": (
            _FIX / "gsm7252ps_portsConfiguration.html"
        ).read_text(),
        "/portStatistics.html": (_FIX / "gsm7252ps_portStatistics.html").read_text(),
        "/portPvidConfiguration.html": (
            _FIX / "gsm7252ps_portPvidConfiguration.html"
        ).read_text(),
        "/vlanStatus.html": (_FIX / "gsm7252ps_vlanStatus.html").read_text(),
        "/basicAddressTable.html": (
            _FIX / "gsm7252ps_basicAddressTable.html"
        ).read_text(),
        "/poeInterfaceConfiguration.html": (
            _FIX / "gsm7252ps_poeInterfaceConfiguration.html"
        ).read_text(),
        "/lldpRemoteInventory.html": (
            _FIX / "gsm7252ps_lldpRemoteInventory.html"
        ).read_text(),
        "/base/system/management/sysInfo.html": (
            _FIX / "gsm7252ps_sysInfo.html"
        ).read_text(),
        # LIVE capture 2026-07-30 from 10.1.5.22 -- the page that adds the
        # gateway and the DHCP/static method sysInfo does not carry.
        "/ipConfiguration.html": (
            _FIX / "gsm7252ps_ipConfiguration.html"
        ).read_text(),
        # VLAN-Membership, captured 2026-07-30 (VLANs 1 and 141 on this switch).
        "/switching/dot1q/vlan_port_cfg.html": _membership(
            "gsm7252ps_vlanPortCfg_vlan1.html",
            "gsm7252ps_vlanPortCfg_vlan141.html",
        ),
        "/switching/dot1q/vlan_port_cfg_rw.html": _membership(
            "gsm7252ps_vlanPortCfg_vlan1.html",
            "gsm7252ps_vlanPortCfg_vlan141.html",
        ),
    }


def test_http_reader_refuses_unverified_model() -> None:
    """The reads_verified gate: a model whose HTTP reads are NOT verified must
    refuse to construct an HttpReader rather than serve unverified scrapes.

    Both gsm7252ps and gsm7228ps used to sit here and have since GRADUATED
    (their shipped specs are reads_verified=True after live cross-verify), so no
    shipped model is unverified anymore. The gate is exercised by temporarily
    flipping a real model's spec to reads_verified=False -- proving the honesty
    gate still fires when a spec says its reads are unverified."""
    import dataclasses

    from netgear_switch.protocols.http import endpoints

    original = endpoints._SPECS["gsm7228ps"]
    endpoints._SPECS["gsm7228ps"] = dataclasses.replace(
        original, reads_verified=False
    )
    try:
        with pytest.raises(UnsupportedCapabilityError):
            HttpReader(_FakeSession({}), get_model("gsm7228ps"))
    finally:
        endpoints._SPECS["gsm7228ps"] = original


def test_gsm7252ps_every_read_op_is_served_over_http() -> None:
    """FULL PARITY: every read op this model supports is answered from a real
    captured page -- including get_sensors and get_mgmt_ip, which an earlier
    draft wrongly called JS-populated/HTTP-infeasible. No op raises
    UnsupportedCapabilityError for this model."""
    with reads_verified("gsm7252ps"):
        reader = HttpReader(_FakeSession(_gsm7252ps_pages()), get_model("gsm7252ps"))
        ports = {p.port: p for p in reader.get_ports()}
        assert len(ports) == 52
        assert (ports[1].link_up, ports[1].speed_mbps) == (True, 1000)
        assert ports[52].link_up is False

        stats = {s.port: s for s in reader.get_stats()}
        assert stats[1].rx_packets == 287280
        assert stats[1].rx_bytes is None  # this page has no octet column

        assert dict(reader.get_pvids())[1] == 90

        # VLAN list from vlanStatus.html (all 14), tagged/untagged from the
        # VLAN-Membership page -- only VLANs 1 and 141 were captured here, so
        # get_vlans() end-to-end is covered by the mock (see
        # tests/test_http_vlan_membership.py).
        from netgear_switch.protocols.http import parse as _parse

        vlans = {
            v.vlan_id: v
            for v in _parse.parse_xe_vlans(
                (_FIX / "gsm7252ps_vlanStatus.html").read_text()
            )
        }
        assert set(vlans) == {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
        assert vlans[4].member_ports == frozenset({11, 12, 46, 49})
        member1 = reader.read_fastpath_membership(1)
        assert member1.tagged_ports == frozenset({6})
        assert member1.tagged_ports | member1.untagged_ports == vlans[1].member_ports

        macs = reader.get_macs()
        assert len(macs) == 231
        assert all(1 <= m.port <= 52 for m in macs)

        poe = {p.port: p for p in reader.get_poe()}
        assert len(poe) == 48
        assert poe[1].detect is PoEDetect.DELIVERING
        assert poe[1].power_mw == 3500

        lldp = {n.local_port: n for n in reader.get_lldp()}
        assert lldp[49].remote_sys_name == "sw-netgear-m4300-24x"

        sensors = reader.get_sensors()
        assert {s.name for s in sensors if s.kind == "temperature"} == {
            "System",
            "CPU",
            "MAC-A",
            "MAC-B",
        }
        assert any(s.kind == "fan" for s in sensors)

        mgmt = reader.get_mgmt_ip()
        assert (mgmt.address, mgmt.netmask) == ("10.1.5.22", "255.255.255.0")
        assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
        # From ipConfiguration.html (live 2026-07-30), not sysInfo: it names the
        # gateway and the addressing method, so neither is None/UNKNOWN now.
        assert mgmt.gateway == "10.1.5.1"
        assert mgmt.mode is IpMode.DHCP


def test_gsm7252ps_async_reader_matches_sync() -> None:
    """The async reader once diverged from the sync one on get_vlans (it
    required a membership path the FASTPATH dialects do not have). Pin parity
    across every gsm7252ps read op."""

    async def run() -> None:
        pages = _gsm7252ps_pages()
        with reads_verified("gsm7252ps"):
            sync = HttpReader(_FakeSession(pages), get_model("gsm7252ps"))
            aio = AsyncHttpReader(_AsyncFakeSession(pages), get_model("gsm7252ps"))
            assert await aio.get_ports() == sync.get_ports()
            assert await aio.get_stats() == sync.get_stats()
            assert await aio.get_pvids() == sync.get_pvids()
            assert await aio.read_fastpath_membership(
                141
            ) == sync.read_fastpath_membership(141)
            assert await aio.get_macs() == sync.get_macs()
            assert await aio.get_poe() == sync.get_poe()
            assert await aio.get_lldp() == sync.get_lldp()
            assert await aio.get_sensors() == sync.get_sensors()
            assert await aio.get_mgmt_ip() == sync.get_mgmt_ip()

    asyncio.run(run())
