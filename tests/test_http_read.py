from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.http_read import AsyncHttpReader, HttpReader
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.registry import get_model

_FIX = Path(__file__).parent / "fixtures" / "http"


class _FakeSession:
    """In-memory session returning captured fixtures per path."""

    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages
        self.logged_in = False

    def login(self) -> None:
        self.logged_in = True

    def get_page(self, path: str) -> str:
        return self._pages[path]

    def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._pages[path]


class _AsyncFakeSession(_FakeSession):
    async def login(self) -> None:  # type: ignore[override]
        self.logged_in = True

    async def get_page(self, path: str) -> str:  # type: ignore[override]
        return self._pages[path]

    async def post_form(self, path: str, data: dict[str, str]) -> str:  # type: ignore[override]
        return self._pages[path]


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


def test_gsm7228ps_unverified_model_read_refused() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        HttpReader(_FakeSession({}), get_model("gsm7228ps"))


def _gs110emx_pages() -> dict[str, str]:
    return {
        "/iss/specific/sysInfo.html": (_FIX / "gs110emx_sysinfo.html").read_text(),
        "/iss/specific/interface_stats.html": (
            _FIX / "gs110emx_interface_stats.html"
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


def test_gs110emx_http_has_no_port_status_poe_or_vlan_pages() -> None:
    """Live capture proved /iss/specific/{vlan,port,poePortStatus,neighbor,
    dashboard}.html all 404 on a real GS110EMX -- gs110emx has no PoE and
    serves ports/VLANs/PVIDs via NSDP, not HTTP. These ops must raise, not
    silently return an empty/fabricated result."""
    reader = HttpReader(_FakeSession(_gs110emx_pages()), get_model("gs110emx"))
    for op in ("get_ports", "get_poe", "get_pvids", "get_vlans"):
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
