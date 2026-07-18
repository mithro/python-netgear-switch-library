from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.http_read import AsyncHttpReader, HttpReader
from netgear_switch.models import PoEDetect
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


def test_mac_table_unsupported_on_plus() -> None:
    reader = HttpReader(_FakeSession(_pages()), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_macs()
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_sensors()
    with pytest.raises(UnsupportedCapabilityError):
        reader.get_lldp()


def test_unverified_model_read_refused() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        HttpReader(_FakeSession({}), get_model("gs110emx"))


def test_async_reader_matches_sync() -> None:
    async def run() -> None:
        reader = AsyncHttpReader(_AsyncFakeSession(_pages()), get_model("gs305ep"))
        ports = {p.port: p for p in await reader.get_ports()}
        assert ports[2].link_up is False

    asyncio.run(run())
