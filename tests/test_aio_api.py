from __future__ import annotations

import asyncio

import pytest

from netgear_switch.aio_api import AsyncSwitch
from netgear_switch.config import SwitchConfig
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model


class FakeAsyncClient:
    """Async twin of Task 2's FakeClient: identical lookup, async methods."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        self._tables = tables

    async def get(self, oids: list[str]) -> list[SnmpRow]:
        rows: list[SnmpRow] = []
        for oid in oids:
            rows.extend(await self.walk(oid))
        return rows

    async def walk(self, base_oid: str) -> list[SnmpRow]:
        return list(self._tables.get(base_oid, []))


def _ports_tables() -> dict[str, list[SnmpRow]]:
    return {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.1", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.1", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.1", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.1", "1/0/1", "STRING")],
    }


def test_get_ports_delegates_to_injected_async_client() -> None:
    sw = AsyncSwitch(
        get_model("gsm7252ps"), "host", snmp_client=FakeAsyncClient(_ports_tables())
    )
    ports = asyncio.run(sw.get_ports())
    assert ports[0].port == 1
    assert ports[0].name == "1/0/1"
    assert ports[0].speed_mbps == 1000


def test_plus_model_read_raises_backend_not_implemented() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        asyncio.run(sw.get_ports())
    assert "gs305ep" in str(exc.value)


def test_get_macs_on_plus_model_raises_no_mac_table() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(sw.get_macs())


def test_snapshot_on_plus_model_raises() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(sw.snapshot())


def test_from_config_builds_facade_without_touching_network() -> None:
    """Async from_config mirrors sync test: builds facade without network access."""
    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec=None,
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    sw = AsyncSwitch.from_config(cfg)
    assert sw.host == "10.0.0.9"
    assert sw.model.key == "gsm7252ps"


def test_reader_builds_default_client_when_not_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no client injected, _reader() calls builder; verify the default branch."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build(host: str, community: str | None) -> FakeAsyncClient:
        build_calls.append((host, community))
        return FakeAsyncClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_client", fake_build
    )

    sw = AsyncSwitch(get_model("gsm7252ps"), "10.0.0.5")
    ports = asyncio.run(sw.get_ports())

    assert len(build_calls) == 1
    assert build_calls[0] == ("10.0.0.5", None)
    assert len(ports) > 0
    assert ports[0].port == 1
