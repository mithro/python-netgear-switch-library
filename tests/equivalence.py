"""Reusable sync/async facade equivalence harness.

Generalizes tests/test_snmp_integration.py from the raw readers to the public
facades: given a running VirtualSwitch and a set of per-model content pins, it
runs every read op through BOTH SyncSwitch and AsyncSwitch and asserts the
results are non-empty, content-pinned, and byte-for-byte identical across the
two independent transports. Future backends/models reuse this by supplying
their own EquivalencePins.
"""
from __future__ import annotations

import asyncio
import gc
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from netgear_switch.aio_api import AsyncSwitch
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import IpMode
from netgear_switch.registry import Backend, get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.transport.aio.nsdp_udp import AsyncUdpNsdpClient
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from netgear_switch.models import SwitchData
    from netgear_switch.virtual.server import VirtualSwitch

_NSDP_CLIENT_MAC = b"\x00\x00\x00\x00\x00\x01"


@dataclass(frozen=True)
class EquivalencePins:
    """Known seed values for one model, proving equivalence is over real data."""

    port_name: str
    vlan_id: int
    vlan_name: str
    vlan_member_port: int
    mgmt_address: str
    mgmt_mode: IpMode
    poe_port: int
    poe_power_mw: int
    mac: str
    mac_port: int


GSM7252PS_PINS = EquivalencePins(
    port_name="1/0/1",
    vlan_id=90,
    vlan_name="iot",
    vlan_member_port=10,
    mgmt_address="10.1.5.20",
    mgmt_mode=IpMode.STATIC,
    poe_port=1,
    poe_power_mw=12_800,
    mac="C8:00:84:89:71:70",
    mac_port=110,
)


GS110EMX_PINS = EquivalencePins(
    port_name="1000",       # unused for NSDP (no port names); see note below
    vlan_id=90,
    vlan_name="",           # NSDP carries no VLAN name
    vlan_member_port=10,
    mgmt_address="10.1.5.20",
    mgmt_mode=IpMode.STATIC,
    poe_port=0,             # NSDP exposes no PoE (unused)
    poe_power_mw=0,
    mac="",                 # NSDP exposes no MAC table (unused)
    mac_port=0,
)


def facades_for(sw: VirtualSwitch) -> tuple[SyncSwitch, AsyncSwitch]:
    """Build both facades wired to a running VirtualSwitch via injected clients.

    SNMP models use the net-snmp CLI (sync) + pysnmp (async) clients; NSDP
    (Plus) models use the sync/async UDP NSDP clients pointed at the face's
    ephemeral port. In both cases one client instance serves read AND write.

    Injection sidesteps the sync/async host-spec asymmetry: the net-snmp CLI
    client takes a combined ``host:port`` agent spec, while PysnmpClient takes
    host and port separately.

    The injected net-snmp CLI / pysnmp clients implement both read and write, so
    each is passed as the read client AND the write client; the mock grants the
    same community read+write access (writeSubTree in the SNMP face).
    """
    model = get_model(sw.model)
    if Backend.SNMP in model.backends:
        sync_client = NetsnmpCliClient(f"{sw.host}:{sw.port}", sw.community)
        aio_client = PysnmpClient(sw.host, sw.community, port=sw.port)
        sync = SyncSwitch(
            model,
            sw.host,
            snmp_community=sw.community,
            snmp_client=sync_client,
            snmp_write_client=sync_client,
        )
        aio = AsyncSwitch(
            model,
            sw.host,
            snmp_community=sw.community,
            snmp_client=aio_client,
            snmp_write_client=aio_client,
        )
        return sync, aio
    # NSDP (Plus) backend.
    sync_nsdp = UdpNsdpClient(
        sw.host, client_port=0, server_port=sw.port, client_mac=_NSDP_CLIENT_MAC
    )
    aio_nsdp = AsyncUdpNsdpClient(
        sw.host, client_port=0, server_port=sw.port, client_mac=_NSDP_CLIENT_MAC
    )
    sync = SyncSwitch(
        model,
        sw.host,
        nsdp_client=sync_nsdp,
        nsdp_write_client=sync_nsdp,
        nsdp_password=sw.nsdp_password,
    )
    aio = AsyncSwitch(
        model,
        sw.host,
        nsdp_client=aio_nsdp,
        nsdp_write_client=aio_nsdp,
        nsdp_password=sw.nsdp_password,
    )
    return sync, aio


def assert_facades_equivalent(sw: VirtualSwitch, pins: EquivalencePins) -> None:
    """Run every read op through both facades; assert non-empty + pinned + equal."""
    sync, aio = facades_for(sw)

    ports = sync.get_ports()
    stats = sync.get_stats()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    lldp = sync.get_lldp()
    macs = sync.get_macs()
    poe = sync.get_poe()
    sensors = sync.get_sensors()
    mgmt = sync.get_mgmt_ip()

    # Non-empty: guard against a vacuous [] == [] equivalence pass.
    assert ports, "ports must be non-empty"
    assert [s for s in stats if s.rx_bytes is not None], "stats must be non-empty"
    assert vlans, "vlans must be non-empty"
    assert pvids, "pvids must be non-empty"
    assert lldp, "lldp must be non-empty"
    assert macs, "macs must be non-empty"
    assert any(p.power_mw for p in poe), "poe must show delivered power"
    assert sensors, "sensors must be non-empty"
    assert mgmt.address, "mgmt-ip must be populated"

    # Content pins: prove equivalence is over real, known seed data.
    assert pins.port_name in {p.name for p in ports}
    target_vlan = next(v for v in vlans if v.vlan_id == pins.vlan_id)
    assert target_vlan.name == pins.vlan_name
    assert pins.vlan_member_port in target_vlan.member_ports
    assert mgmt.address == pins.mgmt_address
    assert mgmt.mode is pins.mgmt_mode
    delivering = [p for p in poe if p.power_mw]
    assert delivering[0].port == pins.poe_port
    assert delivering[0].power_mw == pins.poe_power_mw
    # MAC/FDB join proof: a non-identity bridge_port -> ifIndex mapping.
    joined = next(m for m in macs if m.mac == pins.mac)
    assert joined.port == pins.mac_port

    # Equivalence proper: sync (net-snmp CLI) vs async (pysnmp) must be equal.
    assert ports == asyncio.run(aio.get_ports())
    assert stats == asyncio.run(aio.get_stats())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert lldp == asyncio.run(aio.get_lldp())
    assert macs == asyncio.run(aio.get_macs())
    assert poe == asyncio.run(aio.get_poe())
    assert sensors == asyncio.run(aio.get_sensors())
    aio_mgmt = asyncio.run(aio.get_mgmt_ip())
    assert mgmt == aio_mgmt
    assert mgmt.mode is pins.mgmt_mode
    assert aio_mgmt.mode is pins.mgmt_mode

    # snapshot() aggregates the same objects and is equivalent across facades.
    sync_snap = sync.snapshot()
    aio_snap = asyncio.run(aio.snapshot())
    assert sync_snap == aio_snap
    assert sync_snap.model == sw.model
    assert sync_snap.ports == tuple(ports)
    assert sync_snap.macs == tuple(macs)

    # Force finalization of any unreferenced pysnmp transport before the
    # -W error::ResourceWarning run inspects warnings.
    gc.collect()


def assert_nsdp_facades_equivalent(sw: VirtualSwitch, pins: EquivalencePins) -> None:
    """Run every NSDP-supported read op through both facades; assert non-empty,
    pinned, byte-identical across sync/async, and that unsupported ops raise."""
    sync, aio = facades_for(sw)

    ports = sync.get_ports()
    stats = sync.get_stats()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    mgmt = sync.get_mgmt_ip()

    # Non-empty over real seeded data (guard against a vacuous [] == [] pass).
    assert ports, "ports must be non-empty"
    assert [s for s in stats if s.rx_bytes is not None], "stats must be non-empty"
    assert vlans, "vlans must be non-empty"
    assert pvids, "pvids must be non-empty"
    assert mgmt.address, "mgmt-ip must be populated"

    # Content pins over NSDP-populated fields only.
    assert any(p.port == 1 and p.speed_mbps == 1000 for p in ports)
    assert any(p.port == 9 and p.speed_mbps == 10000 for p in ports)  # 10G pin
    target = next(v for v in vlans if v.vlan_id == pins.vlan_id)
    assert pins.vlan_member_port in target.member_ports
    assert mgmt.address == pins.mgmt_address
    assert mgmt.mode is pins.mgmt_mode

    # Ops NSDP genuinely cannot serve must raise, not silently return empty.
    for op in ("get_macs", "get_lldp", "get_sensors", "get_poe"):
        with pytest.raises(UnsupportedCapabilityError):
            getattr(sync, op)()

    # Equivalence proper: sync (UDP) vs async (asyncio UDP) must be equal.
    assert ports == asyncio.run(aio.get_ports())
    assert stats == asyncio.run(aio.get_stats())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert mgmt == asyncio.run(aio.get_mgmt_ip())

    # snapshot() aggregates the same objects (unsupported sections empty) and is
    # equivalent across facades.
    sync_snap = sync.snapshot()
    aio_snap = asyncio.run(aio.snapshot())
    assert sync_snap == aio_snap
    assert sync_snap.model == sw.model
    assert sync_snap.macs == ()      # Plus: no MAC table, aggregated empty
    assert sync_snap.poe == ()

    gc.collect()  # no leaked datagram transports before -W error::ResourceWarning


def assert_write_equivalent(
    perform_sync: Callable[[SyncSwitch], None],
    perform_async: Callable[[AsyncSwitch], Awaitable[None]],
    expect: Callable[[SwitchData], bool],
    *,
    model: str = "gsm7252ps",
    community: str = "public",
) -> None:
    """Apply the same write via sync (on one mock) and async (on a second, fresh
    mock), then assert both post-write snapshots are byte-identical and the
    write actually took effect (``expect``)."""
    from netgear_switch.virtual.server import VirtualSwitch

    sw_sync = VirtualSwitch(model=model, community=community)
    sw_async = VirtualSwitch(model=model, community=community)
    sw_sync.start()
    sw_async.start()
    try:
        sync_facade, _ = facades_for(sw_sync)
        _, async_facade = facades_for(sw_async)
        perform_sync(sync_facade)
        asyncio.run(perform_async(async_facade))

        # Read both back through the SYNC transport for a like-for-like compare.
        snap_from_sync = sync_facade.snapshot()
        snap_from_async = facades_for(sw_async)[0].snapshot()
        assert snap_from_sync == snap_from_async, "sync and async writes diverged"
        assert expect(snap_from_sync), "write did not take effect"
    finally:
        sw_sync.stop()
        sw_async.stop()
    gc.collect()  # finalize pysnmp transports before -W error::ResourceWarning
