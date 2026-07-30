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
# VirtualSwitchState.nsdp_mac's default (see virtual/state.py): every seed
# below that doesn't override it -- gsm7252ps, gs110emx, gs305ep -- projects
# this same value as both the SNMP dot1dBaseBridgeAddress scalar and the NSDP
# identity MAC.
_DEFAULT_BASE_MAC = "28:C6:8E:00:00:01"


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
    # dot1dBaseBridgeAddress (SNMP) / the NSDP identity MAC: both mocks default
    # VirtualSwitchState.nsdp_mac to the same bytes, so this pin is identical
    # across the SNMP and NSDP model fixtures below.
    base_mac: str = _DEFAULT_BASE_MAC
    # lldpRemPortId (LLDP-MIB col 7): distinct from the neighbour's port desc
    # ("eth0", see seed_gsm7252ps). None for NSDP (no LLDP at all).
    lldp_port_id: str | None = None


# Transcribed from seed_gsm7252ps, which is itself transcribed from the real
# capture of 10.1.5.22 (see that function's docstring for what remains
# illustrative -- the MAC/FDB join and the LLDP neighbour pinned here are).
GSM7252PS_PINS = EquivalencePins(
    port_name="1/0/1",
    vlan_id=90,
    vlan_name="iot",
    vlan_member_port=11,  # a real member of VLAN 90 on the captured switch
    mgmt_address="10.1.5.22",
    mgmt_mode=IpMode.STATIC,
    poe_port=1,
    poe_power_mw=3_500,  # captured live draw on 1/0/1
    mac="C8:00:84:89:71:70",
    mac_port=110,
    lldp_port_id="1/xg51",
    base_mac="E0:91:F5:0C:D6:DB",  # the switch's captured System MAC Address
)


GS110EMX_PINS = EquivalencePins(
    port_name="1000",  # unused for NSDP (no port names); see note below
    vlan_id=90,
    vlan_name="",  # NSDP carries no VLAN name
    vlan_member_port=10,
    mgmt_address="10.1.5.25",
    mgmt_mode=IpMode.STATIC,
    base_mac="BC:A5:11:B8:EC:F1",
    poe_port=0,  # NSDP exposes no PoE (unused)
    poe_power_mw=0,
    mac="",  # NSDP exposes no MAC table (unused)
    mac_port=0,
    lldp_port_id=None,  # NSDP exposes no LLDP (unused)
)


@dataclass(frozen=True)
class M4300Pins:
    """Known capture-grounded seed values for one M4300 variant (see
    ``virtual/seed.py``'s ``seed_m4300_24x``/``seed_m4300_16x``, both literal
    transcriptions of ``tests/fixtures/captures/m4300-*.json``)."""

    port_name: str
    vlan_id: int
    vlan_name: str
    vlan_member_port: int
    mac: str
    mac_port: int
    lldp_port_id: str
    lldp_port_desc: str
    base_mac: str
    mgmt_address: str
    mgmt_mode: IpMode
    # None on both = this model has NO PoE at all (m4300-24x, verified real
    # capture poe=[]); otherwise a verified-delivering (port, power_mw) pair
    # (m4300-16x, ports 11+12 delivering live).
    poe_port: int | None = None
    poe_power_mw: int | None = None


M4300_24X_PINS = M4300Pins(
    port_name="1/0/1",
    vlan_id=90,
    vlan_name="iot",
    vlan_member_port=6,
    mac="00:0A:FA:24:28:20",
    mac_port=1,
    lldp_port_id="88:A2:9E:80:87:01",
    lldp_port_desc="eth0",
    base_mac="8C:3B:AD:6B:BB:E0",
    mgmt_address="10.1.5.13",
    mgmt_mode=IpMode.STATIC,
)

M4300_16X_PINS = M4300Pins(
    port_name="1/0/1",
    vlan_id=90,
    vlan_name="iot",
    vlan_member_port=9,
    mac="00:08:A2:09:EF:ED",
    mac_port=16,
    lldp_port_id="5",
    lldp_port_desc="Device Port 5",
    base_mac="8C:3B:AD:69:1C:38",
    # This model's captured mgmt_ip.address was never discovered (see
    # seed_m4300_16x's docstring): the honest blank-default MgmtSim, not a
    # fabricated static address.
    mgmt_address="0.0.0.0",
    mgmt_mode=IpMode.DHCP,
    poe_port=11,
    poe_power_mw=5_000,
)


def assert_m4300_facades_equivalent(sw: VirtualSwitch, pins: M4300Pins) -> None:
    """Run every applicable read op through both facades for an M4300
    variant; assert non-empty (except PoE on the non-PoE 24X, where get_poe
    honestly RAISES UnsupportedCapabilityError on BOTH facades -- consistent
    with CLI/HTTP, not a silent ``[]``), content-pinned to the real
    capture-grounded seed (see ``M4300Pins``), and byte-for-byte identical
    between sync (net-snmp CLI) and async (pysnmp).

    Deliberately does NOT assert ifAlias (``description``) presence/absence
    the way ``assert_facades_equivalent`` does for gsm7252ps: m4300-16x's
    seed carries no ifAlias on ANY port at all (unlike gsm7252ps's mix of set
    and absent), so a shared assumption there would be false for one variant.
    """
    sync, aio = facades_for(sw)

    ports = sync.get_ports()
    stats = sync.get_stats()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    lldp = sync.get_lldp()
    macs = sync.get_macs()
    sensors = sync.get_sensors()
    mgmt = sync.get_mgmt_ip()

    # Non-empty: guard against a vacuous [] == [] equivalence pass.
    assert ports, "ports must be non-empty"
    assert [s for s in stats if s.rx_bytes is not None], "stats must be non-empty"
    assert vlans, "vlans must be non-empty"
    assert pvids, "pvids must be non-empty"
    assert lldp, "lldp must be non-empty"
    assert macs, "macs must be non-empty"
    assert sensors, "sensors must be non-empty"
    assert mgmt.address, "mgmt-ip must be populated"
    if pins.poe_port is None:
        # PoE parity: a 0-PSE model (m4300-24x) must raise
        # UnsupportedCapabilityError from get_poe on BOTH facades -- NOT return
        # [] on one path while another raises. (SnmpReader.get_poe now guards on
        # poe_port_count == 0 exactly like CliReader/HttpReader.)
        with pytest.raises(UnsupportedCapabilityError):
            sync.get_poe()
        with pytest.raises(UnsupportedCapabilityError):
            asyncio.run(aio.get_poe())
    else:
        poe = sync.get_poe()
        assert any(p.power_mw for p in poe), "poe must show delivered power"

    # Content pins: prove equivalence is over real, capture-grounded data.
    assert pins.port_name in {p.name for p in ports}
    target_vlan = next(v for v in vlans if v.vlan_id == pins.vlan_id)
    assert target_vlan.name == pins.vlan_name
    assert pins.vlan_member_port in target_vlan.member_ports
    assert mgmt.address == pins.mgmt_address
    assert mgmt.mode is pins.mgmt_mode
    # dot1dBaseBridgeAddress: device base MAC, proven over real seed data.
    assert mgmt.base_mac == pins.base_mac
    # MAC/FDB join proof (identity bridge_port->ifIndex on both M4300 seeds).
    joined = next(m for m in macs if m.mac == pins.mac)
    assert joined.port == pins.mac_port
    # lldpRemPortId: a distinct value from remote_port_desc.
    assert lldp[0].remote_port_id == pins.lldp_port_id
    assert lldp[0].remote_port_desc == pins.lldp_port_desc
    assert lldp[0].remote_port_id != lldp[0].remote_port_desc
    if pins.poe_port is not None:
        delivering = [p for p in poe if p.power_mw]
        assert any(
            p.port == pins.poe_port and p.power_mw == pins.poe_power_mw
            for p in delivering
        )

    # Equivalence proper: sync (net-snmp CLI) vs async (pysnmp) must be equal.
    assert ports == asyncio.run(aio.get_ports())
    assert stats == asyncio.run(aio.get_stats())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert lldp == asyncio.run(aio.get_lldp())
    assert macs == asyncio.run(aio.get_macs())
    if pins.poe_port is not None:
        # (The 0-PSE case asserted both facades raise, above -- nothing to
        # compare here.)
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

    gc.collect()  # finalize pysnmp transport before -W error::ResourceWarning


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
        # http_password is supplied so the facade can CONSTRUCT its HTTP and CLI
        # readers for the per-op backend fallback (both back ends resolve their
        # password from http_password). SNMP is authoritative and serves every
        # op these models support, so the fallback is exercised only when SNMP
        # itself raises UnsupportedCapabilityError -- e.g. m4300-24x get_poe (0
        # PSE ports): SNMP/HTTP/CLI must ALL then report the op unsupported, and
        # the facade re-raises that UnsupportedCapabilityError consistently
        # rather than a CredentialError. The SSH transport is built lazily (no
        # connection), and CliReader.get_poe's poe_port_count==0 guard short-
        # circuits before any session use, so no real network I/O occurs.
        sync = SyncSwitch(
            model,
            sw.host,
            snmp_community=sw.community,
            snmp_client=sync_client,
            snmp_write_client=sync_client,
            http_password="unused-mock-password",
        )
        aio = AsyncSwitch(
            model,
            sw.host,
            snmp_community=sw.community,
            snmp_client=aio_client,
            snmp_write_client=aio_client,
            http_password="unused-mock-password",
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
    # dot1dBaseBridgeAddress: device base MAC, proven over real seed data.
    assert mgmt.base_mac == pins.base_mac
    # ifAlias: at least one port carries an operator-set description, distinct
    # from ifName (`name`); a port with no seeded alias stays honestly None.
    assert any(p.description for p in ports)
    assert any(p.description is None for p in ports)
    # lldpRemPortId: a distinct value from remote_port_desc (proves the two
    # LLDP-MIB columns are surfaced as separate fields, not collapsed).
    assert lldp[0].remote_port_id == pins.lldp_port_id
    assert lldp[0].remote_port_id != lldp[0].remote_port_desc

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
    assert any(p.port == 8 and p.speed_mbps == 1000 for p in ports)
    assert any(p.port == 9 and p.speed_mbps == 10000 for p in ports)  # 10G pin
    target = next(v for v in vlans if v.vlan_id == pins.vlan_id)
    assert pins.vlan_member_port in target.member_ports
    assert mgmt.address == pins.mgmt_address
    assert mgmt.mode is pins.mgmt_mode
    # NSDP always echoes the device's identity MAC (Tag.MAC / server_mac
    # fallback), so base_mac is honestly populated here too, never None.
    assert mgmt.base_mac == pins.base_mac
    # NSDP PORT_STATUS carries no operator-set alias; honestly None.
    assert all(p.description is None for p in ports)

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
    assert sync_snap.macs == ()  # Plus: no MAC table, aggregated empty
    assert sync_snap.poe == ()

    gc.collect()  # no leaked datagram transports before -W error::ResourceWarning


@dataclass(frozen=True)
class HttpEquivalencePins:
    """Known gs305ep seed values spanning the NSDP + HTTP backends."""

    port_name: str
    poe_port: int
    poe_power_mw: int
    vlan_id: int
    vlan_member_port: int


# NOTE: on gs305ep the ports/stats/vlans/pvids/mgmt come from NSDP (which carries
# NO port name — PortStatus.name is None), so we pin the NSDP port on its speed,
# not its name; the poe/vlan pins span the HTTP + NSDP backends. port_name is kept
# on the dataclass for parity with EquivalencePins but is not asserted here.
GS305EP_HTTP_PINS = HttpEquivalencePins(
    port_name="",  # unused: NSDP-served ports have no name
    poe_port=1,
    poe_power_mw=12_800,
    vlan_id=90,
    vlan_member_port=1,
)


def http_facades_for(sw: VirtualSwitch) -> tuple[SyncSwitch, AsyncSwitch]:
    """Wire both facades to BOTH faces of the running gs305ep VirtualSwitch:
    NSDP (ports/stats/vlans/pvids/mgmt) + HTTP (PoE). Injecting both clients is
    what proves per-op routing end-to-end on a single device."""
    from netgear_switch.protocols.http.endpoints import http_spec
    from netgear_switch.transport.http.client import AsyncHttpClient, HttpClient

    model = get_model(sw.model)
    spec = http_spec(model)
    http_host = f"{sw.host}:{sw.http_port}"
    sync_http = HttpClient(http_host, sw.http_password, spec)
    aio_http = AsyncHttpClient(http_host, sw.http_password, spec)
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
        http_client=sync_http,
    )
    aio = AsyncSwitch(
        model,
        sw.host,
        nsdp_client=aio_nsdp,
        nsdp_write_client=aio_nsdp,
        nsdp_password=sw.nsdp_password,
        http_client=aio_http,
    )
    return sync, aio


def assert_http_facades_equivalent(
    sw: VirtualSwitch, pins: HttpEquivalencePins
) -> None:
    sync, aio = http_facades_for(sw)

    # NSDP-served reads (must stay populated — no Slice-5 regression).
    ports = sync.get_ports()
    stats = sync.get_stats()
    vlans = sync.get_vlans()
    pvids = sync.get_pvids()
    mgmt = sync.get_mgmt_ip()
    # HTTP-served read, EXPLICITLY: NSDP (this model's default backend) has no
    # PoE at all, and the facade no longer substitutes another protocol behind
    # the caller's back, so PoE must be asked of HTTP by name. That also makes
    # this a genuine HTTP test: the answer below cannot have come from NSDP.
    poe = sync.get_poe(backend=Backend.HTTP)

    assert ports, "ports must be non-empty (NSDP)"
    assert [s for s in stats if s.rx_bytes is not None], "stats non-empty (NSDP)"
    assert vlans, "vlans must be non-empty (NSDP)"
    assert pvids, "pvids must be non-empty (NSDP)"
    assert mgmt.address, "mgmt-ip must be populated (NSDP)"
    assert any(p.power_mw for p in poe), "poe must show delivered power (HTTP)"

    # Content pins spanning BOTH backends.
    assert any(p.port == 1 and p.speed_mbps == 1000 for p in ports)  # NSDP
    target = next(v for v in vlans if v.vlan_id == pins.vlan_id)  # NSDP
    assert pins.vlan_member_port in target.member_ports
    delivering = [p for p in poe if p.power_mw]  # HTTP
    assert delivering[0].port == pins.poe_port
    assert delivering[0].power_mw == pins.poe_power_mw
    # base_mac comes via NSDP (HttpReader.get_mgmt_ip always raises), so it
    # stays honestly populated exactly like the other NSDP-served fields above.
    assert mgmt.base_mac == _DEFAULT_BASE_MAC

    # sync (NSDP+HTTP) == async (NSDP+HTTP): per-op routing is identical.
    assert ports == asyncio.run(aio.get_ports())
    assert stats == asyncio.run(aio.get_stats())
    assert vlans == asyncio.run(aio.get_vlans())
    assert pvids == asyncio.run(aio.get_pvids())
    assert mgmt == asyncio.run(aio.get_mgmt_ip())
    assert poe == asyncio.run(aio.get_poe(backend=Backend.HTTP))

    # snapshot() describes ONE backend and is equal across facades. Over NSDP
    # (the default here) the NSDP-served fields are never nulled, and poe -- an
    # op NSDP genuinely lacks -- is EMPTY rather than quietly filled from HTTP:
    # a snapshot must not present a blend of protocols as one protocol's answer.
    sync_snap = sync.snapshot()
    assert sync_snap == asyncio.run(aio.snapshot())
    assert sync_snap.ports, "snapshot ports (NSDP) must stay populated"
    assert sync_snap.poe == (), "NSDP snapshot must not borrow HTTP's PoE"
    assert sync_snap.macs == ()  # neither backend serves a MAC table on Plus

    gc.collect()


def assert_http_write_equivalent(
    perform_sync: Callable[[SyncSwitch], None],
    perform_async: Callable[[AsyncSwitch], Awaitable[None]],
    expect: Callable[[list[object]], bool],
) -> None:
    from netgear_switch.virtual.server import VirtualSwitch

    sw_sync = VirtualSwitch(model="gs305ep")
    sw_async = VirtualSwitch(model="gs305ep")
    sw_sync.start()
    sw_async.start()
    try:
        sync_facade, _ = http_facades_for(sw_sync)
        _, async_facade = http_facades_for(sw_async)
        perform_sync(sync_facade)
        asyncio.run(perform_async(async_facade))
        # Read back over HTTP BY NAME (the write went over HTTP by name too):
        # NSDP has no PoE, and nothing is substituted silently any more.
        poe_sync = http_facades_for(sw_sync)[0].get_poe(backend=Backend.HTTP)
        poe_async = http_facades_for(sw_async)[0].get_poe(backend=Backend.HTTP)
        assert poe_sync == poe_async, "sync and async writes diverged"
        assert expect(poe_sync), "write did not take effect"
    finally:
        sw_sync.stop()
        sw_async.stop()
    gc.collect()


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
