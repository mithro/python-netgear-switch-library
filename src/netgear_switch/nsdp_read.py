"""Model-driven NSDP read operations over a sync or async client.

Parallel to ``snmp_read.py``. Maps NSDP TLVs onto the SAME public ``models``
types. NSDP genuinely exposes only port link/speed, byte/CRC statistics, VLAN
membership, PVID and management IP on these Plus switches; MAC/FDB, LLDP,
sensors and PoE are not in the protocol, so those ops raise
``UnsupportedCapabilityError`` rather than fabricating empty results.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import UnsupportedCapabilityError
from .models import IpMode, MgmtIpConfig, PortStats, PortStatus, VLANInfo
from .protocols.nsdp.parsers import parse_device
from .protocols.nsdp.protocol import Tag
from .protocols.nsdp.types import LinkSpeed
from .registry import Backend

if TYPE_CHECKING:
    from .models import LLDPNeighbor, MacEntry, PoEStatus, Sensor
    from .protocols.nsdp.client import AsyncNsdpClient, NsdpClient
    from .protocols.nsdp.types import NsdpDevice
    from .registry import SwitchModel

_NO_MACS = "NSDP exposes no MAC/FDB table (Plus switches have no remote FDB)"
_NO_LLDP = "NSDP exposes no LLDP neighbours on these Plus switches"
_NO_SENSORS = "NSDP exposes no environmental sensors on these Plus switches"
_NO_POE = "NSDP exposes no PoE status; use the HTTP backend (Slice 6) for PoE"


def _require_nsdp(model: SwitchModel) -> None:
    if Backend.NSDP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no NSDP backend")


def _ports(dev: NsdpDevice) -> list[PortStatus]:
    return [
        PortStatus(
            port=s.port_id,
            name=None,  # NSDP PORT_STATUS carries no port name
            # NSDP PORT_STATUS reports link speed only; it cannot distinguish an
            # admin-disabled port from a link-down one, so admin_enabled is
            # reported True (the honest "not administratively removed" default).
            admin_enabled=True,
            link_up=s.speed is not LinkSpeed.DOWN,
            speed_mbps=s.speed.speed_mbps or None,
        )
        for s in dev.port_status
    ]


def _stats(dev: NsdpDevice) -> list[PortStats]:
    return [
        PortStats(
            port=s.port_id,
            rx_bytes=s.bytes_received,
            tx_bytes=s.bytes_sent,
            rx_packets=None,  # NSDP PORT_STATISTICS has no packet counters
            tx_packets=None,
            rx_errors=s.crc_errors,
            tx_errors=None,
        )
        for s in dev.port_statistics
    ]


def _vlans(dev: NsdpDevice) -> list[VLANInfo]:
    return [
        VLANInfo(
            vlan_id=m.vlan_id,
            name=None,  # NSDP VLAN_MEMBERS carries no VLAN name
            member_ports=m.member_ports,
            tagged_ports=m.tagged_ports,
            untagged_ports=m.untagged_ports,
        )
        for m in dev.vlan_members
    ]


def _mgmt(dev: NsdpDevice) -> MgmtIpConfig:
    if dev.dhcp_enabled is None:
        mode = IpMode.UNKNOWN
    else:
        mode = IpMode.DHCP if dev.dhcp_enabled else IpMode.STATIC
    return MgmtIpConfig(
        mode=mode, address=dev.ip, netmask=dev.netmask, gateway=dev.gateway,
        # NSDP always echoes the device MAC (Tag.MAC, with a server_mac
        # fallback -- see parse_device), so this is honestly always
        # populated, never a guess. Uppercased to match the SNMP-backend
        # formatting (parse.parse_base_mac / _format_mac_bytes) so the public
        # field has one consistent case across backends.
        base_mac=dev.mac.upper(),
    )


class NsdpReader:
    """Synchronous NSDP read facade over one switch."""

    def __init__(self, client: NsdpClient, model: SwitchModel) -> None:
        _require_nsdp(model)
        self.client = client
        self.model = model

    def _device(self, tags: list[Tag]) -> NsdpDevice:
        return parse_device(self.client.read(tags))

    def get_ports(self) -> list[PortStatus]:
        return _ports(self._device([Tag.PORT_COUNT, Tag.PORT_STATUS]))

    def get_stats(self) -> list[PortStats]:
        return _stats(self._device([Tag.PORT_STATISTICS]))

    def get_vlans(self) -> list[VLANInfo]:
        return _vlans(self._device([Tag.PORT_COUNT, Tag.VLAN_MEMBERS]))

    def get_pvids(self) -> list[tuple[int, int]]:
        dev = self._device([Tag.PORT_PVID])
        return [(p.port_id, p.vlan_id) for p in dev.port_pvids]

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return _mgmt(
            self._device([Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY, Tag.DHCP_MODE])
        )

    def get_macs(self) -> list[MacEntry]:
        raise UnsupportedCapabilityError(_NO_MACS)

    def get_lldp(self) -> list[LLDPNeighbor]:
        raise UnsupportedCapabilityError(_NO_LLDP)

    def get_sensors(self) -> list[Sensor]:
        raise UnsupportedCapabilityError(_NO_SENSORS)

    def get_poe(self) -> list[PoEStatus]:
        raise UnsupportedCapabilityError(_NO_POE)


class AsyncNsdpReader:
    """Asynchronous NSDP read facade (mirror of NsdpReader)."""

    def __init__(self, client: AsyncNsdpClient, model: SwitchModel) -> None:
        _require_nsdp(model)
        self.client = client
        self.model = model

    async def _device(self, tags: list[Tag]) -> NsdpDevice:
        return parse_device(await self.client.read(tags))

    async def get_ports(self) -> list[PortStatus]:
        return _ports(await self._device([Tag.PORT_COUNT, Tag.PORT_STATUS]))

    async def get_stats(self) -> list[PortStats]:
        return _stats(await self._device([Tag.PORT_STATISTICS]))

    async def get_vlans(self) -> list[VLANInfo]:
        return _vlans(await self._device([Tag.PORT_COUNT, Tag.VLAN_MEMBERS]))

    async def get_pvids(self) -> list[tuple[int, int]]:
        dev = await self._device([Tag.PORT_PVID])
        return [(p.port_id, p.vlan_id) for p in dev.port_pvids]

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        return _mgmt(
            await self._device(
                [Tag.IP_ADDRESS, Tag.NETMASK, Tag.GATEWAY, Tag.DHCP_MODE]
            )
        )

    async def get_macs(self) -> list[MacEntry]:
        raise UnsupportedCapabilityError(_NO_MACS)

    async def get_lldp(self) -> list[LLDPNeighbor]:
        raise UnsupportedCapabilityError(_NO_LLDP)

    async def get_sensors(self) -> list[Sensor]:
        raise UnsupportedCapabilityError(_NO_SENSORS)

    async def get_poe(self) -> list[PoEStatus]:
        raise UnsupportedCapabilityError(_NO_POE)
