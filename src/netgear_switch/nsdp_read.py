"""Model-driven NSDP read operations over a sync or async client.

Parallel to ``snmp_read.py``. Maps NSDP TLVs onto the SAME public ``models``
types: port link/speed/flow-control, per-port descriptions, byte/CRC
statistics, VLAN membership, PVID and management IP.

MAC/FDB, LLDP, sensors and PoE raise ``UnsupportedCapabilityError``, and that
is now MEASURED rather than asserted -- see ``_NO_MACS`` & co. below for the
captured evidence and how to reproduce it.
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

# The four refusals below used to be bare assertions. They are now grounded in
# a MEASURED, exhaustive tag sweep of a real GS110EMX (10.1.5.25, firmware
# 1.0.2.8, 2026-07-30) plus that firmware's own web-UI page inventory.
#
# Method (reproducible; see the "NSDP tag inventory" note in docs/): one
# READ_REQUEST per tag was sent for EVERY 0xNN00 tag in the whole 16-bit space
# (256 probes) and for every tag 0x0000-0x00FF (256 more). The switch answers a
# tag it cannot serve with header error code 3 ("attribute not readable") naming
# that tag in the header's error-attribute field, so the reply distinguishes
# "tag exists" from "tag does not" without guessing. Tags resolve on a 0x0400
# grid, so the 0xNN00 sweep covers every distinct tag.
#
# The complete set the GS110EMX answers is:
#   identity/auth : 0x0001 0x0002 0x0003 0x0004 0x0005 0x0006 0x0007 0x0008
#                   0x000A 0x000B 0x000C 0x000D 0x000E 0x000F 0x0014 0x0017
#                   0x0019
#   per-port      : 0x0800 0x0C00 0x1000 0x3000 0x3800 0x8800 0x9400 0xB000
#   VLAN          : 0x2000 0x2400 0x2800 0x6400
#   other         : 0x3400 0x5400 0x5C00 0x6000 0x6800 0x6C00 0x7000 0x7400
#                   0x7800 0x7C00 0x8000 0x8C00 0xA800 0xF000 0xF800
# There is NO tag anywhere in that space carrying a forwarding table, an LLDP
# neighbour, a temperature/fan reading or a PoE row -- the largest per-port TLV
# is the 49-byte PORT_STATISTICS counter block.
#
# Independent corroboration from the same device: its firmware's own navigation
# file (``GET /frame.js``) enumerates all 37 web-UI pages, and there is no MAC
# address table page, no LLDP page, no sensor page and no PoE page among them.
_SWEEP = (
    "measured by an exhaustive NSDP tag sweep of a real GS110EMX "
    "(10.1.5.25, firmware 1.0.2.8, 2026-07-30) covering every tag in the "
    "16-bit space; see nsdp_read.py for the full tag inventory"
)
_NO_MACS = f"NSDP has no MAC/FDB table tag ({_SWEEP})"
_NO_LLDP = f"NSDP has no LLDP neighbour tag ({_SWEEP})"
_NO_SENSORS = f"NSDP has no environmental-sensor tag ({_SWEEP})"
# PoE: the sweep found no PoE tag either. Separately, neither NSDP-class model
# with a reachable unit is a PSE at all -- gs110emx has poe_port_count=0 (and
# no PoE page in its own /frame.js nav), and gs105pe is PoE PASS-THROUGH with
# poe_port_count=0 (its web UI 404s getPoePortStatus.cgi). gs305ep IS a PSE and
# reads PoE over its HTTP backend (poe_status_path=/getPoePortStatus.cgi).
_NO_POE = f"NSDP has no PoE status tag ({_SWEEP}); use the HTTP backend for PoE"

# Every read-tag ``parse_device`` knows how to decode, requested together so
# ``get_device()``/``nsdp_device()`` returns the COMPLETE NsdpDevice in one
# round trip -- identity, mgmt IP, per-port status/stats, VLANs/PVIDs, and the
# QoS/mirroring/IGMP/broadcast-filtering/loop-detection tags (see parsers.py).
#
# A tag this model does not answer is simply OMITTED from a multi-tag reply --
# MEASURED on 10.1.5.25 (fw 1.0.2.8): requesting [MODEL, LOOP_DETECTION] returns
# error 0 with just the MODEL TLV, and the full list below (which includes
# LOOP_DETECTION 0x9000, a tag that firmware does not serve) returns error 0
# with 57 TLVs. The error-3 refusal only happens when an unanswerable tag is the
# ONLY tag requested. So this list is safe to keep model-agnostic.
_FULL_DEVICE_TAGS = [
    Tag.MODEL,
    Tag.MAC,
    Tag.HOSTNAME,
    Tag.PORT_NAME,
    Tag.IP_ADDRESS,
    Tag.NETMASK,
    Tag.GATEWAY,
    Tag.FIRMWARE_VER_1,
    Tag.DHCP_MODE,
    Tag.PORT_COUNT,
    Tag.SERIAL_NUMBER,
    Tag.VLAN_ENGINE,
    Tag.PORT_STATUS,
    Tag.PORT_STATISTICS,
    Tag.VLAN_MEMBERS,
    Tag.PORT_PVID,
    Tag.QOS_ENGINE,
    Tag.PORT_MIRRORING,
    Tag.IGMP_SNOOPING,
    Tag.BROADCAST_FILTERING,
    Tag.LOOP_DETECTION,
]


def _require_nsdp(model: SwitchModel) -> None:
    if Backend.NSDP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no NSDP backend")


def _with_model(tags: list[Tag]) -> list[Tag]:
    """Prepend ``Tag.MODEL`` to a per-op read's tag list.

    Real Plus hardware answers a read with ONLY the tags requested (confirmed
    live on a GS105PE, 2026-07-21: a read omitting MODEL either times out or
    returns a MODEL-less response), and ``parse_device`` requires a MODEL tag to
    build an ``NsdpDevice``. The virtual NSDP face historically emitted MODEL
    unconditionally, so the per-op reads (which never requested it) passed in the
    mock while failing on real switches. Requesting MODEL on every read is cheap
    (one extra TLV) and makes the per-op ops work against real hardware."""
    if Tag.MODEL in tags:
        return tags
    return [Tag.MODEL, *tags]


def _ports(dev: NsdpDevice) -> list[PortStatus]:
    # PORT_STATUS carries no name, but tag 0xB000 (PORT_NAME) does -- measured
    # on three real GS110EMX units, see Tag.PORT_NAME. get_ports() requests both
    # in one round trip, so the NSDP backend now reports the same operator
    # descriptions the model's HTTP backend does instead of a blanket None.
    names = {n.port_id: n.name for n in dev.port_names}
    return [
        PortStatus(
            port=s.port_id,
            name=names.get(s.port_id),
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
        mode=mode,
        address=dev.ip,
        netmask=dev.netmask,
        gateway=dev.gateway,
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
        return parse_device(self.client.read(_with_model(tags)))

    def get_ports(self) -> list[PortStatus]:
        return _ports(self._device([Tag.PORT_COUNT, Tag.PORT_STATUS, Tag.PORT_NAME]))

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

    def get_device(self) -> NsdpDevice:
        """Return the COMPLETE raw ``NsdpDevice`` for this switch: every tag
        ``parse_device`` knows how to decode, in one round trip. Unlike the
        other ``get_*`` ops above, this returns the NSDP-native shape
        (including the raw port-status speed byte) rather than mapping onto
        the shared ``models`` types -- callers that need the full protocol
        surface (e.g. gdoc2netcfg's DiscoveryDB) use this instead of the
        per-field ops."""
        return self._device(_FULL_DEVICE_TAGS)

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
        return parse_device(await self.client.read(_with_model(tags)))

    async def get_ports(self) -> list[PortStatus]:
        return _ports(
            await self._device([Tag.PORT_COUNT, Tag.PORT_STATUS, Tag.PORT_NAME])
        )

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

    async def get_device(self) -> NsdpDevice:
        """Async twin of ``NsdpReader.get_device`` -- see there."""
        return await self._device(_FULL_DEVICE_TAGS)

    async def get_macs(self) -> list[MacEntry]:
        raise UnsupportedCapabilityError(_NO_MACS)

    async def get_lldp(self) -> list[LLDPNeighbor]:
        raise UnsupportedCapabilityError(_NO_LLDP)

    async def get_sensors(self) -> list[Sensor]:
        raise UnsupportedCapabilityError(_NO_SENSORS)

    async def get_poe(self) -> list[PoEStatus]:
        raise UnsupportedCapabilityError(_NO_POE)
