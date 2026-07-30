"""NSDP-native parsed value types. Lifted from ``gdoc2netcfg/src/nsdp/types.py``.

These are the raw protocol shapes the parsers return; ``nsdp_read.py`` maps them
onto the shared ``models.py`` types. Named with an ``Nsdp`` prefix so they never
collide with the public ``models`` dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

_MBPS = {
    0x00: 0,
    0x01: 10,
    0x02: 10,
    0x03: 100,
    0x04: 100,
    0x05: 1000,
    0xFF: 10000,
}


class LinkSpeed(IntEnum):
    DOWN = 0x00
    HALF_10M = 0x01
    FULL_10M = 0x02
    HALF_100M = 0x03
    FULL_100M = 0x04
    GIGABIT = 0x05
    # ASSUMED/UNVERIFIED — the reference spec states 2.5G/5G/10G speed byte
    # values are undocumented and require a hardware capture; 0xFF is carried
    # over from prior art without independent confirmation.
    TEN_GIGABIT = 0xFF

    @classmethod
    def from_byte(cls, value: int) -> LinkSpeed:
        try:
            return cls(value)
        except ValueError:
            return cls.DOWN  # unknown 2.5G/5G codes: report DOWN, never raise

    @property
    def speed_mbps(self) -> int:
        return _MBPS.get(int(self), 0)


class VLANEngine(IntEnum):
    DISABLED = 0
    BASIC_PORT = 1
    ADVANCED_PORT = 2
    BASIC_802_1Q = 3
    ADVANCED_802_1Q = 4


@dataclass(frozen=True)
class NsdpPortStatus:
    port_id: int
    speed: LinkSpeed


@dataclass(frozen=True)
class NsdpPortStatistics:
    port_id: int
    bytes_received: int
    bytes_sent: int
    crc_errors: int


@dataclass(frozen=True)
class NsdpVlanMembership:
    vlan_id: int
    member_ports: frozenset[int]
    tagged_ports: frozenset[int] = frozenset()

    @property
    def untagged_ports(self) -> frozenset[int]:
        return self.member_ports - self.tagged_ports


@dataclass(frozen=True)
class NsdpPortPvid:
    port_id: int
    vlan_id: int


@dataclass(frozen=True)
class NsdpPortMirroring:
    """Port mirroring configuration (NSDP tag 0x5C00).

    Lifted from ``gdoc2netcfg/src/nsdp/types.py::PortMirroring``.

    Attributes:
        destination_port: Port receiving mirrored traffic (0 = disabled).
        source_ports: Ports being mirrored.
    """

    destination_port: int
    source_ports: frozenset[int] = frozenset()


@dataclass(frozen=True)
class NsdpIgmpSnooping:
    """IGMP snooping configuration (NSDP tag 0x6800).

    Lifted from ``gdoc2netcfg/src/nsdp/types.py::IGMPSnooping``.

    Attributes:
        enabled: Whether IGMP snooping is enabled.
        vlan_id: VLAN for IGMP snooping (if applicable); ``None`` when the
            wire value is 0 (no VLAN association).
    """

    enabled: bool
    vlan_id: int | None = None


@dataclass(frozen=True)
class NsdpDevice:
    model: str
    mac: str
    hostname: str | None = None
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    firmware_version: str | None = None
    dhcp_enabled: bool | None = None
    port_count: int | None = None
    serial_number: str | None = None
    vlan_engine: VLANEngine | None = None
    port_status: tuple[NsdpPortStatus, ...] = ()
    port_statistics: tuple[NsdpPortStatistics, ...] = ()
    vlan_members: tuple[NsdpVlanMembership, ...] = ()
    port_pvids: tuple[NsdpPortPvid, ...] = field(default_factory=tuple)
    # QoS engine mode (tag 0x3400): 0=disabled, 1=port-based, 2=802.1p.
    qos_engine: int | None = None
    # Port mirroring configuration (tag 0x5C00).
    port_mirroring: NsdpPortMirroring | None = None
    # IGMP snooping configuration (tag 0x6800).
    igmp_snooping: NsdpIgmpSnooping | None = None
    # Whether broadcast storm filtering is enabled (tag 0x5400).
    broadcast_filtering: bool | None = None
    # Whether loop detection is enabled (tag 0x9000).
    loop_detection: bool | None = None
