"""Public device-data model: frozen dataclasses returned by both APIs."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class PoEDetect(enum.Enum):
    DISABLED = "disabled"
    SEARCHING = "searching"
    DELIVERING = "delivering"
    FAULT = "fault"
    UNKNOWN = "unknown"


class VlanMode(enum.Enum):
    UNTAGGED = "untagged"
    TAGGED = "tagged"
    EXCLUDED = "excluded"


@dataclass(frozen=True)
class PortStatus:
    port: int
    name: str | None
    admin_enabled: bool
    link_up: bool
    speed_mbps: int | None


@dataclass(frozen=True)
class PoEStatus:
    port: int
    admin_enabled: bool
    detect: PoEDetect
    power_mw: int | None

    @property
    def delivering(self) -> bool:
        return self.detect is PoEDetect.DELIVERING


@dataclass(frozen=True)
class VLANInfo:
    vlan_id: int
    name: str | None
    member_ports: frozenset[int]
    tagged_ports: frozenset[int]
    untagged_ports: frozenset[int]


@dataclass(frozen=True)
class LLDPNeighbor:
    local_port: int
    remote_sys_name: str | None
    remote_port_desc: str | None
    remote_chassis_id: str | None


@dataclass(frozen=True)
class MacEntry:
    mac: str
    port: int
    vlan_id: int | None


@dataclass(frozen=True)
class Sensor:
    name: str
    kind: str  # "temperature" | "fan" | "power"
    value: float
    unit: str


@dataclass(frozen=True)
class SwitchData:
    model: str
    host: str
    ports: tuple[PortStatus, ...] = ()
    poe: tuple[PoEStatus, ...] = ()
    vlans: tuple[VLANInfo, ...] = ()
    pvids: tuple[tuple[int, int], ...] = ()
    lldp: tuple[LLDPNeighbor, ...] = ()
    macs: tuple[MacEntry, ...] = ()
    sensors: tuple[Sensor, ...] = ()
