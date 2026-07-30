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


class IpMode(enum.Enum):
    DHCP = "dhcp"
    STATIC = "static"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PortStatus:
    port: int
    name: str | None
    admin_enabled: bool
    link_up: bool
    speed_mbps: int | None
    # ifAlias (operator-set port description) -- distinct from `name` (ifName).
    # Defaults to None so existing positional call sites (name-only backends,
    # older tests) keep constructing without it; a backend that cannot read
    # ifAlias (NSDP, HTTP) leaves it honestly None rather than fabricating "".
    description: str | None = None


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
    # lldpRemPortId (LLDP-MIB column 7): the remote port's IDENTIFIER, distinct
    # from remote_port_desc (lldpRemPortDesc, column 8) -- e.g. a neighbour can
    # report port_id "gi24" and port_desc "gi24.uplink" as different values.
    # Defaults to None so existing positional call sites (older tests, a
    # backend that cannot read this column) keep constructing without it.
    remote_port_id: str | None = None


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
class PortStats:
    port: int
    rx_bytes: int | None
    tx_bytes: int | None
    rx_packets: int | None
    tx_packets: int | None
    rx_errors: int | None
    tx_errors: int | None


@dataclass(frozen=True)
class MgmtIpConfig:
    mode: IpMode
    address: str | None
    netmask: str | None
    gateway: str | None
    # dot1dBaseBridgeAddress (BRIDGE-MIB) / the NSDP identity MAC / the HTTP
    # sysInfo.html "MAC Address" row: the switch's own base MAC, formatted
    # "XX:XX:XX:XX:XX:XX" (uppercase) by every backend that reads it (SNMP's
    # parse_base_mac, NSDP's .upper(), HTTP's _mgmt_ip_from_sysinfo -- the
    # real captured HTTP page text is lowercase and gets normalized). Defaults
    # to None so existing positional call sites keep constructing without it;
    # a backend/model whose web UI has no such page at all (gs305ep,
    # gsm7228ps) leaves it honestly None via UnsupportedCapabilityError
    # rather than fabricating a value.
    base_mac: str | None = None


@dataclass(frozen=True)
class DetectedModel:
    """Result of identifying a switch's model over SNMP (sysObjectID + sysDescr).

    ``key`` is a registry key (see ``registry.get_model``) if the switch was
    confidently identified -- either by a real-capture-confirmed sysObjectID
    (``parse.detect_model_from_sysobjectid``, tried first) or, failing that, by
    its sysDescr matching exactly one registered model's name
    (``parse.detect_model_from_sysdescr``) -- or ``None`` if neither did (an
    unregistered Netgear model, a non-Netgear device, or an unreadable/absent
    reply). ``None`` is NEVER a fabricated guess.

    ``sys_descr``/``sys_object_id`` are the raw SNMP-reported strings, kept
    for the caller/logging even when unmatched. ``sys_object_id`` IS the
    PREFERRED matching signal: an unambiguous manufacturer product identifier,
    so it can distinguish SKUs whose sysDescr text is indistinguishable (the
    S3300-52X vs the unregistered S3300-28X). Its map (``SYSOBJECTID_MODELS``)
    holds ONLY OIDs proven by a live capture, never a spec-sheet guess, so a
    model with no committed capture is still identified purely by sysDescr.
    """

    key: str | None
    sys_descr: str | None
    sys_object_id: str | None

    @property
    def matched(self) -> bool:
        return self.key is not None


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
    stats: tuple[PortStats, ...] = ()
    mgmt_ip: MgmtIpConfig | None = None
