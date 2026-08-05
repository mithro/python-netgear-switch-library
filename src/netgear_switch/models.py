"""Public device-data model: frozen dataclasses returned by both APIs."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


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
class PortSpeed:
    """A port's CONFIGURED speed/duplex -- what it is SET to, not what it got.

    Deliberately NOT folded into ``PortStatus.speed_mbps``, which is the
    OPERATIONAL rate the link actually came up at. The two answer different
    questions and neither substitutes for the other: a port configured ``auto``
    can be running at 100 Mbit/s, and a port forced to 100 Mbit/s full-duplex
    still reports no operational rate at all while its link is down. Overloading
    one field would have made "what did I configure?" unanswerable exactly when
    it matters most -- on a down port, which is the only kind this library is
    allowed to reconfigure.

    ``autonegotiate`` is the whole of the configuration when it is True:
    ``speed_mbps`` and ``full_duplex`` are then None, because an auto port has
    no configured rate -- it has whatever it negotiates. A FORCED configuration
    carries both, because every firmware measured here requires the duplex to be
    named alongside the rate (``speed 100 full-duplex``).

    NOT representable, deliberately: auto-negotiation with a restricted
    ADVERTISED rate list (FASTPATH's ``speed auto [10] [100] [1000] [10G]``).
    The grammar accepts it, but ``show port``'s Physical Mode column reports a
    bare ``Auto`` for it -- measured on gsm7252ps 10.1.5.22 port 1/0/8,
    2026-08-03, where ``speed auto 1000`` read back identically to ``speed
    auto``. Offering it would mean offering a write this library cannot verify
    it made, so it is left out until a read that can distinguish the two (the
    running-config line) is built.
    """

    autonegotiate: bool
    speed_mbps: int | None = None
    full_duplex: bool | None = None

    def __post_init__(self) -> None:
        if self.autonegotiate:
            if self.speed_mbps is not None or self.full_duplex is not None:
                raise ValueError(
                    "an auto-negotiating port has no configured rate or duplex; "
                    "leave speed_mbps and full_duplex as None"
                )
        elif self.speed_mbps is None or self.full_duplex is None:
            raise ValueError(
                "a forced port configuration needs BOTH a rate and a duplex "
                "(the firmware's own grammar requires them together)"
            )

    @classmethod
    def auto(cls) -> PortSpeed:
        """Auto-negotiate (the factory default on every switch measured here)."""
        return cls(autonegotiate=True)

    @classmethod
    def forced(cls, speed_mbps: int, *, full_duplex: bool) -> PortSpeed:
        """Force a fixed rate and duplex, disabling auto-negotiation."""
        return cls(autonegotiate=False, speed_mbps=speed_mbps, full_duplex=full_duplex)

    def __str__(self) -> str:
        if self.autonegotiate:
            return "auto"
        return f"{self.speed_mbps}M {'full' if self.full_duplex else 'half'}-duplex"


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
    #: Whether the link negotiated FULL duplex. ``None`` when the backend cannot
    #: tell -- a down port has no negotiated duplex, and not every backend
    #: reports it at all. Measured 2026-08-02: the M4300's EtherLike-MIB dot3
    #: table exposes only error counters, NOT dot3StatsDuplexStatus (column 19
    #: is absent), so SNMP cannot answer this and leaves it None. The FASTPATH
    #: CLI does: `show port all` reports "1000 Full" in its Physical Status
    #: column, carrying speed and duplex together.
    full_duplex: bool | None = None
    #: Whether IEEE 802.3x flow control is enabled on the port ("Flow Mode" in
    #: `show port all`). ``None`` where the backend does not report it.
    flow_control: bool | None = None
    #: The port's CONFIGURED speed/duplex -- ``show port``'s "Physical Mode"
    #: column, as opposed to the "Physical Status" column the three fields above
    #: come from. ``None`` where the backend cannot tell, which is every backend
    #: but the CLI so far: SNMP's ifSpeed and the Plus models' NSDP port record
    #: both report the NEGOTIATED rate only, and no vendor column carrying the
    #: admin setting has been located on any of them.
    speed_config: PortSpeed | None = None


@dataclass(frozen=True)
class PoEStatus:
    port: int
    admin_enabled: bool
    detect: PoEDetect
    power_mw: int | None

    @property
    def delivering(self) -> bool:
        return self.detect is PoEDetect.DELIVERING


def poe_cycle_complete(before: PoEStatus | None, now: PoEStatus | None) -> bool:
    """Has a power-cycled port finished coming back?

    Shared by every backend that power-cycles a port, because "back" is a
    property of the PORT, not of the protocol used to ask.

    What "back" means depends on what the port was doing, and getting it wrong
    turns a successful cycle into a reported failure. LIVE-PROVEN on
    sw-netgear-gs728tpp.monarto.mithis.com (10.2.5.10, firmware 6.0.1.30)
    2026-08-03: cycling port 17 -- link-down with NOTHING attached -- performed
    the off/on correctly and left the port SEARCHING, and a predicate demanding
    DELIVERING unconditionally polled the full 60s and then raised on a cycle
    that had worked. A port with no powered device can never reach DELIVERING.

    * powering a device before the cycle -> success is powering it again, which
      is the entire point of cycling it and the strict check worth keeping;
    * powering nothing before -> success is detection running again.
    """
    if now is None:
        return False
    if before is not None and before.delivering:
        return now.delivering
    return now.detect in (PoEDetect.DELIVERING, PoEDetect.SEARCHING)


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
class ServiceStatus:
    """One management service the switch offers, and whether it is on.

    Covers the four protocols an operator turns on or off to control how the
    switch itself can be reached: ``http``, ``https``, ``telnet`` and ``ssh``.
    """

    #: One of ``http``, ``https``, ``telnet``, ``ssh``.
    name: str
    enabled: bool
    #: The TCP port the service listens on, or ``None`` where the firmware does
    #: not report one. Measured: gsm7252ps omits the ``SSH Port`` line that
    #: m4300-24x prints, so this is genuinely absent rather than defaulted to 22.
    port: int | None = None


#: Access-mode text meaning FULL privilege, in every vocabulary measured so far.
#: There are three, and they do not agree -- the same two accounts on the same
#: two switches read differently depending on which face you ask (2026-08-02 /
#: 2026-08-03):
#:
#:   backend          m4300-24x admin   gsm7252ps admin   guest (both)
#:   CLI `show users` Privilege-15      Read/Write        Privilege-1 / Read Only
#:   web userManagement.html            Super User        Read Only
#:
#: Note the web UI is the CONSISTENT one: it says "Super User"/"Read Only" on
#: both switches, where the CLI's wording splits by firmware family. A parser
#: taught only one vocabulary would silently mis-report the others, so this
#: table is shared by every backend rather than living in one parser.
PRIVILEGED_ACCESS_MODES: frozenset[str] = frozenset(
    {"privilege-15", "read/write", "super user"}
)
UNPRIVILEGED_ACCESS_MODES: frozenset[str] = frozenset(
    {"privilege-1", "read only", "no access"}
)


def privileged_access(access_mode: str) -> bool | None:
    """Whether ``access_mode`` is a full-privilege level, or ``None`` if the
    word is one this library has not measured on a device."""
    text = access_mode.strip().lower()
    if text in PRIVILEGED_ACCESS_MODES:
        return True
    if text in UNPRIVILEGED_ACCESS_MODES:
        return False
    return None


@dataclass(frozen=True)
class SwitchUser:
    """One local login account on the switch."""

    name: str
    #: The access mode exactly as this firmware words it, on the FACE that was
    #: asked. Kept verbatim because the vocabulary is not shared -- see
    #: :data:`PRIVILEGED_ACCESS_MODES` for the three spellings measured so far.
    access_mode: str
    #: Whether ``access_mode`` is the full-privilege level, normalised across
    #: every measured vocabulary so callers do not have to know which image or
    #: which backend they are on. ``None`` when the text is none of them -- an
    #: unrecognised level is reported honestly rather than guessed.
    privileged: bool | None
    #: The three SNMPv3 columns the same table carries. ``None`` where the
    #: firmware prints nothing.
    snmpv3_access: str | None = None
    snmpv3_auth: str | None = None
    snmpv3_encryption: str | None = None


@dataclass(frozen=True)
class SyslogServer:
    """One remote syslog collector the switch is configured to send to."""

    host: str
    port: int
    #: Standard syslog severity, 0 (emergency) to 7 (debug). The switch sends
    #: messages AT OR ABOVE this level. Cross-checked on m4300-24x: the SNMP
    #: column reads 6 where ``show logging hosts`` prints "info".
    severity: int
    #: The switch's own word for the row's state, "Active" in the CLI table.
    active: bool


#: Syslog severity names as the switches PRINT them, mapped to the standard
#: numbers the SNMP columns carry. Netgear spells the same value differently
#: depending on which face you ask, so this is shared rather than per-backend:
#: the FASTPATH CLI's `show logging hosts` prints "info" (lowercase) while the
#: web UI's Severity Filter column prints "Info" -- MEASURED on the same
#: collector row of the same switch (m4300-24x 10.1.5.13, 2026-08-03), where
#: the SNMP severity column reads 6.
#:
#: "informational" is listed beside "info" because it is the word FASTPATH's
#: own `logging host` command accepts; both are severity 6.
SYSLOG_SEVERITY_NAMES: Mapping[str, int] = MappingProxyType(
    {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5,
        "info": 6,
        "informational": 6,
        "debug": 7,
    }
)


#: The canonical WORD each severity number is written back as. The inverse of
#: SYSLOG_SEVERITY_NAMES is not a function -- 6 has two spellings there -- so
#: the one a command may carry is pinned rather than derived. "info" is the
#: spelling every switch's own running-config uses (`logging host "10.1.5.1"
#: ipv4 514 info`, read off all four FASTPATH models 2026-08-05).
SYSLOG_SEVERITY_WORDS: Mapping[int, str] = MappingProxyType(
    {
        0: "emergency",
        1: "alert",
        2: "critical",
        3: "error",
        4: "warning",
        5: "notice",
        6: "info",
        7: "debug",
    }
)


def syslog_severity_word(level: int) -> str:
    """A severity NUMBER -> the word a switch command carries.

    Raises on anything outside 0-7 rather than emitting the integer: syslog
    severities are a closed set, and a command built from an out-of-range value
    would be rejected by the device with a message that names the command
    rather than the caller's mistake.
    """
    try:
        return SYSLOG_SEVERITY_WORDS[level]
    except KeyError:
        raise ValueError(
            f"syslog severity {level!r} is outside the standard range 0-7"
        ) from None


def syslog_severity(name: str) -> int:
    """A switch's severity WORD -> its standard number, case-insensitively.

    Raises ``ValueError`` on a word this library has not measured. That is
    deliberate: the obvious alternative -- defaulting to 0 -- reports the
    switch as forwarding EMERGENCIES ONLY, which is both wrong and invisible,
    and 0 is indistinguishable from a genuine "emergency" row. An unrecognised
    word means a firmware spells a level differently than any device measured
    here, and the caller should see that rather than a plausible number.
    """
    try:
        return SYSLOG_SEVERITY_NAMES[name.strip().lower()]
    except KeyError:
        raise ValueError(
            f"unknown syslog severity {name!r}; measured names are "
            f"{sorted(SYSLOG_SEVERITY_NAMES)}"
        ) from None


@dataclass(frozen=True)
class SyslogConfig:
    """Remote-logging configuration: whether it is on, and where it sends.

    Deliberately narrower than everything ``show logging`` prints. The console
    and buffered-logging columns are in the same vendor subtree, but only the
    console pair could be decoded against captured CLI output; the buffered
    severity did not match any column read, so it is left out rather than
    guessed at. See ``VendorOids.syslog_*``.
    """

    enabled: bool
    #: The source port the switch sends FROM (``Logging Client Local Port``),
    #: not the collector's port -- that is per-server in ``servers``.
    local_port: int
    servers: tuple[SyslogServer, ...]


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
