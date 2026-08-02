"""The one authoritative in-memory virtual-switch device state.

``VirtualSwitchState`` holds everything a simulated switch "knows" about
itself — port link/admin/speed, counters, VLANs, PoE, sensors, the MAC/FDB
table, LLDP neighbours and the management IP — as small mutable ``*Sim``
dataclasses. ``oid_map()`` projects that state onto the flat numeric
OID -> (snmp_type, value) view a protocol face (Task 15) serves and the
Task 5-9 parsers consume. This module is pure data + projection: no network.
"""

from __future__ import annotations

import copy
import dataclasses
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..registry import get_model

if TYPE_CHECKING:
    from ..protocols.nsdp.protocol import Tag, TLVEntry


class CommitFailedError(Exception):
    """The agent accepted the varbind's type but refused to apply it.

    Models a real SNMP ``commitFailed``. VERIFIED on an M4300-24X (FASTPATH
    12.0.13.8): a SET of dot1qVlanStaticEgressPorts commitFails even when
    writing back byte-identical octets, because per-port switchport mode -- not
    the Q-BRIDGE PortList -- owns VLAN membership on that firmware.
    """


class NotWritableError(Exception):
    """The object exists but is read-only (real agents answer notWritable)."""


class InconsistentValueError(Exception):
    """The agent refuses this value in the device's current state.

    Models a real SNMP ``inconsistentValue``. VERIFIED on the GS728TPP
    (sw-netgear-gs728tpp.monarto.mithis.com / 10.2.5.10, firmware 6.0.1.30,
    2026-08-03): every documented way of CREATING a dot1qVlanStaticTable row is
    refused with exactly this error -- createAndGo(4) alone, createAndGo with
    dot1qVlanStaticName in the same PDU, createAndWait(5) then name then
    active(1), setting the name column alone, and createAndGo carrying an empty
    126-byte egress PortList. The same firmware happily writes an EXISTING
    row's membership and accepts destroy(6), so this is specifically row
    creation, not a read-only table.
    """


def _all_vlans_bitmap() -> bytes:
    """A switchport allowed-VLAN bitmap with VLANs 1..4093 set.

    Matches the real M4300 default: a live read of the allowed-VLAN column
    returned 4093 VLANs set in a 512-byte map.
    """
    from ..protocols.snmp.oids import SWITCHPORT_VLAN_BITMAP_BYTES

    data = bytearray(SWITCHPORT_VLAN_BITMAP_BYTES)
    for vlan in range(1, 4094):
        data[(vlan - 1) // 8] |= 0x80 >> ((vlan - 1) % 8)
    return bytes(data)


def _vlan_bitmap_bytes(vlans: set[int]) -> bytes:
    """Encode VLAN ids into a 512-byte switchport bitmap (inverse of below)."""
    from ..protocols.snmp.oids import SWITCHPORT_VLAN_BITMAP_BYTES

    data = bytearray(SWITCHPORT_VLAN_BITMAP_BYTES)
    for vlan in vlans:
        data[(vlan - 1) // 8] |= 0x80 >> ((vlan - 1) % 8)
    return bytes(data)


def _vlans_in_bitmap(bitmap: bytes) -> set[int]:
    """Decode a switchport VLAN bitmap (MSB-first, VLAN 1 = bit 7 of byte 0)."""
    return {
        i * 8 + off + 1
        for i, byte in enumerate(bitmap)
        for off in range(8)
        if byte & (0x80 >> off)
    }


def encode_port_bitmap(ports: set[int], width_bytes: int = 8) -> str:
    """Inverse of ``parse.decode_port_bitmap``: a port set -> a latin-1 bitmap.

    Delegates to the canonical bytes encoder in
    ``protocols/snmp/write.encode_port_bitmap`` (single source of truth for the
    MSB-first bit-packing) and decodes to the latin-1 ``str`` this module's
    callers expect.
    """
    from ..protocols.snmp.write import encode_port_bitmap as _encode_bytes

    return _encode_bytes(ports, width_bytes).decode("latin-1")


def _mbps_to_speed_byte(mbps: int) -> int:
    """Map a negotiated Mbps rate to its NSDP LinkSpeed wire byte.

    10G is 0x06, MEASURED off real hardware -- a GS110EMX (10.1.5.25/.26, fw
    1.0.2.8, 2026-07-30) answers PORT_STATUS ``09 06 01`` / ``0a 06 01`` for the
    two uplinks its own web UI shows as "10G Full". This mock previously emitted
    0xFF here, the same unverified prior-art guess the DECODER carried, so mock
    and code agreed with each other while both disagreed with every real
    GS110EMX -- the exact failure mode principle 5 exists to prevent. 0xFF is
    still decoded (see LinkSpeed.TEN_GIGABIT_PRIOR_ART) but is never emitted.
    """
    return {10: 0x02, 100: 0x04, 1000: 0x05, 10000: 0x06}.get(mbps, 0x00)


@dataclass
class PortSim:
    """One switch port's link/admin/speed/name plus optional HC counters.

    Counters are ``int | None``: ``None`` means "this port does not expose
    this counter" and must round-trip to an *absent* row in ``oid_map()`` (no
    fabricated zero), so ``parse_port_stats`` yields ``None`` there too.
    """

    name: str
    admin: bool
    link: bool
    speed: int
    # ifType (IF-MIB): 6=ethernetCsmacd (a physical port -- the default). Real
    # hardware also exposes non-physical rows in the same ifTable -- LAGs
    # (161=ieee8023adLag), the CPU interface (1=other), VLAN routing interfaces
    # (135=l2vlan) -- which the read path filters OUT (parse._physical_ports).
    # Seeds that add those interfaces set if_type so the mock's SNMP get_ports/
    # get_stats/get_pvids drop them exactly as real hardware does (and as the
    # mock's own HTTP/CLI backends already do), instead of fabricating phantom
    # ports the web/CLI faces never list.
    if_type: int = 6
    rx_octets: int | None = None
    tx_octets: int | None = None
    rx_ucast: int | None = None
    tx_ucast: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    # FASTPATH switchport mode ("access" | "general" | "trunk"), the CLI-only
    # attribute that decides whether a ``vlan participation``/``vlan tagging``/
    # ``vlan pvid`` command actually TAKES EFFECT on this port. Proven live on an
    # M4300-24X: in access mode those commands are accepted into running-config
    # yet ``show vlan <id>`` keeps reporting Exclude/Autodetect -- see
    # ``faces/cli.py``, which reproduces exactly that inertness, and
    # ``cli_write.CliWriter``, which therefore always sends
    # ``switchport mode general`` first.
    # Defaults to "general" because that is what the SEEDS describe: every seed
    # is transcribed from a real switch whose ports genuinely ARE members of
    # (often several, often tagged) VLANs, which on real hardware requires
    # general/trunk mode. A test that wants the access-mode behaviour sets this
    # to "access" explicitly. NOT part of any SNMP/NSDP/HTTP projection: no
    # captured MIB/TLV/web page exposes it (it is a CLI running-config notion),
    # so oid_map()/nsdp_tlvs() deliberately ignore it.
    switchport_mode: str = "general"
    # ifAlias (operator-set port description). None = this port's ifAlias
    # column instance is entirely absent (never configured), mirroring real
    # hardware where an unset alias may not answer at all -- not a fabricated
    # "".
    description: str | None = None
    # IEEE 802.3x flow control, as reported in NSDP PORT_STATUS byte 2 and in
    # the Plus web UI's "Flow Control" column. MEASURED per-port on three real
    # GS110EMX units (2026-07-30): 10.1.5.25/.26 answer 0x01 on every port and
    # their pages say Enable; 10.1.5.27 answers 0x00 on every port and its page
    # says Disable. Defaults True, which is the factory default those first two
    # units are still on.
    flow_control: bool = True


@dataclass
class SyslogCollectorSim:
    """One remote syslog collector row, as the vendor host table reports it.

    Field values are SEEDED from a live switch, never computed: the severity is
    the standard syslog number the device actually returns (6 for "info" on
    m4300-24x, cross-checked against its own `show logging hosts`), and status 1
    is what that command prints as "Active".
    """

    host: str
    port: int
    severity: int
    status: int = 1


@dataclass
class SyslogSim:
    """The switch's remote-logging state, as the vendor `.14` subtree reports it.

    MEASURED 2026-08-02 -- see docs/superpowers/specs/. ``admin_mode`` is the
    device's own enum (1 = enabled, 2 = disabled), kept as the raw integer
    rather than a bool so the mock emits exactly what a real agent emits and the
    reader's own decoding is what gets exercised.
    """

    admin_mode: int = 2
    local_port: int = 514
    collectors: list[SyslogCollectorSim] = field(default_factory=list)


@dataclass
class VlanSim:
    """One dot1q VLAN: display name plus egress-member and untagged port sets.

    ``member``/``untagged`` are the **CURRENT** (operational) egress sets -- what
    ``show vlan <id>`` prints under ``Current: Include``, what the FASTPATH
    ``vlanStatus.html`` Member Ports cell lists, and what the VLAN Membership
    page's ``hiddenTagged``/``hiddenUnTagged`` ifName lists carry.
    """

    name: str
    member: set[int] = field(default_factory=set)
    untagged: set[int] = field(default_factory=set)
    # Ports that are CONFIGURED into this VLAN but are NOT currently
    # participating -- ``show vlan`` prints them as ``Current: Exclude /
    # Configured: Include``. This is a REAL, MEASURED divergence, not a
    # theoretical one: on GSM7252PS @10.1.5.22, VLAN 1 lists ports 1/0/50 and
    # 1/0/51 exactly that way, so the switch reports them in
    # ``dot1qVlanStaticEgressPorts`` (the STATIC/configured table) and in the web
    # UI's ``hiddenMem`` grid, while omitting them from the CLI's current list,
    # from ``vlanStatus.html`` and from ``hiddenTagged``/``hiddenUnTagged``.
    #
    # Keeping the two views separate is what lets the mock reproduce that split;
    # collapsing them (as it did before) made the mock's SNMP and HTTP faces agree
    # with each other while both disagreed with hardware. Empty (the default) =
    # configured and current coincide, which is the normal case.
    configured_only: set[int] = field(default_factory=set)
    # Does this VLAN have a ``dot1qVlanStaticTable`` row at all?
    #
    # MEASURED on the GS728TPP (sw-netgear-gs728tpp.monarto.mithis.com /
    # 10.2.5.10, firmware 6.0.1.30, 2026-08-02): its default VLAN 1 does NOT.
    # A walk of dot1qVlanStaticName/Egress/Untagged/RowStatus returns exactly 12
    # rows -- ids 2,3,4,5,6,7,10,20,31,41,90,99 -- while dot1qVlanCurrentTable
    # returns 13, the extra one being VLAN 1 with dot1qVlanStatus = 1 (other)
    # where every other VLAN reads 2 (permanent). The web UI lists VLAN 1, so a
    # reader that consults only the static table loses it; see
    # protocols/snmp/parse.parse_vlans, which reads both tables because of this.
    #
    # True (the default) is the normal case and is itself measured: the
    # GSM7252PS, both M4300s and the S3300-52X all publish a static VLAN 1 row.
    static_row: bool = True

    @property
    def configured(self) -> set[int]:
        """The CONFIGURED egress set: current members plus ``configured_only``."""
        return self.member | self.configured_only


@dataclass(frozen=True)
class VlanMembershipPageSim:
    """MEASURED shape of one model's FASTPATH "VLAN Membership" page.

    Every field below is a number/flag read off a real capture of
    ``switching/dot1q/vlan_port_cfg.html`` (2026-07-30), NOT derived from the
    port count -- deliberately, for the same reason ``vlan_portlist_width`` is
    seeded rather than computed: a mock that re-derives a device constant using
    the code's own formula can only ever agree with the code (principle 5).

    Live measurements:

    ==========  =====  ========  ====  ==============  ====  ======
    model       slots  lag_slot  grid  trailing_comma  csrf  escape
    ==========  =====  ========  ====  ==============  ====  ======
    gsm7252ps     116         3  gif               no    no      no
    gsm7228ps      78         3  png               no    no     yes
    m4300-24x     152        13  png              yes    no     yes
    m4300-16x     144        13  png              yes   yes     yes
    ==========  =====  ========  ====  ==============  ====  ======

    ``slots`` = physical ports first, then the LAG pseudo-interfaces (so
    ``slots - port_count`` LAGs: 64 / 26 / 128 / 128). ``lag_slot`` is the middle
    component of a LAG ifName (``0/3/N`` on the gsm72xx, ``0/13/N`` on the
    M4300). ``grid`` selects which of the two firmware generations' port grids
    the page renders: ``"gif"`` = the older ``toggleImageFirst`` +
    ``grey_[btu].gif`` cells (0-BASED hiddenMem index), ``"png"`` = the jQuery
    ``togImg`` + ``switch_<state>_inactive.png`` cells (1-BASED index).
    ``trailing_comma`` reproduces the M4300 firmware appending an empty field to
    ``hiddenMem``/``hiddenTagged``. ``csrf`` renders the per-page ``CSRFToken``
    the M4300-16X requires back on every POST. ``escape`` HTML-entity-escapes the
    ifName lists (``1&#x2F;0&#x2F;49``) as every firmware but the gsm7252ps does.
    """

    slots: int
    lag_slot: int
    grid: str
    trailing_comma: bool = False
    csrf: bool = False
    escape: bool = False


@dataclass
class PoeSim:
    """One PoE port: RFC3621 admin/detect state plus vendor delivered power."""

    admin: bool
    detect: int
    power_mw: int = 0
    # How many more CLI ``show poe port info all`` reads still report the
    # pre-enable "Disabled" status after PoE was administratively re-enabled.
    #
    # MEASURED ON HARDWARE (M4300-16X, 10.1.5.20, FASTPATH 12.0.19.15,
    # 2026-07-30): right after ``poe`` re-enabled port 1/0/1 the table still said
    # ``Disabled``; the same port read ``Searching`` moments later. That column is
    # a DETECTION state, and it lags the admin write -- which made a single
    # immediate read-back report a perfectly good ``set_poe`` as a verification
    # failure. The mock reproduces the lag (one stale read) so
    # ``cli_write.CliWriter.set_poe``'s polling is actually exercised instead of
    # passing by accident; SNMP's pethPsePortAdminEnable has no such lag and is
    # deliberately unaffected.
    cli_status_lag_reads: int = 0


@dataclass
class SensorSim:
    """One box sensor reading (fan RPM / PSU watts / temperature).

    ``raw`` is the literal wire text: either a decimal integer string or
    Netgear's ``"Not Supported"`` placeholder for an unpopulated slot.
    """

    kind: str  # "fan" | "power" | "temperature"
    instance: str
    raw: str


@dataclass
class EntitySim:
    """One ENTITY-MIB entPhysicalTable component (index + class/name/descr).

    Used only by models whose SNMP agent exposes the fan/PSU sensor INVENTORY
    via the standard ENTITY-MIB rather than a Netgear vendor sensor column
    (verified: the GS728TPP). ``phys_class`` is the entPhysicalClass int enum
    (6=powerSupply, 7=fan). No live value/status exists on the wire -- this is
    inventory only (see protocols/snmp/parse.parse_entity_sensors)."""

    index: int
    phys_class: int
    name: str
    descr: str


@dataclass
class MacSim:
    """One learned MAC/FDB entry: VLAN, 6-byte MAC, bridge-port index."""

    vlan: int
    mac_bytes: tuple[int, int, int, int, int, int]
    bridge_port: int


@dataclass
class LldpSim:
    """One lldpRemTable neighbour row group."""

    time_mark: int
    local_port: int
    rem_idx: int
    chassis: str
    port_id: str
    port_desc: str
    sys_name: str


@dataclass
class MgmtSim:
    """The switch's own management-IP configuration."""

    address: str
    netmask: str
    gateway: str
    mode: str  # "static" | "dhcp"


@dataclass
class ScpCertDeploy:
    """Record of a FASTPATH ``copy scp://`` SSL-cert deploy the mock CLI face
    received (see ``virtual.faces.cli.VirtualCliFace.run_scp_copy``).

    Purely a record of the EXEC sequence the library ISSUED -- the copy commands
    and their ``nvram:`` destinations, plus the HTTPS toggle + save-config steps
    -- so a test can assert the deploy driver drove the switch correctly. It does
    NOT carry cert bytes: the SCP deploy pulls the PEM from a staging server the
    caller set up (the library only sends the copy commands), so there is no PEM
    to observe here. Not part of any SNMP/NSDP/HTTP projection.
    """

    commands: list[str] = field(default_factory=list)
    copies: list[tuple[str, str]] = field(default_factory=list)  # (source_url, dest)
    https_disabled: bool = False
    https_enabled: bool = False
    saved: bool = False


@dataclass
class VirtualSwitchState:
    """The one authoritative virtual-switch device state.

    A mutable holder (later slices mutate it to simulate writes); pure data
    plus the ``oid_map()`` SNMP projection, no network here.
    """

    model_key: str
    ports: dict[int, PortSim] = field(default_factory=dict)
    vlans: dict[int, VlanSim] = field(default_factory=dict)
    pvids: dict[int, int] = field(default_factory=dict)
    poe: dict[int, PoeSim] = field(default_factory=dict)
    # SNMP box sensors (the vendor box_fan/box_psu_power/box_temp columns
    # projected by oid_map()). This is the SNMP FACE's sensor set.
    sensors: list[SensorSim] = field(default_factory=list)
    # HTTP sysInfo box sensors, when the web UI exposes a DIFFERENT sensor set
    # than SNMP does (the gsm7252ps really does: SNMP reports fan RPM + PSU
    # watts, sysInfo.html reports temperatures + fan/PSU health text). Left
    # None on models whose two faces report the same sensors (e.g. the M4300,
    # whose web renderer reads ``sensors`` directly); a renderer that wants the
    # web-specific set uses ``sysinfo_sensors`` below.
    http_sensors: list[SensorSim] | None = None
    # ENTITY-MIB entPhysical inventory (entPhysicalClass/Name/Descr), for a
    # model whose SNMP agent exposes fan/PSU sensors ONLY as this standard
    # physical inventory and implements NO vendor sensor column (the GS728TPP).
    # Empty on every model that projects vendor box sensors via ``sensors``.
    entity_components: list[EntitySim] = field(default_factory=list)
    macs: list[MacSim] = field(default_factory=list)
    bridge_ports: dict[int, int] = field(default_factory=dict)
    lldp: list[LldpSim] = field(default_factory=list)
    mgmt: MgmtSim = field(
        default_factory=lambda: MgmtSim(
            address="0.0.0.0", netmask="0.0.0.0", gateway="0.0.0.0", mode="dhcp"
        )
    )
    model_name: str = ""
    serial: str = ""
    firmware: str = ""
    hostname: str = ""
    #: Remote-logging state. Only meaningful for a model with a vendor subtree;
    #: oid_map() projects it under <vendor base>.14 for those models only, which
    #: is what makes gs728tpp (no vendor OIDs) correctly unable to answer.
    syslog: SyslogSim = field(default_factory=SyslogSim)
    nsdp_password: str = "password"
    # Write-auth scheme this mock advertises via AUTH_V2_ENCPASS (0x0014), and
    # the ONLY scheme it accepts on a WRITE_REQUEST:
    # 1 = legacy v1 XOR (PASSWORD 0x000A), 0x10 = v2 salted challenge-response
    # (AUTH_V2_SALT 0x0017 -> AUTH_V2_PASSWORD 0x001A).
    #
    # MEASURED on the real GS110EMX units at 10.1.5.25/.26/.27 (firmware
    # 1.0.2.8, 2026-07-29/30): AUTH_V2_ENCPASS answers 0x00000010, and a
    # WRITE_REQUEST whose PASSWORD (0x000A) TLV carries the v1 repeating-XOR
    # encoding -- or a PLAINTEXT password -- is answered error=13 with the
    # header's error-attribute set to 0x000A, escalating to error=14 and then
    # silence on repeats. Setting this to 0x10 reproduces exactly that: the v2
    # handler in faces/nsdp.py finds no 0x001A token in a v1 packet and refuses
    # it 13/ATTR_PASSWORD. Older Plus units advertise 1, so the default 1 keeps
    # every other seeded model on the v1 path (see auth.ENCPASS_V1/ENCPASS_V2).
    nsdp_auth_version: int = 1
    # The last 4-byte salt this mock handed out on an AUTH_V2_SALT read. A real
    # switch rotates it on EVERY 0x0017 read and validates the next v2 write
    # against exactly this value; None = none issued yet (a v2 write with no
    # preceding salt read is rejected). Populated by nsdp_tlvs() below.
    nsdp_last_salt: bytes | None = None
    # Consecutive v2 auth failures, for the observed lockout: a GS110EMX escalates
    # error 13 -> 14 after a few rapid wrong tokens and then goes SILENT for a
    # cooldown. A successful write resets this to 0. (See faces/nsdp.py; the exact
    # real thresholds are firmware rate-based, approximated here.)
    nsdp_auth_failures: int = 0
    # QoS engine mode (NSDP tag 0x3400): None = unseeded (tag omitted from
    # nsdp_tlvs(), exactly like a real switch that doesn't answer it).
    nsdp_qos_engine: int | None = None
    # Port mirroring (NSDP tag 0x5C00): None destination = unseeded/disabled.
    nsdp_port_mirroring_dest: int | None = None
    nsdp_port_mirroring_sources: frozenset[int] = field(default_factory=frozenset)
    # IGMP snooping (NSDP tag 0x6800): None = unseeded.
    nsdp_igmp_snooping_enabled: bool | None = None
    nsdp_igmp_snooping_vlan: int | None = None
    # Broadcast storm filtering (NSDP tag 0x5400): None = unseeded.
    nsdp_broadcast_filtering: bool | None = None
    # Loop detection (NSDP tag 0x9000): None = unseeded.
    nsdp_loop_detection: bool | None = None
    # Fixed seed MAC for device identity: the NSDP identity TLV (Tag.MAC /
    # server_mac) AND the SNMP dot1dBaseBridgeAddress scalar (see oid_map())
    # both project this same value -- on real hardware they're the same
    # physical base MAC.
    nsdp_mac: bytes = b"\x28\xc6\x8e\x00\x00\x01"
    # MIB-II sysDescr (Task 2 model detection). Empty means unseeded: oid_map()
    # falls back to a generic-but-real-model-name text derived from the
    # registry's own display_name, so sysDescr-based detection works out of
    # the box for every SNMP-capable registered model, not just the ones with
    # a hand-authored seed_*() (see seed_gsm7252ps for the hand-seeded case).
    sys_descr: str = ""
    # UNVERIFIED sysObjectID test fixture -- see oid_map(). There is no known
    # real sysObjectID -> model table (no MIBs/captures/prior-art exist for
    # one); this value is NEVER a claim about real hardware, purely a
    # plausible-looking virtual/test placeholder under the model's own
    # 1.3.6.1.4.1.4526 vendor subtree, so sysObjectID round-trips end-to-end.
    # Empty means unseeded: oid_map() derives one from the model's vendor base.
    sys_object_id: str = ""
    # SSL server certificate last accepted by the virtual HTTP face's
    # cert-upload endpoint (see faces/http.py). None = nothing uploaded yet;
    # a successful multipart upload records the combined cert+key PEM here so a
    # test can assert the bytes actually arrived. Not part of any SNMP/NSDP
    # projection -- purely a record of what the web-UI upload received.
    uploaded_cert: str | None = None
    # Record of a FASTPATH copy-scp SSL-cert deploy the mock CLI face received
    # (see ScpCertDeploy above). None = no deploy driven yet.
    scp_cert_deploy: ScpCertDeploy | None = None
    # Number of reboots requested through a protocol face (the CLI's "reload").
    # A real reboot is unobservable through the same session -- the switch stops
    # answering -- so the mock records the REQUEST instead of pretending to
    # restart, letting a test prove the right command was issued. Not part of any
    # SNMP/NSDP/HTTP projection.
    reboots: int = 0
    # dot1dBaseBridgeAddress wire quirk: VERIFIED on the real M4300-24X (see
    # protocols/snmp/parse.py::_mac_from_ascii_text) -- that firmware answers
    # this scalar as a 17-character ASCII colon-hex STRING ("XX:XX:..:XX")
    # rather than the 6 raw OCTET STRING bytes every other captured model
    # (gsm7252ps, m4300-16x) uses. False (the default) emits the normal raw
    # 6-byte encoding; only a seed with hardware evidence of this quirk
    # should set it True.
    dot1d_base_mac_ascii: bool = False
    # Fixed Q-BRIDGE PortList byte-width the SNMP agent reports for
    # dot1qVlanStaticEgressPorts / dot1qVlanStaticUntaggedPorts. A real switch
    # emits a CONSTANT-width bitmap covering every port it knows -- physical
    # ports PLUS the LAG/CPU pseudo-ports far above the physical count -- so the
    # width does NOT track the highest member. Measured LIVE (read-only,
    # community "public"): GSM7252PS @10.1.5.22 = 79 bytes (highest set byte 60
    # => LAG ~port 481); M4300 @10.1.5.13 = 131 bytes (highest set byte 112 =>
    # ~port 897). None = unmeasured: oid_map() falls back to
    # vlan_bitmap_width(model), the physical-port-only width. Seeding the REAL
    # width is what lets the mock catch the historical writer bug (issue #3):
    # the buggy writer re-encoded the decoded member set at max(8, port_count/8)
    # rather than preserving the device width, so it sent a SET narrower than
    # this -- which a stricter Q-BRIDGE agent rejects outright.
    vlan_portlist_width: int | None = None
    # FASTPATH vendor switchport state, for a model whose registry entry says
    # snmp_vlan_write == "fastpath_switchport" (the M4300s). Per-port mode
    # (access=1/trunk=2/general=3), access VLAN, native (trunk untagged) VLAN,
    # and the writable allowed-VLAN bitmap. Empty dicts mean "unseeded":
    # _switchport_defaults() fills a port in on first use so the mock answers
    # these columns for every port, exactly like the real agent (which has a row
    # per interface). Defaults are the LIVE-measured factory shape of an untouched
    # M4300 port: access VLAN 1, native VLAN 1, all 4093 VLANs allowed.
    switchport_mode: dict[int, int] = field(default_factory=dict)
    switchport_access_vlan: dict[int, int] = field(default_factory=dict)
    switchport_native_vlan: dict[int, int] = field(default_factory=dict)
    switchport_allowed_vlans: dict[int, bytes] = field(default_factory=dict)
    # The GENERAL-mode per-VLAN participation lists (columns 7 and 8). These are
    # INDEPENDENT stored config, NOT a mirror of effective membership: measured
    # live on m4300-24x port 1/0/15, which is access-mode on VLAN 10 (so really
    # untagged in 10) while column 7 still read VLAN 1 -- the general-mode config
    # it would fall back to. They are only in force while mode == general(3), and
    # a SET of either answers notWritable on real hardware.
    switchport_general_untagged: dict[int, set[int]] = field(default_factory=dict)
    switchport_general_tagged: dict[int, set[int]] = field(default_factory=dict)
    # TRANSIENT (per-SET-PDU, not device state): VLAN ids whose egress PortList
    # was written by the PDU currently being applied. Only used by a model with
    # snmp_vlan_split_membership_writes, to reproduce the S3300's ordering quirk:
    # its egress write auto-untags the port, and that side effect beats an
    # untagged varbind carried in the SAME PDU. Reset by snapshot(), which
    # faces/snmp.py calls exactly once per PDU.
    pdu_egress_writes: set[int] = field(default_factory=set)

    # Geometry of the managed FASTPATH "VLAN Membership" web page, MEASURED live
    # (see VlanMembershipPageSim). None = this model has no such page (every
    # Plus-class model, whose membership CGI is a different shape entirely), and
    # the mock's HTTP face then 404s it rather than fabricating one.
    vlan_membership_page: VlanMembershipPageSim | None = None
    # Ports whose ``switchport mode`` makes the firmware REFUSE an explicit
    # VLAN-membership apply. On the M4300 image a port only accepts explicit
    # participation in ``general`` mode; in ``access`` or ``trunk`` mode the web
    # UI answers HTTP 200 but sets ``err_flag=1`` with
    # ``err_msg="Unable to set VLAN membership for VLAN ( <vid> )"``.
    # LIVE-PROVEN 2026-07-30: on the M4300-24X (10.1.5.13) EVERY port is access or
    # trunk (``show running-config``) and every membership apply was refused that
    # way, while on the M4300-16X (10.1.5.20:49152) ports 1-8 carry no
    # ``switchport mode`` line at all (the default) and the identical apply
    # succeeded for all three modes. Empty (the default) = every port accepts it,
    # which is what the gsm72xx images do.
    vlan_membership_locked_ports: frozenset[int] = frozenset()

    @property
    def _switchport_model(self) -> bool:
        """True when this model's VLAN membership is owned by switchport mode."""
        return get_model(self.model_key).snmp_vlan_write == "fastpath_switchport"

    @property
    def _access_mode_ports(self) -> list[int]:
        """Physical ports currently in switchport access mode."""
        from ..protocols.snmp.oids import SWITCHPORT_MODE_ACCESS

        for port in self.ports:
            self._switchport_defaults(port)
        return [
            p for p, m in self.switchport_mode.items() if m == SWITCHPORT_MODE_ACCESS
        ]

    def _reject_if_readonly_qbridge(self, column: str, vid: int) -> None:
        """Refuse a Q-BRIDGE egress PortList write exactly as FASTPATH 12.x does.

        The rule was pinned down live on 2026-07-30 with a deterministic A/B/A on
        m4300-16x @10.1.5.20 (fw 12.0.19.15): flipping ONE port (1/0/1) between
        general and access mode and issuing BYTE-IDENTICAL writes to an unrelated
        throwaway VLAN each time gave general->noError, access->commitFailed,
        general->noError, trunk->noError, access->commitFailed, general->noError.
        So ``dot1qVlanStaticEgressPorts`` is writable only while NO interface on
        the switch is in access mode -- switch-wide, not per-VLAN, not per-VLAN-row
        and not per-firmware. That one rule also explains the m4300-24x
        @10.1.5.13 (fw 12.0.13.8) rejecting the write in access, trunk AND general
        mode: 21 of its 24 ports are access-mode, so the column is never writable
        there.

        Because the library's own UNTAGGED write puts a port INTO access mode, the
        qbridge dialect is self-defeating on this firmware family -- which is why
        both M4300s use snmp_vlan_write="fastpath_switchport".
        """
        if not self._switchport_model:
            return
        access = self._access_mode_ports
        if access:
            raise CommitFailedError(
                f"{column}.{vid}: the Q-BRIDGE egress PortList is read-only while "
                f"any interface is in switchport access mode (ports {access} are) "
                f"-- a real FASTPATH 12.x agent answers commitFailed here, even "
                f"for a byte-identical value. Write the switchport mode / access "
                f"VLAN / native VLAN / allowed-VLAN columns instead."
            )

    def _switchport_defaults(self, port: int) -> None:
        """Seed a port's switchport row on first touch.

        Defaults are the live-measured factory shape of an untouched M4300 port:
        mode access(1), access VLAN 1, native VLAN 1, all 4093 VLANs allowed, and
        general-mode participation = untagged in VLAN 1 / tagged nowhere (column 7
        read VLAN 1 and column 8 read empty on EVERY port of both M4300 SKUs).
        """
        from ..protocols.snmp.oids import SWITCHPORT_MODE_ACCESS

        self.switchport_mode.setdefault(port, SWITCHPORT_MODE_ACCESS)
        self.switchport_access_vlan.setdefault(port, 1)
        self.switchport_native_vlan.setdefault(port, 1)
        if port not in self.switchport_allowed_vlans:
            # Real hardware ships every VLAN allowed (4093 of them on the M4300).
            self.switchport_allowed_vlans[port] = _all_vlans_bitmap()
        self.switchport_general_untagged.setdefault(port, {1})
        self.switchport_general_tagged.setdefault(port, set())

    def _apply_switchport(self, port: int) -> None:
        """Recompute VLAN membership from ``port``'s switchport config.

        Reproduces the derivation established live on 2026-07-30 against BOTH
        M4300 SKUs (m4300-24x @10.1.5.13 fw 12.0.13.8 port 1/0/8; m4300-16x
        @10.1.5.20 fw 12.0.19.15 port 1/0/1) by writing the vendor columns and
        re-reading the Q-BRIDGE mirrors after every single step:

        * access(1)  -> untagged member of the access VLAN (col3) and NOTHING
          else; it also drives the PVID.
        * trunk(2)   -> untagged member of the native VLAN (col4), PLUS a TAGGED
          member of (allowed(col6) INTERSECT existing VLANs) - {native}; the PVID
          becomes the native VLAN. The native VLAN is an untagged member EVEN WHEN
          it is not in the allowed list (proved by removing VLAN 1 from col6 while
          native stayed 1: the port stayed untagged in VLAN 1).
        * general(3) -> membership is the col7/col8 participation lists, which
          answer notWritable; the PVID is configured independently (live: a
          general-mode port read access VLAN 10 while its PVID was 1).

        The previous version modelled trunk as "tagged member of every allowed
        VLAN, untagged nowhere" and had no native VLAN at all -- which is exactly
        why the mock could not catch a writer that flipped a port to trunk with
        the factory all-4093 allowed list still in place and thereby handed it
        every VLAN on the switch.
        """
        from ..protocols.snmp import oids as _oids

        self._switchport_defaults(port)
        mode = self.switchport_mode[port]
        if mode == _oids.SWITCHPORT_MODE_ACCESS:
            untagged = {self.switchport_access_vlan[port]}
            tagged: set[int] = set()
            self.pvids[port] = self.switchport_access_vlan[port]
        elif mode == _oids.SWITCHPORT_MODE_TRUNK:
            native = self.switchport_native_vlan[port]
            untagged = {native}
            allowed = _vlans_in_bitmap(self.switchport_allowed_vlans[port])
            tagged = (allowed & set(self.vlans)) - {native}
            self.pvids[port] = native
        else:  # SWITCHPORT_MODE_GENERAL
            untagged = set(self.switchport_general_untagged[port])
            tagged = set(self.switchport_general_tagged[port]) - untagged
            # PVID is NOT derived in general mode -- see the docstring.
        for vid, vsim in self.vlans.items():
            if vid in untagged:
                vsim.member.add(port)
                vsim.untagged.add(port)
            elif vid in tagged:
                vsim.member.add(port)
                vsim.untagged.discard(port)
            else:
                vsim.member.discard(port)
                vsim.untagged.discard(port)

    def _reconcile_qbridge_membership(self, vid: int, incoming: set[int]) -> None:
        """Fold an ACCEPTED Q-BRIDGE egress write back into switchport config.

        Only reachable when no port is in access mode (see
        ``_reject_if_readonly_qbridge``). On the m4300-16x such a write is just
        another front end for the same configuration, VERIFIED live: adding 1/0/1
        to a VLAN while that port was TRUNK made the allowed-VLAN column (col6)
        gain the VLAN and the port became a TAGGED member, and removing it again
        cleared the col6 bit; doing the same while the port was GENERAL instead
        updated the col7 untagged list and the port became an UNTAGGED member.
        Keeping the vendor columns in step is what stops the mock drifting into a
        state no real switch can be in.
        """
        from ..protocols.snmp import oids as _oids

        for port in self.ports:
            self._switchport_defaults(port)
            mode = self.switchport_mode[port]
            if mode == _oids.SWITCHPORT_MODE_TRUNK:
                allowed = _vlans_in_bitmap(self.switchport_allowed_vlans[port])
                allowed = allowed | {vid} if port in incoming else allowed - {vid}
                self.switchport_allowed_vlans[port] = _vlan_bitmap_bytes(allowed)
            elif mode == _oids.SWITCHPORT_MODE_GENERAL:
                # The egress write auto-UNTAGS on this firmware (col7 gained the
                # VLAN) -- the same class of side effect the S3300 shows.
                if port in incoming:
                    self.switchport_general_untagged[port].add(vid)
                else:
                    self.switchport_general_untagged[port].discard(vid)
                    self.switchport_general_tagged[port].discard(vid)
            self._apply_switchport(port)

    @property
    def sysinfo_sensors(self) -> list[SensorSim]:
        """The sensor set the HTTP sysInfo page renders.

        Returns ``http_sensors`` when a model's web UI exposes a different
        sensor set than SNMP (e.g. the gsm7252ps), else falls back to
        ``sensors`` so a model whose two faces agree (the M4300) is unchanged.
        """
        return self.sensors if self.http_sensors is None else self.http_sensors

    def oid_map(self) -> dict[str, tuple[str, str]]:
        """Project this state onto the full numeric OID -> (type, value) view.

        Built directly from the exact OID layouts in ``protocols.snmp.oids``
        so a protocol face can serve it and the Task 5-9 parsers reconstruct
        the seeded state from what the face returns.
        """
        from ..protocols.snmp import oids
        from ..protocols.snmp.write import vlan_bitmap_width

        model = get_model(self.model_key)
        # A model with no vendor subtree (gs728tpp) serves everything via
        # standard MIBs -- vendor_oids() would raise, so it stays None and the
        # vendor-column projections below are skipped, matching a real agent
        # that answers noSuchObject for the whole 4526 tree.
        v = oids.vendor_oids(model) if oids.has_vendor_oids(model) else None
        # Prefer the device's REAL fixed PortList width (live-measured, seeded on
        # vlan_portlist_width) so the mock is an INDEPENDENT source of truth for
        # the wire width -- not a re-derivation of the same vlan_bitmap_width()
        # formula the writer uses (that shared assumption is exactly why the mock
        # never caught issue #3). Falls back to the physical-port-only width when
        # a model's real width hasn't been measured.
        vlan_width = self.vlan_portlist_width or vlan_bitmap_width(model)
        m: dict[str, tuple[str, str]] = {}

        # dot1dBaseBridgeAddress (BRIDGE-MIB scalar): the switch's own base
        # MAC. Reuses `nsdp_mac` -- on a real device the SNMP bridge base
        # address and the NSDP-reported identity MAC are the same physical
        # address, so one seed value serves both protocol faces. Most models
        # emit the standard raw 6-byte OCTET STRING; `dot1d_base_mac_ascii`
        # (verified on the real M4300-24X) instead emits the 17-character
        # ASCII colon-hex text form -- see `_mac_from_ascii_text`.
        if self.dot1d_base_mac_ascii:
            base_mac_wire = ":".join(f"{b:02X}" for b in self.nsdp_mac)
        else:
            base_mac_wire = self.nsdp_mac.decode("latin-1")
        m[f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0"] = ("OCTETSTR", base_mac_wire)

        # MIB-II System group (Task 2 model detection). sysDescr is a REAL,
        # honestly-matchable signal (a real switch's own sysDescr text
        # contains its model name); sysObjectID has no known OID->model
        # table, so the value projected here is an UNVERIFIED virtual/test
        # fixture only -- see the field docstrings above, never trust it as
        # ground truth for a real device.
        m[oids.SYS_DESCR] = (
            "OCTETSTR",
            self.sys_descr or f"Netgear {model.display_name}",
        )
        # sysObjectID: the seeded value, else a plausible placeholder under the
        # model's vendor subtree (or the generic mgmt.mib-2 root when the model
        # has no vendor subtree at all -- see the field docstring).
        default_object_id = f"{v.base}.1" if v is not None else "1.3.6.1.2.1"
        m[oids.SYS_OBJECT_ID] = ("OID", self.sys_object_id or default_object_id)
        # sysName: the same host name the CLI face reports through `show hosts`
        # and the web faces render, so the backends cannot disagree about it
        # here any more than they do on real hardware. Projected for EVERY model
        # with an SNMP backend, matching the devices: all five reachable
        # switches answered sysName on 2026-08-02, including gs728tpp, which
        # publishes no vendor subtree at all.
        m[oids.SYS_NAME] = ("OCTETSTR", self.hostname)

        # Remote logging, under <vendor base>.14 -- the same columns the real
        # agents publish, and ONLY for a model that has a vendor subtree. A
        # model with none (gs728tpp) must stay unable to answer get_syslog here
        # exactly as it is on the wire, rather than the mock inventing a reply.
        if v is not None:
            m[f"{v.base}.14.1.4.1.0"] = ("INTEGER", str(self.syslog.admin_mode))
            m[f"{v.base}.14.1.4.3.0"] = ("Gauge32", str(self.syslog.local_port))
            for index, col in enumerate(self.syslog.collectors, start=1):
                m[f"{v.base}.14.1.4.5.1.2.{index}"] = ("INTEGER", "1")
                m[f"{v.base}.14.1.4.5.1.3.{index}"] = ("OCTETSTR", col.host)
                m[f"{v.base}.14.1.4.5.1.4.{index}"] = ("Gauge32", str(col.port))
                m[f"{v.base}.14.1.4.5.1.5.{index}"] = ("INTEGER", str(col.severity))
                m[f"{v.base}.14.1.4.5.1.7.{index}"] = ("INTEGER", str(col.status))

        for port, sim in self.ports.items():
            m[f"{oids.IF_ADMIN_STATUS}.{port}"] = ("INTEGER", "1" if sim.admin else "2")
            m[f"{oids.IF_OPER_STATUS}.{port}"] = ("INTEGER", "1" if sim.link else "2")
            m[f"{oids.IF_HIGH_SPEED}.{port}"] = ("Gauge32", str(sim.speed))
            m[f"{oids.IF_TYPE}.{port}"] = ("INTEGER", str(sim.if_type))
            m[f"{oids.IF_NAME}.{port}"] = ("OCTETSTR", sim.name)
            if sim.description is not None:
                m[f"{oids.IF_ALIAS}.{port}"] = ("OCTETSTR", sim.description)
            # Port stats: only emit a counter the port actually exposes
            # (None -> skip, so parse_port_stats yields None there, never a
            # fabricated 0).
            stat_cols: tuple[tuple[str, str, int | None], ...] = (
                (oids.IF_HC_IN_OCTETS, "Counter64", sim.rx_octets),
                (oids.IF_HC_OUT_OCTETS, "Counter64", sim.tx_octets),
                (oids.IF_HC_IN_UCAST, "Counter64", sim.rx_ucast),
                (oids.IF_HC_OUT_UCAST, "Counter64", sim.tx_ucast),
                (oids.IF_IN_ERRORS, "Counter32", sim.rx_errors),
                (oids.IF_OUT_ERRORS, "Counter32", sim.tx_errors),
            )
            for base, typ, val in stat_cols:
                if val is not None:
                    m[f"{base}.{port}"] = (typ, str(val))

        # FASTPATH vendor switchport table, for a model whose VLAN membership is
        # owned by switchport mode. Emitted for every physical port so the table
        # has a row per interface exactly like the real agent, and so the writer's
        # read-modify-write of the allowed-VLAN column finds octets to modify.
        if self._switchport_model:
            for port in self.ports:
                self._switchport_defaults(port)
                m[f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"] = (
                    "INTEGER",
                    str(self.switchport_mode[port]),
                )
                m[f"{oids.FASTPATH_SWITCHPORT_ACCESS_VLAN}.{port}"] = (
                    "Gauge32",
                    str(self.switchport_access_vlan[port]),
                )
                m[f"{oids.FASTPATH_SWITCHPORT_NATIVE_VLAN}.{port}"] = (
                    "Gauge32",
                    str(self.switchport_native_vlan[port]),
                )
                m[f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}"] = (
                    "OCTETSTR",
                    self.switchport_allowed_vlans[port].decode("latin-1"),
                )
                # The two notWritable columns: the GENERAL-mode participation
                # lists. Emitted from their own stored config, NOT derived from
                # effective membership -- live proof they are independent is
                # m4300-24x port 1/0/15, an access port on VLAN 10 (so really
                # untagged in 10) whose column 7 still read VLAN 1.
                for base, vids in (
                    (
                        oids.FASTPATH_SWITCHPORT_TAGGED_VLANS,
                        self.switchport_general_tagged[port],
                    ),
                    (
                        oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS,
                        self.switchport_general_untagged[port],
                    ),
                ):
                    m[f"{base}.{port}"] = (
                        "OCTETSTR",
                        _vlan_bitmap_bytes(vids).decode("latin-1"),
                    )

        for vid, vsim in self.vlans.items():
            # dot1qVlanCurrentTable -- the OPERATIONAL view, indexed
            # <timeMark>.<vlanIndex>. Real agents publish it for EVERY VLAN,
            # including ones with no static row, which is the only place the
            # GS728TPP's VLAN 1 appears at all (see VlanSim.static_row). Time
            # mark 0 is what that switch reports on every row.
            m[f"{oids.DOT1Q_VLAN_CURRENT_EGRESS}.0.{vid}"] = (
                "OCTETSTR",
                encode_port_bitmap(vsim.member, width_bytes=vlan_width),
            )
            m[f"{oids.DOT1Q_VLAN_CURRENT_UNTAGGED}.0.{vid}"] = (
                "OCTETSTR",
                encode_port_bitmap(vsim.untagged, width_bytes=vlan_width),
            )
            # 1=other, 2=permanent: the live GS728TPP reports 1 for its
            # static-row-less VLAN 1 and 2 for all 12 configured VLANs.
            m[f"{oids.DOT1Q_VLAN_STATUS}.0.{vid}"] = (
                "INTEGER",
                "2" if vsim.static_row else "1",
            )
            if not vsim.static_row:
                # No dot1qVlanStaticTable row at all -- not an empty one. The
                # distinction is the whole point: an empty row would still make
                # the VLAN visible to a static-table-only reader.
                continue
            m[f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vid}"] = ("OCTETSTR", vsim.name)
            m[f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vid}"] = (
                "OCTETSTR",
                # dot1qVlanStaticEgressPorts is the STATIC (configured) table, so
                # it reports ``configured``, not the current member set -- proven
                # live on GSM7252PS @10.1.5.22, whose VLAN 1 static egress bitmap
                # includes 1/0/50 and 1/0/51 even though ``show vlan 1`` and
                # vlanStatus.html both omit them (see VlanSim.configured_only).
                encode_port_bitmap(vsim.configured, width_bytes=vlan_width),
            )
            m[f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vid}"] = (
                "OCTETSTR",
                encode_port_bitmap(vsim.untagged, width_bytes=vlan_width),
            )

        for port, pv in self.pvids.items():
            m[f"{oids.DOT1Q_PVID}.{port}"] = ("Gauge32", str(pv))

        for port, psim in self.poe.items():
            m[f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"] = (
                "INTEGER",
                "1" if psim.admin else "2",
            )
            m[f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}"] = ("INTEGER", str(psim.detect))
            # Per-port delivered-power (mW) is a Netgear VENDOR column; a model
            # with no vendor subtree (gs728tpp) exposes no such column at all.
            if v is not None:
                m[f"{v.poe_power_mw}.1.{port}"] = ("Gauge32", str(psim.power_mw))

        # Vendor box sensors (fan RPM / PSU watts / temperature) -- only for a
        # model with a vendor subtree. Empty ``sensors`` on a no-vendor model.
        if v is not None:
            for ssim in self.sensors:
                base = {
                    "fan": v.box_fan,
                    "power": v.box_psu_power,
                    "temperature": v.box_temp,
                }[ssim.kind]
                m[f"{base}.{ssim.instance}"] = ("OCTETSTR", ssim.raw)

        # ENTITY-MIB entPhysical inventory: the standard-MIB sensor components
        # for a no-vendor model (gs728tpp exposes fan/PSU ONLY here, with no
        # live value). entPhysicalClass is the int enum; Name/Descr are text.
        for ent in self.entity_components:
            m[f"{oids.ENT_PHYSICAL_CLASS}.{ent.index}"] = (
                "INTEGER",
                str(ent.phys_class),
            )
            m[f"{oids.ENT_PHYSICAL_NAME}.{ent.index}"] = ("OCTETSTR", ent.name)
            m[f"{oids.ENT_PHYSICAL_DESCR}.{ent.index}"] = ("OCTETSTR", ent.descr)

        # MAC/FDB: dot1qTpFdbPort values keyed by <vlan>.<6 MAC bytes>, plus
        # the dot1dBasePortIfIndex bridge-port -> ifIndex rows the parser
        # joins on.
        for msim in self.macs:
            mac_suffix = ".".join(str(b) for b in msim.mac_bytes)
            m[f"{oids.DOT1Q_TP_FDB_PORT}.{msim.vlan}.{mac_suffix}"] = (
                "INTEGER",
                str(msim.bridge_port),
            )
        for bridge_port, ifindex in self.bridge_ports.items():
            m[f"{oids.DOT1D_BASE_PORT_IF_INDEX}.{bridge_port}"] = (
                "INTEGER",
                str(ifindex),
            )

        # LLDP remote neighbours across lldpRemTable columns 5/7/8/9.
        for nb in self.lldp:
            idx = f"{nb.time_mark}.{nb.local_port}.{nb.rem_idx}"
            m[f"{oids.LLDP_REM_TABLE}.1.5.{idx}"] = ("OCTETSTR", nb.chassis)
            m[f"{oids.LLDP_REM_TABLE}.1.7.{idx}"] = ("OCTETSTR", nb.port_id)
            m[f"{oids.LLDP_REM_TABLE}.1.8.{idx}"] = ("OCTETSTR", nb.port_desc)
            m[f"{oids.LLDP_REM_TABLE}.1.9.{idx}"] = ("OCTETSTR", nb.sys_name)

        # mgmt-ip: ipAddrTable + ipRouteTable + DHCP mode.
        idx = self.mgmt.address
        m[f"{oids.IP_ADENT_ADDR}.{idx}"] = ("IPADDR", self.mgmt.address)
        m[f"{oids.IP_ADENT_NETMASK}.{idx}"] = ("IPADDR", self.mgmt.netmask)
        m[f"{oids.IP_ROUTE_DEST}.0.0.0.0"] = ("IPADDR", "0.0.0.0")
        m[f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0"] = ("IPADDR", self.mgmt.gateway)
        # Single named UNVERIFIED DHCP-mode OID (Task 4) — never a bare
        # ".99.1" literal. Absent on a no-vendor model (gs728tpp) -> reader
        # returns IpMode.UNKNOWN, matching that model's HTTP mgmt-IP read.
        if v is not None:
            m[f"{v.dhcp_mode_unverified}.0"] = (
                "INTEGER",
                "2" if self.mgmt.mode == "static" else "1",
            )

        return m

    def snapshot(self) -> VirtualSwitchState:
        """Deep-copy this state, for atomic multi-varbind SET rollback.

        A single SNMP SET PDU can carry several varbinds (e.g.
        ``set_vlan_membership`` writing both the egress and untagged
        bitmaps in one ``set_many`` call) and a real agent guarantees they
        apply all-or-nothing. ``faces/snmp.py``'s ``write_variables``
        snapshots the state before applying a PDU's varbinds and calls
        ``restore`` on this snapshot if any of them fails, so a partial
        mutation is never observable. See ``restore``.

        Also marks a PDU boundary: ``pdu_egress_writes`` (which tracks
        same-PDU egress writes for the S3300's auto-untag ordering quirk) is
        cleared here, because ``faces/snmp.py`` snapshots exactly once per PDU.
        """
        self.pdu_egress_writes = set()
        return copy.deepcopy(self)

    def restore(self, snapshot: VirtualSwitchState) -> None:
        """Restore this state in place from a prior ``snapshot()`` result.

        Copies every dataclass field from ``snapshot`` onto ``self`` rather
        than replacing ``self`` itself, so existing references to this exact
        object (e.g. ``VirtualSwitch.state``, ``StateMibView._state``) keep
        seeing the restored data.
        """
        for f in dataclasses.fields(self):
            setattr(self, f.name, getattr(snapshot, f.name))

    def apply_poe_admin(self, port: int, *, on: bool) -> None:
        """Switch a PSE port's admin state, with the coherence a real PoE switch
        shows: admin off -> detect=1 (unused) and the data link drops; admin on
        -> detect=3 (delivering).

        ONE rule shared by every protocol face -- the SNMP SET path
        (``apply_write``) and the CLI ``poe``/``no poe`` commands both come
        through here, so the mock cannot behave differently depending on which
        backend a test drove (which would make cross-backend write parity
        meaningless). Unknown port: deliberate no-op, exactly as before.
        """
        psim = self.poe.get(port)
        if psim is None:
            return
        was_on = psim.admin
        psim.admin = on
        psim.detect = 3 if on else 1  # delivering / unused
        if on and not was_on:
            # The CLI status column lags a re-enable by at least one read on real
            # hardware -- see PoeSim.cli_status_lag_reads.
            psim.cli_status_lag_reads = 1
        if not on and port in self.ports:
            self.ports[port].link = False

    def apply_poe_reset(self, port: int) -> None:
        """Re-arm PSE detection on a port (the CLI's ``poe reset``).

        Models what the hardware does: the port is powered down and detection
        starts again, so it ends up DELIVERING only if a powered device is
        actually drawing power (``power_mw``), else back to SEARCHING (2) -- a
        reset does NOT conjure a PD onto an empty port. This is what makes
        ``cycle_poe`` legitimately time out on an empty port, exactly as it
        would on real hardware, while ``clear_poe_fault`` (which only needs the
        port to LEAVE the fault state) succeeds.
        """
        psim = self.poe.get(port)
        if psim is None:
            return
        psim.admin = True
        psim.detect = 3 if psim.power_mw else 2

    def _refuse_vlan_creation_if_unsupported(self, oid: str) -> None:
        """Reproduce a device that will not create a dot1qVlanStaticTable row.

        MEASURED on the GS728TPP (10.2.5.10, firmware 6.0.1.30): every
        documented creation mechanism answers ``inconsistentValue``, while the
        SAME table's data columns accept writes and ``destroy(6)`` works. The
        mock has to make that exact distinction -- a blanket notWritable, or
        silently creating the row, would each let a create_vlan that cannot work
        on this hardware look fine in tests.
        """
        from ..registry import get_model

        if not get_model(self.model_key).snmp_can_create_vlan:
            raise InconsistentValueError(
                f"{self.model_key}: this agent refuses VLAN row creation "
                f"(inconsistentValue at {oid})"
            )

    def apply_write(self, oid: str, value: int | bytes | str) -> None:
        """Mutate this state from one SNMP SET varbind, with device coherence.

        Dispatches on the OID's column prefix. Applies the same coherence a real
        PoE switch shows so ``cycle_poe`` terminates against the mock: admin off
        -> detect=1 (unused) + data-port link down; admin on -> detect=3
        (delivering). Unhandled writable OIDs are a deliberate no-op (the write
        "succeeds" but reads back unchanged), which is exactly what a
        verify-after-write must catch. (The SNMP face layer additionally
        rejects a SET on an OID ``is_writable_oid`` doesn't recognize at all
        with a proper SNMP error, before it ever reaches here — see
        ``faces/snmp.py``.)
        """
        from ..protocols.snmp import oids
        from ..registry import get_model

        model = get_model(self.model_key)
        v = oids.vendor_oids(model) if oids.has_vendor_oids(model) else None

        def _tail(base: str) -> int | None:
            prefix = base + "."
            if oid.startswith(prefix) and oid[len(prefix) :].isdigit():
                return int(oid[len(prefix) :])
            return None

        def _as_bytes(val: int | bytes | str) -> bytes:
            if isinstance(val, bytes):
                return val
            if isinstance(val, str):
                return val.encode("latin-1")
            return bytes([val])

        # ifAdminStatus.<port>
        port = _tail(oids.IF_ADMIN_STATUS)
        if port is not None and port in self.ports:
            self.ports[port].admin = int(value) == 1
            if int(value) != 1:
                self.ports[port].link = False
            return

        # pethPsePortAdminEnable = <table>.3.1.<port>
        poe_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if oid.startswith(poe_prefix) and oid[len(poe_prefix) :].isdigit():
            self.apply_poe_admin(int(oid[len(poe_prefix) :]), on=int(value) == 1)
            return

        # dot1qPvid.<port>
        port = _tail(oids.DOT1Q_PVID)
        if port is not None:
            self.pvids[port] = int(value)
            return

        # dot1qVlanStaticEgressPorts.<vid> -- decode the incoming PortList and
        # REPLACE the member set, exactly as a real Q-BRIDGE agent does. A
        # too-narrow PortList (the historical writer bug) is faithfully
        # truncating here: every member beyond the incoming byte width is
        # silently dropped -- the exact silent VLAN corruption the GSM7252PS
        # exhibits on hardware for an 8-byte SET against its 79-byte PortList.
        # tests/virtual/test_snmp_write_face.py proves both the corruption (a
        # narrow SET drops the LAG/CPU members) and that the width-preserving
        # writer keeps them.
        vid = _tail(oids.DOT1Q_VLAN_STATIC_EGRESS)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap

            self._reject_if_readonly_qbridge("dot1qVlanStaticEgressPorts", vid)
            incoming = set(decode_port_bitmap(_as_bytes(value)))
            if self._switchport_model:
                # Accepted (no access-mode port), so this firmware treats the
                # column as an alternative front end for the switchport config.
                self._reconcile_qbridge_membership(vid, incoming)
                return
            if get_model(self.model_key).snmp_vlan_split_membership_writes:
                # S3300 Smart-firmware side effect (VERIFIED live): a port added
                # to the egress list becomes an UNTAGGED member. Recorded for this
                # PDU so a same-PDU untagged varbind loses to it, exactly as the
                # real switch behaves -- which is why the writer must split the
                # two columns into separate PDUs, egress first.
                added = incoming - self.vlans[vid].member
                self.vlans[vid].untagged |= added
                self.pdu_egress_writes.add(vid)
            self.vlans[vid].member = incoming
            return

        # dot1qVlanStaticUntaggedPorts.<vid>  (same truncation semantics)
        vid = _tail(oids.DOT1Q_VLAN_STATIC_UNTAGGED)
        if vid is not None and vid in self.vlans:
            from ..protocols.snmp.parse import decode_port_bitmap

            if self._switchport_model:
                # ACCEPTED AND SILENTLY IGNORED -- the nastiest of the three
                # behaviours, and PROVEN live on m4300-24x @10.1.5.13: a SET of
                # dot1qVlanStaticUntaggedPorts.4007 := {port 8} returned noError
                # while the column still read back [] afterwards (and the same
                # SET was accepted in access, trunk and general mode alike, in the
                # very same session where the EGRESS column commitFailed). A mock
                # that raised here would let the library "succeed" on a device
                # that never applied anything, so it must no-op instead and let
                # write verification be the thing that catches it.
                return
            if vid in self.pdu_egress_writes:
                # Same PDU already wrote this VLAN's egress list, whose auto-untag
                # side effect wins on this firmware: the write is ACKed but has no
                # effect (verified live -- one PDU left the port untagged, two PDUs
                # tagged it correctly).
                return
            self.vlans[vid].untagged = set(decode_port_bitmap(_as_bytes(value)))
            return

        # --- FASTPATH vendor switchport table (the writable VLAN-membership
        # control plane on a model whose Q-BRIDGE PortLists are read-only) ---
        port = _tail(oids.FASTPATH_SWITCHPORT_MODE)
        if port is not None and self._switchport_model:
            self.switchport_mode[port] = int(value)
            self._apply_switchport(port)
            return

        port = _tail(oids.FASTPATH_SWITCHPORT_ACCESS_VLAN)
        if port is not None and self._switchport_model:
            self.switchport_access_vlan[port] = int(value)
            self._apply_switchport(port)
            return

        port = _tail(oids.FASTPATH_SWITCHPORT_NATIVE_VLAN)
        if port is not None and self._switchport_model:
            # WRITABLE, live-verified on m4300-24x 1/0/8 (SET ...37.1.4.8 := 4007
            # read back 4007), but only to an EXISTING VLAN in 1..4093: := 0,
            # := 4094 and := a deleted VLAN id all answered commitFailed. That
            # last one is why the writer can never express "untagged nowhere".
            native = int(value)
            if native not in self.vlans:
                why = (
                    "is out of range" if not 1 <= native <= 4093 else "does not exist"
                )
                raise CommitFailedError(
                    f"switchport native VLAN for port {port} must be an existing "
                    f"VLAN in 1..4093; {native} {why} (a real FASTPATH agent "
                    f"answers commitFailed)"
                )
            self.switchport_native_vlan[port] = native
            self._apply_switchport(port)
            return

        port = _tail(oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS)
        if port is not None and self._switchport_model:
            self.switchport_allowed_vlans[port] = _as_bytes(value)
            self._apply_switchport(port)
            return

        # The per-port tagged/untagged VLAN bitmaps are the READ-ONLY mirrors of
        # the switchport config on real hardware: a SET answers notWritable.
        for base, name in (
            (oids.FASTPATH_SWITCHPORT_TAGGED_VLANS, "tagged"),
            (oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS, "untagged"),
        ):
            port = _tail(base)
            if port is not None and self._switchport_model:
                raise NotWritableError(
                    f"switchport per-port {name} VLAN bitmap for port {port} is "
                    "read-only (a real FASTPATH agent answers notWritable); set "
                    "the switchport mode / access VLAN instead"
                )

        # dot1qVlanStaticRowStatus.<vid>  (createAndGo=4 / destroy=6)
        vid = _tail(oids.DOT1Q_VLAN_STATIC_ROW_STATUS)
        if vid is not None:
            if int(value) == oids.ROW_STATUS_DESTROY:
                self.vlans.pop(vid, None)
            elif vid not in self.vlans:
                self._refuse_vlan_creation_if_unsupported(oid)
                if int(value) == oids.ROW_STATUS_CREATE_AND_GO:
                    self.vlans[vid] = VlanSim(name="")
            return

        # dot1qVlanStaticName.<vid>
        vid = _tail(oids.DOT1Q_VLAN_STATIC_NAME)
        if vid is not None:
            name = value.decode("latin-1") if isinstance(value, bytes) else str(value)
            if vid in self.vlans:
                self.vlans[vid].name = name
            else:
                # Setting the name of a row that does not exist IS a creation
                # attempt -- one of the five the GS728TPP refuses.
                self._refuse_vlan_creation_if_unsupported(oid)
                self.vlans[vid] = VlanSim(name=name)
            return

        # UNVERIFIED mgmt-IP + dhcp-mode write OIDs live under the vendor
        # subtree, so they only exist for a model that HAS one. A no-vendor
        # model (gs728tpp) never advertises or accepts them (its SNMP mgmt-IP
        # write is honestly UnsupportedCapabilityError in snmp_write).
        if v is not None:
            if oid == v.mgmt_write_addr_unverified:
                self.mgmt.address = str(value)
                return
            if oid == v.mgmt_write_netmask_unverified:
                self.mgmt.netmask = str(value)
                return
            if oid == v.mgmt_write_gateway_unverified:
                self.mgmt.gateway = str(value)
                return
            # 2=static, anything else=dhcp, matching oid_map()'s encoding.
            if oid == f"{v.dhcp_mode_unverified}.0":
                self.mgmt.mode = "static" if int(value) == 2 else "dhcp"
                return

        # Unhandled writable OID: deliberate no-op (verify-after-write catches it).

    def nsdp_tlvs(self, tags: set[Tag]) -> list[TLVEntry]:
        """Project this state onto NSDP read TLVs for the requested tags.

        MODEL / MAC / PORT_COUNT identity is always included (a real Plus switch
        echoes it, and ``parse_device`` needs the model + a port count to size
        VLAN bitmaps). Only tags this mock knows are emitted; unknown requested
        tags are silently skipped, exactly as real hardware does.
        """
        import socket

        from ..protocols.nsdp.protocol import Tag, TLVEntry

        model = get_model(self.model_key)
        port_count = model.port_count
        width = (port_count + 7) // 8
        model_bytes = (self.model_name or model.display_name).encode("ascii")
        # STRICT: answer with ONLY the tags requested. Real Plus hardware does
        # exactly this -- a read that omits MODEL gets a MODEL-less response,
        # which is why every per-op read must request it (see nsdp_read
        # ``_with_model``). Emitting identity tags unconditionally, as this used
        # to, made the mock over-serve and hid that bug from CI entirely.
        out: list[TLVEntry] = []
        if Tag.MODEL in tags:
            out.append(TLVEntry(Tag.MODEL, model_bytes))
        if Tag.MAC in tags:
            out.append(TLVEntry(Tag.MAC, self.nsdp_mac))
        if Tag.PORT_COUNT in tags:
            out.append(TLVEntry(Tag.PORT_COUNT, bytes([port_count])))
        if Tag.SERIAL_NUMBER in tags and self.serial:
            serial_bytes = b"\x01" + self.serial.encode("ascii")
            out.append(TLVEntry(Tag.SERIAL_NUMBER, serial_bytes))
        if Tag.HOSTNAME in tags and self.hostname:
            out.append(TLVEntry(Tag.HOSTNAME, self.hostname.encode("ascii")))
        if Tag.FIRMWARE_VER_1 in tags and self.firmware:
            out.append(TLVEntry(Tag.FIRMWARE_VER_1, self.firmware.encode("ascii")))
        if Tag.AUTH_V2_ENCPASS in tags:
            # 4-byte scheme advertisement (real GS110EMX returns 0x00000010).
            out.append(
                TLVEntry(Tag.AUTH_V2_ENCPASS, struct.pack(">I", self.nsdp_auth_version))
            )
        if Tag.AUTH_V2_SALT in tags:
            # A read of the salt ROTATES it (real hardware does this on every
            # 0x0017 read), and the mock remembers exactly what it handed out so
            # the next v2 write is validated against it. This is a deliberate
            # side effect of the read, matching the device's challenge-response.
            import os

            self.nsdp_last_salt = os.urandom(4)
            out.append(TLVEntry(Tag.AUTH_V2_SALT, self.nsdp_last_salt))
        if Tag.PORT_STATUS in tags:
            for port, sim in sorted(self.ports.items()):
                speed_byte = _mbps_to_speed_byte(sim.speed) if sim.link else 0x00
                out.append(
                    TLVEntry(
                        Tag.PORT_STATUS,
                        # Byte 2 is flow control, not a constant 0x01 -- measured
                        # on real GS110EMX units, see PortSim.flow_control.
                        bytes([port, speed_byte, 1 if sim.flow_control else 0]),
                    )
                )
        if Tag.PORT_NAME in tags:
            # One TLV per port, ALWAYS -- a real GS110EMX answers every port,
            # emitting a bare 1-byte TLV for a port with no description (e.g.
            # 10.1.5.25 answers ``01``..``05``, ``064e69636f6c65277320526f6f6d``
            # for the described port 6, then ``07``...). Skipping undescribed
            # ports would make the mock's row count disagree with hardware.
            for port, sim in sorted(self.ports.items()):
                name_bytes = (sim.description or "").encode("utf-8")
                out.append(TLVEntry(Tag.PORT_NAME, bytes([port]) + name_bytes))
        if Tag.PORT_STATISTICS in tags:
            # Real hardware returns a PORT_STATISTICS TLV for EVERY port, with
            # zeroed counters on idle ports (verified on a real GS105PE, whose
            # capture has all 5 rows). Previously ports with rx_octets=None were
            # skipped, so the NSDP face disagreed with the HTTP face -- which
            # renders every port -- for the SAME state, hiding any lost-row bug.
            for port, sim in sorted(self.ports.items()):
                out.append(
                    TLVEntry(
                        Tag.PORT_STATISTICS,
                        bytes([port])
                        + struct.pack(">Q", sim.rx_octets or 0)
                        + struct.pack(">Q", sim.tx_octets or 0)
                        + struct.pack(">Q", sim.rx_errors or 0)
                        + b"\x00" * 24,
                    )
                )
        if Tag.VLAN_MEMBERS in tags:
            from ..protocols.nsdp.parsers import ports_to_bitmap

            for vid, vsim in sorted(self.vlans.items()):
                tagged = vsim.member - vsim.untagged
                out.append(
                    TLVEntry(
                        Tag.VLAN_MEMBERS,
                        struct.pack(">H", vid)
                        + ports_to_bitmap(vsim.member, width)
                        + ports_to_bitmap(tagged, width),
                    )
                )
        if Tag.PORT_PVID in tags:
            for port, pv in sorted(self.pvids.items()):
                pvid_bytes = bytes([port]) + struct.pack(">H", pv)
                out.append(TLVEntry(Tag.PORT_PVID, pvid_bytes))
        if Tag.IP_ADDRESS in tags:
            out.append(TLVEntry(Tag.IP_ADDRESS, socket.inet_aton(self.mgmt.address)))
        if Tag.NETMASK in tags:
            out.append(TLVEntry(Tag.NETMASK, socket.inet_aton(self.mgmt.netmask)))
        if Tag.GATEWAY in tags:
            out.append(TLVEntry(Tag.GATEWAY, socket.inet_aton(self.mgmt.gateway)))
        if Tag.DHCP_MODE in tags:
            dhcp_byte = b"\x00" if self.mgmt.mode == "static" else b"\x01"
            out.append(TLVEntry(Tag.DHCP_MODE, dhcp_byte))
        if Tag.QOS_ENGINE in tags and self.nsdp_qos_engine is not None:
            out.append(TLVEntry(Tag.QOS_ENGINE, bytes([self.nsdp_qos_engine])))
        if Tag.PORT_MIRRORING in tags and self.nsdp_port_mirroring_dest is not None:
            from ..protocols.nsdp.parsers import ports_to_bitmap

            # The source-port bitmap width is MODEL-dependent on real hardware:
            # a 5-port GS105PE returns a 2-byte bitmap (3-byte TLV) while a
            # 10-port GS110EMX returns 3 bytes. Hard-coding 3 meant the mock
            # could never reproduce the narrow TLV that broke
            # parse_port_mirroring, so derive it from port_count exactly like
            # the VLAN bitmap above.
            out.append(
                TLVEntry(
                    Tag.PORT_MIRRORING,
                    bytes([self.nsdp_port_mirroring_dest])
                    + ports_to_bitmap(self.nsdp_port_mirroring_sources, width),
                )
            )
        if Tag.IGMP_SNOOPING in tags and self.nsdp_igmp_snooping_enabled is not None:
            vlan_byte = self.nsdp_igmp_snooping_vlan or 0
            out.append(
                TLVEntry(
                    Tag.IGMP_SNOOPING,
                    bytes(
                        [
                            0x00,
                            1 if self.nsdp_igmp_snooping_enabled else 0,
                            0x00,
                            vlan_byte,
                        ]
                    ),
                )
            )
        if (
            Tag.BROADCAST_FILTERING in tags
            and self.nsdp_broadcast_filtering is not None
        ):
            out.append(
                TLVEntry(
                    Tag.BROADCAST_FILTERING,
                    bytes([1 if self.nsdp_broadcast_filtering else 0]),
                )
            )
        if Tag.LOOP_DETECTION in tags and self.nsdp_loop_detection is not None:
            out.append(
                TLVEntry(
                    Tag.LOOP_DETECTION,
                    bytes([1 if self.nsdp_loop_detection else 0]),
                )
            )
        return out

    def apply_nsdp_write(self, tag: Tag | int, value: bytes) -> None:
        """Mutate this state from one NSDP write TLV (verify-after-write reads it
        back). Unknown/read-only tags are a deliberate no-op."""
        import socket

        from ..protocols.nsdp.parsers import parse_vlan_members
        from ..protocols.nsdp.protocol import Tag

        model = get_model(self.model_key)
        if tag == Tag.PORT_PVID:
            self.pvids[value[0]] = struct.unpack_from(">H", value, 1)[0]
        elif tag == Tag.VLAN_MEMBERS:
            m = parse_vlan_members(value, model.port_count)
            existing = self.vlans.get(m.vlan_id)
            name = existing.name if existing is not None else ""
            self.vlans[m.vlan_id] = VlanSim(
                name=name,
                member=set(m.member_ports),
                untagged=set(m.untagged_ports),
            )
        elif tag == Tag.VLAN_DESTROY:
            # Write-only action carrying the 2-byte VLAN id (ngadmin
            # ATTR_VLAN_DESTROY 0x2C00). Destroying a VLAN also drops every
            # port's PVID that pointed at it back to the default VLAN 1 -- that
            # is what a switch must do, since a PVID may not name a VLAN that no
            # longer exists.
            vid = struct.unpack_from(">H", value, 0)[0]
            if self.vlans.pop(vid, None) is not None:
                for port, pv in list(self.pvids.items()):
                    if pv == vid:
                        self.pvids[port] = 1
        elif tag == Tag.PORT_NAME:
            port = value[0]
            sim = self.ports.get(port)
            if sim is not None:
                text = value[1:].decode("utf-8", errors="replace").rstrip("\x00")
                sim.description = text or None
        elif tag == Tag.IP_ADDRESS:
            self.mgmt.address = socket.inet_ntoa(value)
        elif tag == Tag.NETMASK:
            self.mgmt.netmask = socket.inet_ntoa(value)
        elif tag == Tag.GATEWAY:
            self.mgmt.gateway = socket.inet_ntoa(value)
        elif tag == Tag.DHCP_MODE:
            self.mgmt.mode = "dhcp" if value[:1] == b"\x01" else "static"
        # REBOOT / FACTORY_RESET / unknown: deliberate no-op.

    def is_writable_oid(self, oid: str) -> bool:
        """True if ``oid`` is one this mock recognizes as SNMP-writable.

        Mirrors ``apply_write``'s dispatch prefixes on purpose (single set of
        column constants from ``protocols.snmp.oids``, kept in sync
        deliberately) so the SNMP face (``faces/snmp.py``) can reject a SET on
        a genuinely unknown/read-only OID with a proper SNMP error
        (notWritable) instead of the always-succeeding no-op ``apply_write``
        itself deliberately allows for a recognized-but-absent instance (e.g.
        creating a not-yet-existing VLAN row).
        """
        from ..protocols.snmp import oids
        from ..registry import get_model

        model = get_model(self.model_key)
        v = oids.vendor_oids(model) if oids.has_vendor_oids(model) else None

        def _is_col(base: str) -> bool:
            prefix = base + "."
            return oid.startswith(prefix) and oid[len(prefix) :].isdigit()

        if _is_col(oids.IF_ADMIN_STATUS):
            return True
        poe_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if oid.startswith(poe_prefix) and oid[len(poe_prefix) :].isdigit():
            return True
        if _is_col(oids.DOT1Q_PVID):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_EGRESS):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_ROW_STATUS):
            return True
        if _is_col(oids.DOT1Q_VLAN_STATIC_NAME):
            return True
        # FASTPATH vendor switchport columns. The tagged/untagged VLAN bitmaps
        # are deliberately NOT listed: they are read-only mirrors on real
        # hardware, so a SET must come back notWritable -- apply_write raises
        # NotWritableError for them, which the face maps to that error-status.
        if self._switchport_model and (
            _is_col(oids.FASTPATH_SWITCHPORT_MODE)
            or _is_col(oids.FASTPATH_SWITCHPORT_ACCESS_VLAN)
            or _is_col(oids.FASTPATH_SWITCHPORT_NATIVE_VLAN)
            or _is_col(oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS)
            or _is_col(oids.FASTPATH_SWITCHPORT_TAGGED_VLANS)
            or _is_col(oids.FASTPATH_SWITCHPORT_UNTAGGED_VLANS)
        ):
            return True
        # The vendor-subtree mgmt-IP/dhcp-mode write OIDs exist only for a
        # model with a vendor subtree; a no-vendor model has none of them.
        if v is None:
            return False
        if oid in (
            v.mgmt_write_addr_unverified,
            v.mgmt_write_netmask_unverified,
            v.mgmt_write_gateway_unverified,
        ):
            return True
        return oid == f"{v.dhcp_mode_unverified}.0"

    def is_oid_implemented(self, oid: str) -> bool:
        """True unless ``oid`` falls under a MIB subtree this model's real
        SNMP agent never registers at all (e.g. the RFC3621 PoE MIB on a
        non-PoE model) -- see ``protocols.snmp.oids.is_oid_implemented``.
        Used by ``StateMibView``/``faces/snmp.py`` to answer ``noSuchObject``
        for such a request instead of silently walking into an unrelated
        subtree.
        """
        from ..protocols.snmp import oids

        return oids.is_oid_implemented(get_model(self.model_key), oid)
