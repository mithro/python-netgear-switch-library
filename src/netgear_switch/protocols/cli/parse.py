"""Pure parsers for NETGEAR FASTPATH CLI ``show`` command output.

These are the CLI equivalent of ``protocols/http/parse.py``: I/O-free functions
turning the fixed-width, tabular text a FASTPATH switch prints over its console
into the library's public model dataclasses. Every function is grounded in the
REAL captured transcripts of a live gsm7252ps (SSH, host 10.1.5.22) that are
split, command-per-file, into ``tests/fixtures/cli/gsm7252ps_*.txt`` -- each
parser's docstring names the fixture and the exact column map it was derived
from. Nothing here is invented: expected values are transcribed from those
fixtures.

FASTPATH prints two shapes:

* **Labelled scalars** -- ``Label.......... value`` dotted-leader lines
  (``show version``, ``show network``, ``show interface ethernet <intf>``),
  handled by ``labelled_values``.
* **Fixed-width tables** -- a header, a ruler line of ``----`` groups, then
  rows whose columns are aligned to the ruler (``show port all``,
  ``show vlan port all``, ``show vlan <id>``, ``show mac-addr-table``,
  ``show lldp remote-device all``, ``show poe port info all`` and the tables in
  ``show environment``). The ruler is the single source of truth for column
  boundaries -- a naive ``str.split()`` would corrupt cells that legitimately
  contain spaces (``"Delivering Power"``, ``"CPU Interface:  0/5/1"``,
  ``"Not Supported"``), so ``table_columns``/``iter_table_rows`` slice strictly
  by the ruler's dash-group spans.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ...errors import CliCommandError
from ...models import (
    DetectedModel,
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    ServiceStatus,
    SwitchUser,
    SyslogConfig,
    SyslogServer,
    VLANInfo,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from ...registry import SwitchModel


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^\s*(.+?)\s*\.{2,}\s*(.*?)\s*$")
_RULER_RE = re.compile(r"^[ \t]*-{2,}[- \t]*$")
# A physical FASTPATH interface is "unit/slot/port"; only /0/ (the physical
# slot) maps to a library port number. "lag N", "vlan N" and
# "CPU Interface: ..." are deliberately NOT physical ports.
_PHYS_IFACE_RE = re.compile(r"^(\d+)/0/(\d+)$")
# The Smart-firmware S3300-52X (gsm7228ps) instead names physical ports "1/gN"
# (1-48) and 10G uplinks "1/xgN" (49-52) -- same FASTPATH CLI, different ifName
# text. The trailing integer IS the port number (verified against SNMP on
# 10.1.5.11). Mirrors ``protocols.http.parse._XE_SMART_IFACE_RE``. "1/0/N" is
# unaffected: it is matched first by ``_PHYS_IFACE_RE`` above.
_SMART_IFACE_RE = re.compile(r"^\d+/x?g(\d+)$")
_MAC_TEXT_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def labelled_values(text: str) -> dict[str, str]:
    """Parse ``Label.......... value`` dotted-leader lines into a dict.

    Later duplicate labels overwrite earlier ones (only the last wins); callers
    that need every occurrence of a repeated label (e.g. ``IPv6 Prefix is``)
    must not use this helper. Blank values (``Bootcode Version...........``)
    map to ``""``.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


def _ruler_spans(ruler: str) -> list[tuple[int, int | None]]:
    """Column ``(start, end)`` spans from a ``----`` ruler line.

    Each dash-run starts a column; a column extends up to the NEXT column's
    start (so inter-column padding belongs to the left cell and is stripped
    off), and the final column runs to end-of-line (``end=None``). This is what
    lets a value containing spaces stay in one cell.
    """
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(ruler)
    while i < n:
        if ruler[i] == "-":
            start = i
            while i < n and ruler[i] == "-":
                i += 1
            starts.append(start)
            ends.append(i)
        else:
            i += 1
    spans: list[tuple[int, int | None]] = []
    for idx, start in enumerate(starts):
        end: int | None = starts[idx + 1] if idx + 1 < len(starts) else None
        spans.append((start, end))
    return spans


def _slice_cell(row: str, start: int, end: int | None) -> str:
    """One ruler-column cell of ``row`` (``end=None`` -> to end-of-line), stripped."""
    return (row[start:end] if end is not None else row[start:]).strip()


def _slice_row(spans: list[tuple[int, int | None]], row: str) -> list[str]:
    """Slice ``row`` by ``spans`` (ruler columns) and strip each cell."""
    return [_slice_cell(row, start, end) for start, end in spans]


def iter_table_rows(text: str, *, after: str | None = None) -> Iterator[list[str]]:
    """Yield each data row (as sliced, stripped cells) of a fixed-width table.

    The table is the block of lines following the first ruler (``----``) line --
    optionally the first ruler that appears AFTER a line containing ``after``
    (used to pick one of ``show environment``'s three sub-tables). Iteration
    stops at the first blank line or the next ruler after the table body.
    """
    lines = text.splitlines()
    idx = 0
    if after is not None:
        while idx < len(lines) and after not in lines[idx]:
            idx += 1
    while idx < len(lines) and not _RULER_RE.match(lines[idx]):
        idx += 1
    if idx >= len(lines):
        return
    spans = _ruler_spans(lines[idx])
    for line in lines[idx + 1 :]:
        if not line.strip() or _RULER_RE.match(line):
            break
        yield _slice_row(spans, line)


def header_columns(text: str, *, after: str | None = None) -> list[str]:
    """Reconstruct each table column's HEADER NAME, in order.

    The header of a fixed-width FASTPATH table often wraps over two or three
    lines (``High Power`` / ``Max Power (mW)`` / ``Output Current (mA)`` stack
    their words above the ruler). Each of those header lines is sliced by the
    SAME ruler spans that slice the data rows, and the per-column pieces are
    joined (whitespace-collapsed) into one name. This lets a parser locate a
    column by NAME rather than a fixed index -- needed because the column set is
    not identical across firmware images (e.g. the M4300 ``show poe port info
    all`` omits the ``Temperature`` column the gsm7252ps prints). Returns ``[]``
    if no ruler is found.
    """
    lines = text.splitlines()
    idx = 0
    if after is not None:
        while idx < len(lines) and after not in lines[idx]:
            idx += 1
    while idx < len(lines) and not _RULER_RE.match(lines[idx]):
        idx += 1
    if idx >= len(lines):
        return []
    spans = _ruler_spans(lines[idx])
    # Header lines: the contiguous run of non-blank, non-ruler lines directly
    # above the ruler.
    start = idx - 1
    while start >= 0 and lines[start].strip() and not _RULER_RE.match(lines[start]):
        start -= 1
    header_lines = lines[start + 1 : idx]
    names: list[str] = []
    for span_start, span_end in spans:
        pieces = [_slice_cell(hl, span_start, span_end) for hl in header_lines]
        names.append(re.sub(r"\s+", " ", " ".join(p for p in pieces if p)))
    return names


def _int(text: str) -> int | None:
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return None


def _phys_port(iface: str) -> int | None:
    """Physical port number from a FASTPATH ifName, else ``None``.

    ``"1/0/7"`` -> ``7`` (Fully Managed line); ``"1/g7"`` -> ``7`` and
    ``"1/xg49"`` -> ``49`` (Smart-firmware S3300-52X). ``"lag 1"``/``"vlan 5"``/
    ``"CPU Interface: ..."`` -> ``None``.
    """
    s = iface.strip()
    m = _PHYS_IFACE_RE.match(s)
    if m:
        return int(m.group(2))
    m = _SMART_IFACE_RE.match(s)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# show version -> DetectedModel
# ---------------------------------------------------------------------------


def parse_version(text: str, models: Mapping[str, SwitchModel]) -> DetectedModel:
    """``show version`` -> ``DetectedModel``.

    Column/label map (``gsm7252ps_show_version.txt``)::

        System Description  -> the sysDescr-equivalent string matched against the
                               registry (contains the model name "GSM7252PS").
        Machine Model       -> fallback match token if the description is absent.

    ``sys_object_id`` is always ``None`` (the CLI exposes no sysObjectID).
    Model matching reuses the SNMP backend's exact whole-word matcher so CLI and
    SNMP identify a switch identically.
    """
    from ..snmp.parse import detect_model_from_sysdescr

    fields = labelled_values(text)
    descr = fields.get("System Description") or fields.get("Machine Model") or ""
    key = detect_model_from_sysdescr(descr, models) if descr else None
    return DetectedModel(key=key, sys_descr=descr or None, sys_object_id=None)


# ---------------------------------------------------------------------------
# show port all -> list[PortStatus]
# ---------------------------------------------------------------------------

# gsm7252ps_show_port_all.txt column map (by ruler group), header:
#   Intf | Type | Admin Mode | Physical Mode | Physical Status |
#   Link Status | Link Trap | LACP Mode | Flow Mode
_PORT_INTF, _PORT_TYPE, _PORT_ADMIN = 0, 1, 2
_PORT_PHYS_MODE, _PORT_PHYS_STATUS, _PORT_LINK = 3, 4, 5

_SPEED_RE = re.compile(r"(\d+)\s*([GgMm]?)")


def _speed_mbps(phys_status: str) -> int | None:
    """``"1000 Full"`` -> 1000, ``"10G Full"`` -> 10000, ``""`` -> None.

    ``Physical Status`` is blank on a down port (no negotiated rate), which
    honestly yields ``None`` -- never a fabricated 0.
    """
    m = _SPEED_RE.match(phys_status.strip())
    if not m:
        return None
    value = int(m.group(1))
    return value * 1000 if m.group(2).upper() == "G" else value


def parse_port_status(text: str) -> list[PortStatus]:
    """``show port all`` -> per physical-port ``PortStatus``.

    ``admin_enabled`` = Admin Mode == "Enable"; ``link_up`` = Link Status ==
    "Up"; ``speed_mbps`` from Physical Status (None when blank/down). ``lag N``
    aggregation rows are skipped (not physical ports). ``description`` is
    honestly ``None``: this command carries no ifAlias column.
    """
    out: list[PortStatus] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _PORT_LINK:
            continue
        port = _phys_port(cells[_PORT_INTF])
        if port is None:
            continue
        out.append(
            PortStatus(
                port=port,
                name=cells[_PORT_INTF],
                admin_enabled=cells[_PORT_ADMIN].strip().lower() == "enable",
                link_up=cells[_PORT_LINK].strip().lower() == "up",
                speed_mbps=(
                    _speed_mbps(cells[_PORT_PHYS_STATUS])
                    if cells[_PORT_LINK].strip().lower() == "up"
                    else None
                ),
                description=None,
            )
        )
    return out


# ---------------------------------------------------------------------------
# show vlan brief / show vlan <id> -> VLAN membership
# ---------------------------------------------------------------------------

# gsm7252ps_show_vlan_brief.txt: VLAN ID | VLAN Name | VLAN Type
_VLAN_BRIEF_ID, _VLAN_BRIEF_NAME = 0, 1


def parse_vlan_brief(text: str) -> list[tuple[int, str]]:
    """``show vlan brief`` -> ``[(vlan_id, name), ...]`` (no membership).

    Membership/tagging is NOT on this page; the reader follows up with
    ``show vlan <id>`` per VLAN (``parse_vlan_detail``).
    """
    out: list[tuple[int, str]] = []
    for cells in iter_table_rows(text):
        vid = _int(cells[_VLAN_BRIEF_ID]) if cells else None
        if vid is None:
            continue
        name = cells[_VLAN_BRIEF_NAME] if len(cells) > _VLAN_BRIEF_NAME else ""
        out.append((vid, name))
    return out


# gsm7252ps_show_vlan_90.txt table: Interface | Current | Configured | Tagging
_VLAN_D_IFACE, _VLAN_D_CURRENT, _VLAN_D_TAGGING = 0, 1, 3
_VLAN_HEADER_RE = re.compile(r"VLAN ID:\s*(\d+)")
_VLAN_NAME_RE = re.compile(r"VLAN Name:\s*(.*)")


def parse_vlan_detail(text: str, *, name: str | None = None) -> VLANInfo:
    """``show vlan <id>`` -> one ``VLANInfo`` (egress membership + tagging).

    The ``VLAN ID:``/``VLAN Name:`` scalar header names the VLAN; the per-
    interface table's columns are Interface | Current | Configured | Tagging.
    ``Current == "Include"`` means the port is an egress member; ``Tagging``
    then splits it into tagged vs untagged. ``lag N`` rows are dropped (the
    library models physical ports). ``name`` (from ``show vlan brief``) overrides
    the page's own name when supplied.
    """
    header = {}
    m = _VLAN_HEADER_RE.search(text)
    if m:
        header["id"] = m.group(1)
    nm = _VLAN_NAME_RE.search(text)
    page_name = nm.group(1).strip() if nm else None
    vid = int(header.get("id", "0"))
    tagged: set[int] = set()
    untagged: set[int] = set()
    for cells in iter_table_rows(text):
        if len(cells) <= _VLAN_D_TAGGING:
            continue
        port = _phys_port(cells[_VLAN_D_IFACE])
        if port is None:
            continue
        if cells[_VLAN_D_CURRENT].strip().lower() != "include":
            continue
        if cells[_VLAN_D_TAGGING].strip().lower() == "tagged":
            tagged.add(port)
        else:
            untagged.add(port)
    return VLANInfo(
        vlan_id=vid,
        name=name if name is not None else page_name,
        member_ports=frozenset(tagged | untagged),
        tagged_ports=frozenset(tagged),
        untagged_ports=frozenset(untagged),
    )


# ---------------------------------------------------------------------------
# show vlan port all -> PVIDs
# ---------------------------------------------------------------------------

# gsm7252ps_show_vlan_port_all.txt: Interface | Port VLAN ID Configured |
#   Current | Acceptable Frame Types | Ingress Filtering Configured |
#   Ingress Filtering Current | GVRP | Default Priority
_PVID_IFACE, _PVID_CONFIGURED = 0, 1


def parse_pvids(text: str) -> list[tuple[int, int]]:
    """``show vlan port all`` -> ``[(port, pvid), ...]`` for physical ports.

    Uses the ``Port VLAN ID Configured`` column (the persistent PVID), matching
    what dot1qPvid reports over SNMP; ``lag N`` rows are skipped.
    """
    out: list[tuple[int, int]] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _PVID_CONFIGURED:
            continue
        port = _phys_port(cells[_PVID_IFACE])
        pvid = _int(cells[_PVID_CONFIGURED])
        if port is None or pvid is None:
            continue
        out.append((port, pvid))
    return out


# ---------------------------------------------------------------------------
# show mac-addr-table -> FDB
# ---------------------------------------------------------------------------

# gsm7252ps_show_mac_addr_table.txt:
#   VLAN ID | MAC Address | Interface | IfIndex | Status
_MAC_VLAN, _MAC_ADDR, _MAC_IFINDEX = 0, 1, 3


def parse_mac_table(text: str) -> list[MacEntry]:
    """``show mac-addr-table`` -> ``[MacEntry, ...]``.

    ``MacEntry.port`` is the ``IfIndex`` column (49 for ``1/0/49``, 418 for
    ``lag 1``, 417 for the CPU/Management row) -- the same ifIndex the SNMP FDB
    join yields, so CLI and SNMP report the same port for a given MAC. The
    Interface column (which may contain internal spaces, e.g.
    ``"CPU Interface:  0/5/1"``) is only surfaced via the fixed-width slice and
    is not otherwise used. VLAN ID comes from the first column.
    """
    out: list[MacEntry] = []
    for cells in iter_table_rows(text):
        if len(cells) <= _MAC_IFINDEX:
            continue
        mac = cells[_MAC_ADDR].strip().upper()
        if not _MAC_TEXT_RE.match(mac):
            continue
        ifindex = _int(cells[_MAC_IFINDEX])
        vlan = _int(cells[_MAC_VLAN])
        if ifindex is None:
            continue
        out.append(MacEntry(mac=mac, port=ifindex, vlan_id=vlan))
    return out


# ---------------------------------------------------------------------------
# show lldp remote-device all -> neighbours
# ---------------------------------------------------------------------------

# gsm7252ps_show_lldp_remote_device_all.txt:
#   Local Interface | RemID | Chassis ID | Port ID | System Name
_LLDP_IFACE, _LLDP_CHASSIS, _LLDP_PORTID, _LLDP_SYSNAME = 0, 2, 3, 4


def parse_lldp(text: str) -> list[LLDPNeighbor]:
    """``show lldp remote-device all`` -> ``[LLDPNeighbor, ...]``.

    Columns: Local Interface | RemID | Chassis ID | Port ID | System Name. A
    local-interface row with no neighbour (only the interface printed, e.g.
    ``1/0/6``) is skipped. ``remote_port_desc`` is honestly ``None`` -- this
    command has no port-description column (SNMP's lldpRemPortDesc is the source
    for it). Chassis IDs are uppercased to match the SNMP/HTTP backends.
    """
    out: list[LLDPNeighbor] = []
    for cells in iter_table_rows(text):
        if not cells:
            continue
        if _phys_port(cells[_LLDP_IFACE]) is None:
            continue
        # A bare interface row (no neighbour) has empty trailing cells.
        if len(cells) <= _LLDP_SYSNAME or not cells[_LLDP_CHASSIS].strip():
            continue
        out.append(
            LLDPNeighbor(
                local_port=_phys_port(cells[_LLDP_IFACE]),  # type: ignore[arg-type]
                remote_sys_name=cells[_LLDP_SYSNAME].strip() or None,
                remote_port_desc=None,
                remote_chassis_id=cells[_LLDP_CHASSIS].strip().upper() or None,
                remote_port_id=cells[_LLDP_PORTID].strip() or None,
            )
        )
    return out


# ---------------------------------------------------------------------------
# show poe port info all -> PoE status
# ---------------------------------------------------------------------------

# The column set of `show poe port info all` is NOT fixed across FASTPATH images:
# the gsm7252ps prints a "Temperature" column that the M4300 firmware omits, so a
# fixed column index for Status lands one column off on the M4300 (it read the
# "Fault Status" cell -> every port UNKNOWN). Both headers below are REAL:
#   gsm7252ps: Intf|High Power|Max Power (mW)|Class|Power (mW)|Output Current (mA)|
#              Output Voltage (V)|Temperature|Status|Fault Status   (10 columns)
#   m4300:     Intf|High Power|Max Power (mW)|Class|Power (mW)|Output Current (mA)|
#              Output Voltage (V)|Status|Fault Status               (9 columns)
# So the columns are located by HEADER NAME (see ``header_columns``), not index --
# correct on both firmwares regardless of the Temperature column's presence.
_POE_INTF_HDR = "Intf"
_POE_OUTPUT_MW_HDR = "Power (mW)"  # the live draw, NOT "Max Power (mW)"
_POE_STATUS_HDR = "Status"  # the PSE state, NOT "Fault Status"

_POE_DETECT_TEXT: dict[str, PoEDetect] = {
    "delivering": PoEDetect.DELIVERING,
    "searching": PoEDetect.SEARCHING,
    "disabled": PoEDetect.DISABLED,
    "fault": PoEDetect.FAULT,
}


def parse_poe(text: str) -> list[PoEStatus]:
    """``show poe port info all`` -> per-port ``PoEStatus``.

    ``power_mw`` is the ``Power (mW)`` column -- the live output draw, matching
    the vendor mW OID the SNMP backend reads. ``detect`` maps the Status text
    ("Delivering Power" -> DELIVERING, "Searching" -> SEARCHING, "Disabled" ->
    DISABLED, anything containing "Fault" -> FAULT). This command has NO admin
    column, so ``admin_enabled`` is INFERRED: a port whose Status is anything
    other than "Disabled" is admin-enabled (a searching/delivering PSE port is
    administratively on). Documented inference, not a fabricated field.

    Columns are keyed by HEADER NAME, not a fixed index, because the M4300 image
    drops the ``Temperature`` column the gsm7252ps prints -- see ``header_columns``.
    """
    names = header_columns(text)
    try:
        intf_i = names.index(_POE_INTF_HDR)
        mw_i = names.index(_POE_OUTPUT_MW_HDR)
        status_i = names.index(_POE_STATUS_HDR)
    except ValueError:
        return []
    last = max(intf_i, mw_i, status_i)
    out: list[PoEStatus] = []
    for cells in iter_table_rows(text):
        if len(cells) <= last:
            continue
        port = _phys_port(cells[intf_i])
        if port is None:
            continue
        status = cells[status_i].strip().lower()
        detect = next(
            (v for k, v in _POE_DETECT_TEXT.items() if k in status),
            PoEDetect.UNKNOWN,
        )
        out.append(
            PoEStatus(
                port=port,
                admin_enabled=detect is not PoEDetect.DISABLED,
                detect=detect,
                power_mw=_int(cells[mw_i]),
            )
        )
    return out


# ---------------------------------------------------------------------------
# show environment -> sensors
# ---------------------------------------------------------------------------

# gsm7252ps_show_environment.txt, three sub-tables:
#   Temperature Sensors: Unit | Sensor | Description | Temp (C) | State | Max
#   Fans:                Unit | Fan | Description | Type | Speed | Duty | State
#   Power supplies:      Unit | Power supply | Description | Type | State
_ENV_TEMP_DESC, _ENV_TEMP_VALUE = 2, 3
_ENV_FAN_DESC, _ENV_FAN_SPEED = 2, 4
_ENV_PSU_DESC, _ENV_PSU_STATE = 2, 4


def parse_environment(text: str) -> list[Sensor]:
    """``show environment`` -> box sensors.

    Emits, in order:

    * one ``kind="temperature"`` (``unit="C"``) Sensor per Temperature Sensors
      row -- name from the Description column (CPU/System/MAC-A/MAC-B), value the
      ``Temp (C)`` column.
    * one ``kind="fan"`` Sensor per Fans row with a NUMERIC Speed (RPM as the
      value, ``unit="RPM"``); a fan reporting ``"Not Supported"`` is absent, not
      zero, and is skipped.
    * one ``kind="power"`` Sensor per Power-supplies row carrying its State as a
      health flag (``unit="state"``, value 1.0 when Operational else 0.0).
    """
    out: list[Sensor] = []
    for cells in iter_table_rows(text, after="Temperature Sensors:"):
        if len(cells) <= _ENV_TEMP_VALUE:
            continue
        value = _int(cells[_ENV_TEMP_VALUE])
        if value is None:
            continue
        out.append(
            Sensor(
                name=cells[_ENV_TEMP_DESC].strip(),
                kind="temperature",
                value=float(value),
                unit="C",
            )
        )
    for cells in iter_table_rows(text, after="Fans:"):
        if len(cells) <= _ENV_FAN_SPEED:
            continue
        rpm = _int(cells[_ENV_FAN_SPEED])
        if rpm is None:
            continue  # "Not Supported" -- absent, not zero
        out.append(
            Sensor(
                name=cells[_ENV_FAN_DESC].strip(),
                kind="fan",
                value=float(rpm),
                unit="RPM",
            )
        )
    # The PSU sub-table is headed "Power supplies:" on the gsm7252ps image but
    # "Power Modules:" on M4300 FASTPATH 12.0.13.8; the table columns are
    # identical, so pick whichever header this firmware prints.
    psu_after = "Power supplies:" if "Power supplies:" in text else "Power Modules:"
    for cells in iter_table_rows(text, after=psu_after):
        if len(cells) <= _ENV_PSU_STATE:
            continue
        state = cells[_ENV_PSU_STATE].strip().lower()
        out.append(
            Sensor(
                name=cells[_ENV_PSU_DESC].strip(),
                kind="power",
                value=1.0 if state == "operational" else 0.0,
                unit="state",
            )
        )
    return out


# ---------------------------------------------------------------------------
# show ip http / show telnetcon / show ip ssh -> management services
# ---------------------------------------------------------------------------


def _enabled(text: str) -> bool:
    """FASTPATH spells this two ways: "Enabled" and "Enable"."""
    return text.strip().lower() in {"enabled", "enable", "yes"}


def parse_services(
    http_text: str, telnet_text: str, ssh_text: str
) -> list[ServiceStatus]:
    """The four management services, from the three commands that report them.

    Captured 2026-08-02 from m4300-24x (10.1.5.13) and gsm7252ps (10.1.5.22).

    ``show ip http`` carries BOTH the plain and secure web servers::

        HTTP Mode (Unsecure)........................... Enabled
        HTTP Port...................................... 80
        HTTP Mode (Secure)............................. Enabled
        Secure Port.................................... 443

    ``show telnetcon`` -- NOT ``show telnet`` -- reports the INBOUND server::

        Telnet Server Admin Mode....................... Enable
        Telnet Server Port............................. 23

    ``show telnet`` describes the switch as a telnet *client* ("Allow New
    Outbound Telnet Sessions"), which says nothing about whether the server this
    library's TELNET backend connects to is running. Reading it as the server
    state would be wrong in the way that looks right.

    ``show ip ssh`` reports SSH, and its field set differs by firmware: the
    gsm7252ps prints no ``SSH Port`` line at all, so that port is honestly None
    rather than assumed to be 22.
    """
    http = labelled_values(http_text)
    telnet = labelled_values(telnet_text)
    # `show ip ssh` writes its labels WITH a trailing colon before the dotted
    # leader ("Administrative Mode: ......... Enabled"), unlike every other
    # FASTPATH scalar command. Measured on both m4300-24x and gsm7252ps. Without
    # stripping it the lookup misses and SSH reads as disabled on a switch whose
    # own output says Enabled -- which is exactly what the first live run did.
    ssh = {k.rstrip(":").strip(): v for k, v in labelled_values(ssh_text).items()}
    return [
        ServiceStatus(
            name="http",
            enabled=_enabled(http.get("HTTP Mode (Unsecure)", "")),
            port=_int(http.get("HTTP Port", "")),
        ),
        ServiceStatus(
            name="https",
            enabled=_enabled(http.get("HTTP Mode (Secure)", "")),
            port=_int(http.get("Secure Port", "")),
        ),
        ServiceStatus(
            name="telnet",
            enabled=_enabled(telnet.get("Telnet Server Admin Mode", "")),
            port=_int(telnet.get("Telnet Server Port", "")),
        ),
        ServiceStatus(
            name="ssh",
            enabled=_enabled(ssh.get("Administrative Mode", "")),
            port=_int(ssh.get("SSH Port", "")),
        ),
    ]


# ---------------------------------------------------------------------------
# show users -> local login accounts
# ---------------------------------------------------------------------------

#: Access-mode text meaning full privilege, in BOTH vocabularies FASTPATH uses.
#: Measured 2026-08-02: m4300-24x prints "Privilege-15"/"Privilege-1" while
#: gsm7252ps prints "Read/Write"/"Read Only" for the same admin/guest pair. A
#: parser that knew only one spelling would silently mis-report the other image.
_PRIVILEGED_ACCESS = frozenset({"privilege-15", "read/write"})
_UNPRIVILEGED_ACCESS = frozenset({"privilege-1", "read only", "no access"})


def _privileged(access_mode: str) -> bool | None:
    text = access_mode.strip().lower()
    if text in _PRIVILEGED_ACCESS:
        return True
    if text in _UNPRIVILEGED_ACCESS:
        return False
    return None


def parse_users(text: str) -> list[SwitchUser]:
    """``show users`` -> the switch's local login accounts.

    Captured 2026-08-02 from m4300-24x (10.1.5.13) and gsm7252ps (10.1.5.22);
    both list ``admin`` and ``guest``, under a header that wraps over three
    lines::

        User        SNMPv3         SNMPv3        SNMPv3
        User Name                 Access Mode   Access Mode  Authentication  Encryption
        ------------------------  ------------  -----------  --------------  ----------
        admin                     Privilege-15  Read Only    MD5             None

    Sliced by the ruler rather than split on whitespace, because an access mode
    legitimately contains a space (``Read Only``, ``Read/Write``) and a naive
    split would tear it in half.

    The ACCESS-MODE VOCABULARY differs by firmware -- see ``_PRIVILEGED_ACCESS``
    -- so the raw text is preserved on ``SwitchUser.access_mode`` and only the
    normalised ``privileged`` flag interprets it.
    """
    users: list[SwitchUser] = []
    for cells in iter_table_rows(text):
        if not cells or not cells[0].strip():
            continue
        padded = [*cells, "", "", "", ""]
        name, access, snmp_access, snmp_auth, snmp_enc = (c.strip() for c in padded[:5])
        users.append(
            SwitchUser(
                name=name,
                access_mode=access,
                privileged=_privileged(access),
                snmpv3_access=snmp_access or None,
                snmpv3_auth=snmp_auth or None,
                snmpv3_encryption=snmp_enc or None,
            )
        )
    return users


# ---------------------------------------------------------------------------
# show logging / show logging hosts -> syslog configuration
# ---------------------------------------------------------------------------

#: Syslog severity names as FASTPATH prints them, to the standard numbers the
#: SNMP columns carry. Cross-checked on m4300-24x: `show logging hosts` prints
#: "info" where the SNMP severity column reads 6.
_SEVERITY_NAMES = {
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


def _colon_fields(text: str) -> dict[str, str]:
    """Parse ``Label   : value`` lines, which `show logging` uses.

    Distinct from ``labelled_values`` above: that reads the dotted-leader form
    (``Label........ value``) which `show hosts` and `show network` use. The
    logging command uses a colon instead, so it needs its own reader.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip()
        if label:
            out[label] = value.strip()
    return out


def parse_syslog(logging_text: str, hosts_text: str) -> SyslogConfig:
    """``show logging`` + ``show logging hosts`` -> ``SyslogConfig``.

    Captured 2026-08-02 from m4300-24x (10.1.5.13), m4300-16x (10.1.5.20) and
    gsm7252ps (10.1.5.22)::

        Syslog Logging                      : enabled
        Logging Client Local Port           : 514

        Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#
        ----- ------------------------ ---------- ------ --------- ----- ----- -----
        1     10.1.5.1                 info       514    Active    udp

    **The host table's column set differs by firmware.** The M4300s emit eight
    columns (through ``Cert#``); the gsm7252ps emits only the first five. Both
    are parsed by taking the first five whitespace-separated fields and ignoring
    anything after ``Status``, so neither shape can shift a value into the wrong
    field -- the same class of trap as the VLAN PortList width.
    """
    fields = _colon_fields(logging_text)
    enabled = fields.get("Syslog Logging", "").strip().lower() == "enabled"
    port_text = fields.get("Logging Client Local Port", "").strip()
    local_port = int(port_text) if port_text.isdigit() else 0

    servers: list[SyslogServer] = []
    for line in hosts_text.splitlines():
        cells = line.split()
        # A data row starts with the integer index; the header and the dashed
        # rule under it do not, which is what filters them out.
        if len(cells) < 5 or not cells[0].isdigit():
            continue
        _index, host, severity, port, status = cells[:5]
        servers.append(
            SyslogServer(
                host=host,
                port=int(port) if port.isdigit() else 0,
                severity=_SEVERITY_NAMES.get(severity.lower(), 0),
                active=status.lower() == "active",
            )
        )
    return SyslogConfig(enabled=enabled, local_port=local_port, servers=tuple(servers))


# ---------------------------------------------------------------------------
# show hosts -> host name
# ---------------------------------------------------------------------------


def parse_hostname(text: str) -> str:
    """``show hosts`` -> the switch's host name.

    The command reports far more than the name -- DNS servers, the domain list,
    resolver retry counts, the static host-to-address table -- and only the
    first labelled field is wanted::

        Host name...................................... sw-netgear-m4300-24x
        Default domain................................. Domain name is not configured
        Name servers (Preference order)................ 8.8.8.8, 10.1.5.1

    Captured 2026-08-02 from m4300-24x (10.1.5.13), m4300-16x (10.1.5.20) and
    gsm7252ps (10.1.5.22); all three label it exactly "Host name".

    This is deliberately NOT ``show running-config | include hostname``. The two
    report different values: on m4300-16x running-config holds
    "manage-sw-netgear-m4300-16x-poe-s2" against this command's
    "sw-netgear-m4300-16x-poe-s2", and on gsm7252ps running-config has no
    hostname line at all while this command still answers. ``show hosts`` is the
    one that matches SNMP's sysName, so parsing it is what stops the CLI and
    SNMP backends disagreeing about the same switch.

    Raises rather than returning "" when the label is absent: every FASTPATH
    switch measured answers it, so silence means the command failed or the
    output drifted, and a blank host name would be a fabrication.
    """
    name = labelled_values(text).get("Host name")
    if name is None:
        raise CliCommandError(
            "`show hosts` output carries no 'Host name' field; got: "
            + " ".join(text.split())[:200]
        )
    return name.strip()


# ---------------------------------------------------------------------------
# show network -> management IP
# ---------------------------------------------------------------------------


def parse_mgmt_ip(text: str) -> MgmtIpConfig:
    """``show network`` -> ``MgmtIpConfig``.

    Label map (``gsm7252ps_show_network.txt`` / ``m4300_24x_show_ip_management``)::

        IP Address              -> address
        Subnet Mask             -> netmask
        Default Gateway         -> gateway
        Burned In MAC Address   -> base_mac (uppercased, as the other backends do)
        Configured IPv4 Protocol-> mode (DHCP -> DHCP, else STATIC)

    ``show network`` labels the mode "Configured IPv4 Protocol"; M4300 12.0's
    ``show ip management`` labels it "Method" instead -- accept either.
    """
    fields = labelled_values(text)
    proto = (
        (fields.get("Configured IPv4 Protocol") or fields.get("Method") or "")
        .strip()
        .upper()
    )
    mode = (
        IpMode.DHCP if proto == "DHCP" else (IpMode.STATIC if proto else IpMode.UNKNOWN)
    )
    mac = fields.get("Burned In MAC Address", "").strip().upper()
    return MgmtIpConfig(
        mode=mode,
        address=fields.get("IP Address") or None,
        netmask=fields.get("Subnet Mask") or None,
        gateway=fields.get("Default Gateway") or None,
        base_mac=mac if _MAC_TEXT_RE.match(mac) else None,
    )


# ---------------------------------------------------------------------------
# show interface ethernet <intf> -> one port's counters
# ---------------------------------------------------------------------------

# gsm7252ps_show_interface_ethernet_1_0_1.txt label map (chosen to match the
# SNMP get_stats fields: octets/HC-unicast/errors):
#   Total Packets Received (Octets)        -> rx_bytes  (ifHCInOctets)
#   Total Packets Transmitted (Octets)     -> tx_bytes  (ifHCOutOctets)
#   Unicast Packets Received               -> rx_packets(ifHCInUcastPkts)
#   Unicast Packets Transmitted            -> tx_packets(ifHCOutUcastPkts)
#   Total Packets Received with MAC Errors -> rx_errors (ifInErrors)
#   Total Transmit Errors                  -> tx_errors (ifOutErrors)


def parse_interface_counters(text: str, port: int) -> PortStats:
    """``show interface ethernet <intf>`` -> one port's ``PortStats``.

    The command output carries no interface number, so ``port`` is supplied by
    the caller. Field selection is aligned with the SNMP backend's get_stats
    (see the label map above) so CLI and SNMP report the same six counters.
    """
    fields = labelled_values(text)
    return PortStats(
        port=port,
        rx_bytes=_int(fields.get("Total Packets Received (Octets)", "")),
        tx_bytes=_int(fields.get("Total Packets Transmitted (Octets)", "")),
        rx_packets=_int(fields.get("Unicast Packets Received", "")),
        tx_packets=_int(fields.get("Unicast Packets Transmitted", "")),
        rx_errors=_int(fields.get("Total Packets Received with MAC Errors", "")),
        tx_errors=_int(fields.get("Total Transmit Errors", "")),
    )
