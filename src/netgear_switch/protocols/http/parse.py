"""Pure (I/O-free) parsers mapping web-UI HTML -> shared ``models`` types.

Regex-based (no ``lxml``/``bs4`` dependency). Grounding varies BY PARSER, so
check the specific function's docstring rather than trusting a blanket claim:

- The ``gs110emx_*``, ``gs105pe_*`` and ``m4300_*`` parsers are GROUNDED in
  REAL device captures (``tests/fixtures/http/{gs110emx,gs105pe,m4300}_*.html``)
  and are live-verified -- their column offsets/field names are confirmed.
- The ``gs305ep``/STANDARD-dialect parsers (``parse_port_status``,
  ``parse_port_stats``, ``parse_poe_status``, ``parse_pvids``,
  ``parse_vlan_ids``) match only SYNTHETIC fixtures headed
  ``UNVERIFIED-pending-capture``; their offsets are a same-family guess (the
  gs105pe live work found some gs305ep-derived CGI paths 404 on real hardware),
  so confirm against a real GS305EP before relying on them in production.

Two different failure shapes are deliberate:

- A *token* scrape (``parse_login_rand``/``parse_csrf_hash``/
  ``parse_selected_vlan``) returns ``None`` when the value is absent. The
  reader (Task 4) is the one with enough context to know whether that is
  fatal, and raises ``HttpAuthError``/``HttpUnexpectedPageError`` itself —
  this module never guesses.
- A *table/page* parser that cannot find the structure the page is
  documented to always contain (e.g. no ``portID`` rows on dashboard.cgi, no
  ``hiddenMem`` on 8021qMembe.cgi) raises ``HttpUnexpectedPageError`` naming
  what was expected. These pages are never legitimately empty on a real
  switch (port tables always list every physical port), so a missing
  structure means the wrong page came back, not "empty switch" -> never
  silently swallowed into an empty list/dict.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from html import unescape
from types import MappingProxyType
from typing import TYPE_CHECKING

from ...errors import HttpUnexpectedPageError
from ...models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortSpeed,
    PortStats,
    PortStatus,
    Sensor,
    ServiceStatus,
    SwitchUser,
    SyslogConfig,
    SyslogServer,
    VLANInfo,
    VlanMode,
    privileged_access,
    syslog_severity,
)
from .types import FastpathMembership, HttpSysInfo, XuiFormPage, XuiListPage, XuiRow

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_ROW_RE = re.compile(r'<tr\s+class="portID">(.*?)</tr>', re.DOTALL | re.IGNORECASE)
# GS110EMX interface_stats.html: real hardware NEVER closes a
# ``<tr class="portID">`` with ``</tr>`` (verified in
# gs110emx_interface_stats.html -- only the enclosing table's own closing
# tags exist, none between port rows), unlike the synthetic gs305ep
# portStatistics.cgi shape ``_ROW_RE``/``parse_port_stats`` handles. This row
# splitter cuts at the next ``<tr`` or ``</table>`` instead of requiring a
# matching close tag.
_OPEN_ROW_RE = re.compile(r'<tr class="portID">(.*?)(?=<tr|</table>)', re.DOTALL)
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")

_WIRE_TO_MODE = {"1": VlanMode.UNTAGGED, "2": VlanMode.TAGGED, "3": VlanMode.EXCLUDED}
_DETECT_TEXT = {
    "delivering": PoEDetect.DELIVERING,
    "searching": PoEDetect.SEARCHING,
    "disabled": PoEDetect.DISABLED,
    "fault": PoEDetect.FAULT,
}


def _cells(row_html: str) -> list[str]:
    return [_TAG_RE.sub("", c).strip() for c in _TD_RE.findall(row_html)]


def _int(text: str) -> int | None:
    m = re.search(r"-?\d+", text)
    return int(m.group()) if m else None


def _poe_power_to_mw(text: str) -> int | None:
    """Parse a FASTPATH PoE "Output Power" cell into integer milliwatts, to
    match the SNMP vendor mW OID.

    FIRMWARE VARIANCE (both grounded in real captures): the gsm7252ps renders
    the value in integer MILLIWATTS (``"3500"`` == 3500 mW); the M4300-16X
    renders WATTS with two decimals (``"4.60"`` == 4600 mW) despite a shared
    "(mW)" column header [sic]. The decimal point disambiguates -- an integer
    cell is already milliwatts, a decimal cell is watts (a raw 4.60 mW draw is
    physically absurd for a delivering PD). Empty/absent -> honest ``None``;
    ``"0"``/``"0.00"`` -> ``0``."""
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    if not m:
        return None
    value = m.group()
    return round(float(value) * 1000) if "." in value else int(value)


def parse_login_rand(html: str) -> str | None:
    """Scrape the login nonce from ``<input id="rand" ... value="...">``."""
    m = re.search(r'id=["\']rand["\'][^>]*value=["\']([^"\']*)["\']', html)
    return m.group(1) if m else None


def parse_csrf_hash(html: str) -> str | None:
    """Scrape the CSRF token from ``<input name="hash" value="...">``."""
    m = re.search(r'name=["\']hash["\'][^>]*value=["\']([^"\']*)["\']', html)
    return m.group(1) if m else None


def parse_gambit_token(html: str) -> str | None:
    """Scrape the GS110EMX post-login session token.

    GROUNDED in ``gs110emx_redirect.html`` (a real capture): the
    ``/redirect.html`` POST response is an auto-submit form carrying
    ``<input type="hidden" name="Gambit" value="...">`` -- that value is
    the session identity every subsequent request must carry (as a
    ``Gambit=<token>`` query param on GET, or a form field on POST; see
    ``transport/http/client.py``). Returns ``None`` if the page has no
    such field at all, and ``""`` if it has one with an empty value (a
    rejected login on the virtual face) -- both are falsy, so a caller
    doing ``if not token`` catches either shape.
    """
    m = re.search(r'name=["\']Gambit["\'][^>]*value=["\']([^"\']*)["\']', html)
    return m.group(1) if m else None


def parse_port_status(html: str) -> list[PortStatus]:
    """dashboard.cgi ``portID`` rows: [2]=port,[3]=link/speed,[4]=admin,[5]=name."""
    rows = _ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'dashboard.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStatus] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 5:
            raise HttpUnexpectedPageError(
                f"dashboard.cgi: expected >=5 <td> columns per portID row, got {len(c)}"
            )
        port = _int(c[1])
        if port is None:
            raise HttpUnexpectedPageError(
                f"dashboard.cgi: could not parse a port number from column {c[1]!r}"
            )
        link_text = c[2].lower()
        link_up = "up" in link_text
        speed = _int(c[2]) if link_up else None
        out.append(
            PortStatus(
                port=port,
                name=c[4] or None,
                admin_enabled=c[3].lower().startswith("enable"),
                link_up=link_up,
                speed_mbps=speed,
            )
        )
    return out


def parse_port_stats(html: str) -> list[PortStats]:
    """portStatistics.cgi ``portID`` rows: [1]=port,[2]=rx,[3]=tx,[4]=crc."""
    rows = _ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'portStatistics.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStats] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 4:
            raise HttpUnexpectedPageError(
                f"portStatistics.cgi: expected >=4 <td> columns per portID "
                f"row, got {len(c)}"
            )
        port = _int(c[0])
        if port is None:
            raise HttpUnexpectedPageError(
                f"portStatistics.cgi: could not parse a port number from "
                f"column {c[0]!r}"
            )
        out.append(
            PortStats(
                port=port,
                rx_bytes=_int(c[1]),
                tx_bytes=_int(c[2]),
                rx_packets=None,
                tx_packets=None,
                rx_errors=_int(c[3]),
                tx_errors=None,
            )
        )
    return out


def parse_interface_stats(html: str) -> list[PortStats]:
    """GS110EMX ``interface_stats.html`` ``portID`` rows (real hardware shape;
    see ``_OPEN_ROW_RE``): [0]=port,[1]=bytes received,[2]=bytes sent,
    [3]=CRC error packets.

    GROUNDED in ``gs110emx_interface_stats.html``. The page exposes no
    packet counts and only ONE combined error column (mapped to
    ``rx_errors``, matching the same column-4 -> rx_errors convention
    ``parse_port_stats`` uses for gs305ep); ``tx_errors``/``rx_packets``/
    ``tx_packets`` are honestly ``None`` -- this model's HTTP UI never
    reports them.
    """
    rows = _OPEN_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'interface_stats.html: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStats] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 4:
            raise HttpUnexpectedPageError(
                f"interface_stats.html: expected >=4 <td> columns per portID "
                f"row, got {len(c)}"
            )
        port = _int(c[0])
        if port is None:
            raise HttpUnexpectedPageError(
                f"interface_stats.html: could not parse a port number from "
                f"column {c[0]!r}"
            )
        out.append(
            PortStats(
                port=port,
                rx_bytes=_int(c[1]),
                tx_bytes=_int(c[2]),
                rx_packets=None,
                tx_packets=None,
                rx_errors=_int(c[3]),
                tx_errors=None,
            )
        )
    return out


def _speed_text_to_mbps(text: str) -> int | None:
    """Port-status speed text -> Mbps. ``"10G Full"`` -> 10000, ``"2.5G"`` ->
    2500, ``"1000M Full"`` -> 1000, ``"100M Full"`` -> 100, ``"No Speed"`` ->
    None.

    Matches the SNMP/NSDP backends' Mbps convention (LinkSpeed.speed_mbps) so a
    port's ``speed_mbps`` is identical whichever backend read it -- the whole
    point of the HTTP<->NSDP cross-verification. A ``G`` suffix multiplies by
    1000; a bare ``M`` is Mbps as-is; anything with no digit+unit is ``None``.

    The FRACTIONAL form matters: the GS110EMX's NBASE-T ports (9/10) negotiate
    ``2.5G``/``5G`` with multi-gig clients. Matching only ``(\\d+)`` here would
    backtrack past the ``2.`` in ``"2.5G"`` and match ``5G`` -> 5000, a
    wrong-but-plausible speed that would silently break the cross-verification.
    """
    m = re.search(r"(\d+(?:\.\d+)?)\s*([GM])", text, re.IGNORECASE)
    if not m:
        return None
    value = float(m.group(1))
    if m.group(2).upper() == "G":
        value *= 1000
    return int(value)


def parse_gs110emx_port_status(html: str) -> list[PortStatus]:
    """GS110EMX ``port_settings.html`` ``portID`` rows (OPEN-row shape, see
    ``_OPEN_ROW_RE``): [1]=port#, [2]=description, [3]=link ``Up``/``Down``,
    [5]=speed text.

    GROUNDED in ``gs110emx_port_settings.html`` (a real capture). ``name`` is
    the port description (``None`` when blank, as it is on a factory switch).
    ``admin_enabled`` comes from column [4], the port's speed/admin MODE cell
    (backed by the ``PHYSICAL_MODE`` hidden input): it reads ``Auto``/a forced
    speed when the port is administratively enabled and ``Disable`` when it is
    not. Hardcoding ``True`` here -- as this once did, on the false premise
    that the page carries no admin state -- would report an admin-disabled port
    as enabled. NSDP genuinely cannot see admin state and reports ``True``, so
    the two backends are compared only on port/link_up/speed_mbps.
    """
    rows = _OPEN_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'port_settings.html: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStatus] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 6:
            raise HttpUnexpectedPageError(
                f"port_settings.html: expected >=6 <td> columns per portID "
                f"row, got {len(c)}"
            )
        port = _int(c[1])
        if port is None:
            raise HttpUnexpectedPageError(
                f"port_settings.html: could not parse a port number from "
                f"column {c[1]!r}"
            )
        link_up = c[3].strip().lower() == "up"
        out.append(
            PortStatus(
                port=port,
                name=c[2] or None,
                admin_enabled=c[4].strip().lower() != "disable",
                link_up=link_up,
                speed_mbps=_speed_text_to_mbps(c[5]) if link_up else None,
            )
        )
    return out


def parse_gs110emx_pvids(html: str) -> list[tuple[int, int]]:
    """GS110EMX ``vlan_pvidsetting.html`` ``portID`` rows (OPEN-row shape):
    [1]=port#, [2]=PVID. GROUNDED in ``gs110emx_pvid.html`` (a real capture)."""
    rows = _OPEN_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'vlan_pvidsetting.html: expected <tr class="portID"> rows, found none'
        )
    out: list[tuple[int, int]] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 3:
            raise HttpUnexpectedPageError(
                f"vlan_pvidsetting.html: expected >=3 <td> columns per portID "
                f"row, got {len(c)}"
            )
        port = _int(c[1])
        pvid = _int(c[2])
        if port is None or pvid is None:
            raise HttpUnexpectedPageError(
                f"vlan_pvidsetting.html: could not parse port/PVID from row {c!r}"
            )
        out.append((port, pvid))
    return out


def parse_gs110emx_vlan_ids(html: str) -> list[int]:
    """GS110EMX ``Cf8021q.html`` (Advanced 802.1Q) VLAN list: each
    ``<tr class="vlanID tableTr">`` row's first ``<td class="def">`` is the VID.
    GROUNDED in ``gs110emx_cf8021q.html`` (a real capture)."""
    ids = re.findall(
        r'<tr class="vlanID tableTr">.*?<td class="def">\s*(\d+)\s*</td>',
        html,
        re.DOTALL,
    )
    if not ids:
        raise HttpUnexpectedPageError(
            'Cf8021q.html: expected <tr class="vlanID tableTr"> rows with a VID '
            "cell, found none"
        )
    return sorted({int(i) for i in ids})


# GS105PE port rows: real firmware writes `<tr class="portID">` on status.cgi /
# portPVID.cgi but `<tr class="portID" name="portID">` on portStatistics.cgi,
# and never closes the row -- so allow trailing attributes and cut at the next
# row / table close (all GROUNDED in tests/fixtures/http/gs105pe_*.html).
_GS105PE_ROW_RE = re.compile(
    r'<tr class="portID"[^>]*>(.*?)(?=<tr|</table>)', re.DOTALL
)
_HIDDEN_VALUE_RE = re.compile(r'<input type="hidden" value="(\d+)">')


def parse_gs105pe_port_status(html: str) -> list[PortStatus]:
    """GS105PE ``status.cgi`` portID rows: [1]=port, [2]=link ``Up``/``Down``,
    [4]=speed text (``No Speed``/``100M``/``1000M``).

    GROUNDED in ``gs105pe_status.html`` (a real capture from 10.1.5.30). Its own
    column layout -- link at [2], mode at [3], speed at [4] -- differs from BOTH
    gs305ep's dashboard.cgi and gs110emx's port_settings.html, hence its own
    parser. ``admin_enabled`` comes from the mode cell [3] (``Auto``/forced
    speed when enabled, ``Disable`` when not); hardcoding ``True`` would report
    an admin-disabled port as enabled. ``name`` is ``None`` -- this page has no
    description column."""
    rows = _GS105PE_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'status.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStatus] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 5:
            raise HttpUnexpectedPageError(
                f"status.cgi: expected >=5 <td> columns per portID row, got {len(c)}"
            )
        port = _int(c[1])
        if port is None:
            raise HttpUnexpectedPageError(
                f"status.cgi: could not parse a port number from column {c[1]!r}"
            )
        link_up = c[2].strip().lower() == "up"
        out.append(
            PortStatus(
                port=port,
                name=None,
                admin_enabled=c[3].strip().lower() != "disable",
                link_up=link_up,
                speed_mbps=_speed_text_to_mbps(c[4]) if link_up else None,
            )
        )
    return out


def parse_gs105pe_pvids(html: str) -> list[tuple[int, int]]:
    """GS105PE ``portPVID.cgi`` portID rows: [1]=port, [2]=PVID.
    GROUNDED in ``gs105pe_pvid.html``."""
    rows = _GS105PE_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'portPVID.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[tuple[int, int]] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 3:
            raise HttpUnexpectedPageError(
                f"portPVID.cgi: expected >=3 <td> columns per portID row, got {len(c)}"
            )
        port, pvid = _int(c[1]), _int(c[2])
        if port is None or pvid is None:
            raise HttpUnexpectedPageError(
                f"portPVID.cgi: could not parse port/PVID from row {c!r}"
            )
        out.append((port, pvid))
    return out


def parse_gs105pe_stats(html: str) -> list[PortStats]:
    """GS105PE ``portStatistics.cgi`` -> per-port byte/CRC counters.

    The VISIBLE ``<td>`` cells are unreliable (the first counter's cell is left
    empty and populated by page JS). The authoritative values are the HIDDEN
    inputs that follow each counter cell: three consecutive ``(hi, lo)`` pairs
    -- Bytes Received, Bytes Sent, CRC Error Packets -- each a 64-bit counter
    split into two 32-bit halves (``hi * 2**32 + lo``). Verified live on
    10.1.5.30 against the NSDP counters for the same ports.
    """
    rows = _GS105PE_ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'portStatistics.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[PortStats] = []
    for row in rows:
        c = _cells(row)
        port = _int(c[0]) if c else None
        if port is None:
            raise HttpUnexpectedPageError(
                f"portStatistics.cgi: could not parse a port number from row {c!r}"
            )
        halves = [int(v) for v in _HIDDEN_VALUE_RE.findall(row)]
        if len(halves) < 6:
            raise HttpUnexpectedPageError(
                f"portStatistics.cgi: port {port} expected 6 hidden counter "
                f"halves (rx/tx/crc hi+lo), got {len(halves)}"
            )
        rx, tx, crc = (
            halves[0] * 2**32 + halves[1],
            halves[2] * 2**32 + halves[3],
            halves[4] * 2**32 + halves[5],
        )
        out.append(
            PortStats(
                port=port,
                rx_bytes=rx,
                tx_bytes=tx,
                rx_packets=None,
                tx_packets=None,
                rx_errors=crc,
                tx_errors=None,
            )
        )
    return out


def parse_gs105pe_sysinfo(html: str) -> HttpSysInfo:
    """GS105PE ``switch_info.cgi`` -> device identity + mgmt-IP config.

    GROUNDED in ``gs105pe_switch_info.html``. Identity comes from
    ``<td>Label</td><td>value</td>`` rows; the mgmt IP/mask/gateway from the
    lowercase ``ip_address``/``subnet_mask``/``gateway_address`` inputs (NOT
    gs110emx's uppercase names); DHCP from the ``dhcpMode`` select, whose
    ``<option value="1" selected>`` means Enable/DHCP and ``0`` means
    Disable/STATIC (verified live: this unit is DHCP, matching its NSDP read).
    """
    fields = {
        "Product Name": _labeled_cell(html, "Product Name"),
        "Serial Number": _labeled_cell(html, "Serial Number"),
        "MAC Address": _labeled_cell(html, "MAC Address"),
        "Firmware Version": _labeled_cell(html, "Firmware Version"),
        "ip_address": _named_input_value(html, "ip_address"),
        "subnet_mask": _named_input_value(html, "subnet_mask"),
        "gateway_address": _named_input_value(html, "gateway_address"),
    }
    missing = [name for name, val in fields.items() if val is None]
    if missing:
        raise HttpUnexpectedPageError(
            f"switch_info.cgi: missing expected field(s): {', '.join(missing)}"
        )
    dhcp = re.search(
        r'<select[^>]*id="dhcpMode".*?<option value="1"[^>]*selected', html, re.DOTALL
    )
    return HttpSysInfo(
        product_name=fields["Product Name"] or "",
        switch_name=_named_input_value(html, "switch_name") or "",
        serial_number=fields["Serial Number"] or "",
        mac_address=fields["MAC Address"] or "",
        firmware_version=fields["Firmware Version"] or "",
        ip_mode=IpMode.DHCP if dhcp else IpMode.STATIC,
        ip_address=fields["ip_address"] or "",
        subnet_mask=fields["subnet_mask"] or "",
        gateway_address=fields["gateway_address"] or "",
    )


# --- M4300 "Cheetah /v1" pages -------------------------------------------
#
# Every data cell on a Cheetah page is a hidden input whose NAME encodes the
# ROW INSTANCE, immediately followed by an HTML comment naming the field
# semantically:
#
#   <TD ... id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
#        VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->
#
# So a row is "all cells sharing an instance", and fields are addressed BY NAME
# rather than by column index -- immune to column reordering between firmware
# versions. GROUNDED in real captures from an M4300-24X (10.1.5.13,
# 2026-07-21): portsConfiguration 24 instances x 17 fields, vlanStatus 14,
# basicAddressTable, portStatistics 24.
_CHEETAH_CELL_RE = re.compile(
    r'NAME=([0-9.]+)\.v_[0-9_]+ VALUE="([^"]*)"[^<]*(?:</TD>)?<!-- (\w+) -->',
    re.IGNORECASE,
)


def parse_cheetah_rows(html: str) -> list[dict[str, str]]:
    """Group a Cheetah page's cells into one dict per row instance.

    Returns rows in first-seen instance order, each mapping field NAME (from
    the trailing HTML comment) to its value. Empty list if the page carries no
    such cells -- the caller decides whether that is fatal."""
    rows: dict[str, dict[str, str]] = {}
    for instance, value, field in _CHEETAH_CELL_RE.findall(html):
        # Cheetah HTML-escapes cell values (interface names arrive as
        # "1&#x2F;0&#x2F;1"); unescape so port numbers parse.
        rows.setdefault(instance, {})[field] = unescape(value).strip()
    return list(rows.values())


def _cheetah_int(row: dict[str, str], field: str) -> int | None:
    return _int(row[field]) if field in row else None


def parse_m4300_port_status(html: str) -> list[PortStatus]:
    """M4300 ``portsConfiguration.html`` -> per-port status.

    ``baseport_ifIndex`` is the port number (matching the SNMP backend's
    ifIndex keying), ``baseinterfaceListing_Interfaces`` the name (``1/0/1``),
    ``baseport_AdminMode`` the admin state, ``baseport_LinkStatus2`` the link
    (``Link Up``/``Link Down``) and ``baseport_PhysicalStatus`` the speed text.
    """
    rows = [r for r in parse_cheetah_rows(html) if "baseport_LinkStatus2" in r]
    if not rows:
        raise HttpUnexpectedPageError(
            "portsConfiguration.html: no baseport_* cells found"
        )
    out: list[PortStatus] = []
    for r in rows:
        port = _cheetah_int(r, "baseport_ifIndex")
        if port is None:
            raise HttpUnexpectedPageError(
                "portsConfiguration.html: row without baseport_ifIndex"
            )
        link_up = "up" in r.get("baseport_LinkStatus2", "").lower()
        out.append(
            PortStatus(
                port=port,
                name=r.get("baseinterfaceListing_Interfaces") or None,
                admin_enabled=r.get("baseport_AdminMode", "").lower() == "enable",
                link_up=link_up,
                speed_mbps=(
                    _speed_text_to_mbps(r.get("baseport_PhysicalStatus", ""))
                    if link_up
                    else None
                ),
            )
        )
    return out


def parse_m4300_stats(html: str) -> list[PortStats]:
    """M4300 ``portStatistics.html`` -> per-port FRAME counters.

    This page reports FRAMES, not octets (``basePortStats_TotalFramesRx/Tx``),
    and the detailed page only breaks frames into size buckets -- neither
    exposes total bytes. So ``rx_bytes``/``tx_bytes`` are honestly ``None``
    here and the counts land in ``rx_packets``/``tx_packets``; a byte-level
    comparison against SNMP is therefore not possible for this model, but a
    PACKET-level one is.
    """
    rows = [r for r in parse_cheetah_rows(html) if "basePortStats_TotalFramesRx" in r]
    if not rows:
        raise HttpUnexpectedPageError(
            "portStatistics.html: no basePortStats_* cells found"
        )
    out: list[PortStats] = []
    for r in rows:
        port = _cheetah_int(r, "baseport_ifIndex")
        if port is None:
            # this page keys rows by interface name when ifIndex is absent
            name = r.get("baseinterfaceListing_Interfaces", "")
            port = _int(name.rsplit("/", 1)[-1]) if "/" in name else _int(name)
        if port is None:
            raise HttpUnexpectedPageError(
                "portStatistics.html: row without an identifiable port"
            )
        out.append(
            PortStats(
                port=port,
                rx_bytes=None,
                tx_bytes=None,
                rx_packets=_cheetah_int(r, "basePortStats_TotalFramesRx"),
                tx_packets=_cheetah_int(r, "basePortStats_TotalFramesTx"),
                rx_errors=_cheetah_int(r, "basePortStats_TotalErrorFramesRx"),
                tx_errors=_cheetah_int(r, "basePortStats_TotalErrorFramesTx"),
            )
        )
    return out


def parse_m4300_pvids(html: str) -> list[tuple[int, int]]:
    """M4300 ``portPvidConfiguration.html`` -> ``(port, pvid)`` pairs."""
    rows = [r for r in parse_cheetah_rows(html) if "SwitchingVlanPortConfig_Pvid" in r]
    if not rows:
        raise HttpUnexpectedPageError(
            "portPvidConfiguration.html: no SwitchingVlanPortConfig_Pvid cells"
        )
    out: list[tuple[int, int]] = []
    for r in rows:
        port = _cheetah_int(r, "baseport_ifIndex")
        if port is None:
            name = r.get("baseinterfaceListing_Interfaces", "")
            port = _int(name.rsplit("/", 1)[-1]) if "/" in name else _int(name)
        pvid = _cheetah_int(r, "SwitchingVlanPortConfig_Pvid")
        if port is None or pvid is None:
            continue
        out.append((port, pvid))
    if not out:
        raise HttpUnexpectedPageError(
            "portPvidConfiguration.html: no (port, pvid) pair could be parsed"
        )
    return out


# ``unit/slot/port`` interface name, shared by BOTH FASTPATH web dialects
# (M4300 Cheetah /v1 and the GSM7252PS XE pages) -- both render physical
# interfaces as "1/0/7" and non-physical ones as "lag 3"/"vlan 5".
_FASTPATH_IFACE_RE = re.compile(r"(\d+)/(\d+)/(\d+)")
# The M4300 temperature block mixes a live reading ("MAC 53 C") with the box's
# static datasheet THRESHOLD ("Max Operating Temperature 81 C"). Returning the
# threshold as a Sensor would make any "hottest sensor" alarm read 81 C
# forever, so limit rows are excluded -- the same refusal-to-invent rule that
# keeps the non-numeric fan rows out.
_IS_TEMP_LIMIT_RE = re.compile(r"\b(max|maximum|threshold|limit)\b", re.IGNORECASE)


def _expand_port_list(raw: str) -> frozenset[int]:
    """M4300 egress list -> the set of PHYSICAL port numbers.

    Real format (captured): ``"1/0/1 - 1/0/2, 1/0/5, 1/0/7 - 1/0/8,
    lag 1 - lag 128"``. Only ``unit/slot/port`` interfaces are physical ports
    and only the final component is the port number. ``lag N`` entries are
    link-aggregation groups, NOT physical ports, and are deliberately skipped
    -- expanding them (an earlier bug) turned ``lag 1 - lag 128`` into 128
    "ports" on a 24-port switch. A range is expanded only when both ends are
    physical interfaces in the same unit/slot.
    """
    ports: set[int] = set()
    for part in raw.split(","):
        ends = _FASTPATH_IFACE_RE.findall(part)
        if not ends:
            continue  # "lag N" and any other non-physical interface
        if "-" in part and len(ends) == 2:
            (u1, s1, p1), (u2, s2, p2) = ends
            if (u1, s1) == (u2, s2) and int(p1) <= int(p2):
                ports.update(range(int(p1), int(p2) + 1))
                continue
        ports.update(int(p) for _u, _s, p in ends)
    return frozenset(ports)


def parse_m4300_vlans(html: str) -> list[VLANInfo]:
    """M4300 ``vlanStatus.html`` -> VLANs with their egress member ports.

    ``SwitchingVlanCurrentConfig_VlanCurrentEgressPortList`` gives the member
    set. This page does NOT distinguish tagged from untagged, so both
    ``tagged_ports`` and ``untagged_ports`` are left EMPTY rather than guessed
    -- only ``member_ports`` is populated (see the reader's docs)."""
    rows = [
        r
        for r in parse_cheetah_rows(html)
        if "SwitchingVlanStaticConfig_VlanIndex" in r
    ]
    if not rows:
        raise HttpUnexpectedPageError(
            "vlanStatus.html: no SwitchingVlanStaticConfig_VlanIndex cells"
        )
    out: list[VLANInfo] = []
    for r in rows:
        vid = _cheetah_int(r, "SwitchingVlanStaticConfig_VlanIndex")
        if vid is None:
            continue
        members = _expand_port_list(
            r.get("SwitchingVlanCurrentConfig_VlanCurrentEgressPortList", "")
        )
        out.append(
            VLANInfo(
                vlan_id=vid,
                name=r.get("SwitchingVlanStaticConfig_VlanName") or None,
                member_ports=members,
                tagged_ports=frozenset(),
                untagged_ports=frozenset(),
            )
        )
    if not out:
        raise HttpUnexpectedPageError("vlanStatus.html: no VLAN row could be parsed")
    return out


def parse_m4300_macs(html: str) -> list[MacEntry]:
    """M4300 ``basicAddressTable.html`` -> the MAC/FDB table (one page).

    Two real-hardware traps this deliberately refuses to fall into:

    1. The ``Intf`` cell is NOT always a physical interface -- the real capture
       contains ``lag 1``, ``vlan 1`` and the ``0/15/1`` service port. Taking
       "the trailing number" (an earlier bug) reported ALL of them as physical
       port 1, including the switch's own base MAC. Only ``unit/slot/port``
       names yield a port; entries learned on a LAG/VLAN/service interface have
       no physical port and are SKIPPED rather than mis-attributed.
    2. This page is PAGINATED. It states the true table size in
       ``SwitchingFdbStats_ActiveAddrEntries`` (1213 on the captured switch)
       while rendering ~20 rows. Returning that first page as if it were the
       whole FDB is a silent, badly-wrong answer, so a short page RAISES and
       names SNMP -- which returns the complete table -- as the way to get it.
    """
    rows = [
        r for r in parse_cheetah_rows(html) if "SwitchingmacAddrGroup_MacAddress" in r
    ]
    if not rows:
        raise HttpUnexpectedPageError(
            "basicAddressTable.html: no SwitchingmacAddrGroup_MacAddress cells found"
        )
    out: list[MacEntry] = []
    for r in rows:
        mac = r.get("SwitchingmacAddrGroup_MacAddress", "").strip().upper()
        if not mac:
            continue
        iface = _FASTPATH_IFACE_RE.fullmatch(
            r.get("SwitchingmacAddrGroup_Intf", "").strip()
        )
        if iface is None:
            continue  # lag N / vlan N / service port: no physical port
        out.append(
            MacEntry(
                mac=mac,
                port=int(iface.group(3)),
                vlan_id=_cheetah_int(r, "SwitchingmacAddrGroup_vlanIndex"),
            )
        )
    total = re.search(r'NAME=v_1_1_1 VALUE="(\d+)"', html)
    if total is not None and int(total.group(1)) > len(rows):
        raise HttpUnexpectedPageError(
            f"basicAddressTable.html: the switch reports {total.group(1)} FDB "
            f"entries but this page renders only {len(rows)} -- the web UI "
            "paginates the MAC table. Use the SNMP backend for the complete "
            "FDB rather than a silently truncated page."
        )
    return out


def parse_m4300_sysinfo(html: str) -> MgmtIpConfig:
    """M4300 ``sysInfo.html`` -> management IP + base MAC.

    ``IPv4 Management Address`` is rendered as ``addr/netmask`` inside a link;
    ``System MAC Address`` is a plain labelled cell. The page reports no DHCP
    /static indicator, so ``mode`` is honestly ``UNKNOWN`` rather than guessed
    -- which matches what the SNMP backend reports for this model."""
    addr = netmask = None
    m = re.search(
        r"IPv4 Management Address</td>.*?>([0-9.]+)\s*/\s*([0-9.]+)<", html, re.DOTALL
    )
    if m:
        addr, netmask = m.group(1), m.group(2)
    mac_m = re.search(r"System MAC Address</td>\s*<td[^>]*>\s*([0-9A-Fa-f:]{17})", html)
    if addr is None and mac_m is None:
        raise HttpUnexpectedPageError(
            "sysInfo.html: neither IPv4 Management Address nor System MAC Address found"
        )
    return MgmtIpConfig(
        mode=IpMode.UNKNOWN,
        address=addr,
        netmask=netmask,
        gateway=None,
        base_mac=mac_m.group(1).upper() if mac_m else None,
    )


def parse_m4300_sensors(html: str) -> list[Sensor]:
    """M4300 ``sysInfo.html`` -> TEMPERATURE sensors.

    The page's Temperature block renders numeric readings as
    ``<td>MAC</td><td>53 &#8451;</td>``, which map straight onto ``Sensor``.
    Threshold rows in that same block (``Max Operating Temperature 81``) are a
    static datasheet LIMIT, not a reading, and are excluded -- see
    ``_IS_TEMP_LIMIT_RE``.
    Its FAN block is deliberately NOT returned: it reports a non-numeric state
    (``Fan-1 OK``) and ``Sensor.value`` is a required ``float`` -- emitting a
    fan would mean inventing a number. The SNMP backend, which reads real fan
    RPM, is the honest source for fan sensors on this model.
    """
    return [
        Sensor(name=label.strip(), kind="temperature", value=float(celsius), unit="C")
        for label, celsius in re.findall(
            r"<td[^>]*>([A-Za-z ]{2,28})</td>\s*<td[^>]*>\s*(\d+)\s*&#8451;", html
        )
        if not _IS_TEMP_LIMIT_RE.search(label)
    ]


# --- GSM7252PS "XE_FASTPATH" pages ---------------------------------------
#
# The GSM7252PS web UI is "auto-generated by XE" and encodes each data cell as
# a hidden input whose NAME carries a ROW INSTANCE and a COLUMN COORDINATE:
#
#   <TD class="def alt0" p="1.0.520" id=1_2_10><INPUT xid=1_2_10 TYPE=hidden
#        NAME=1.0.52.v_1_2_10 VALUE="Link Up">Link Up</TD>
#
# Two differences from the M4300 Cheetah dialect matter:
#
# 1. There is NO trailing ``<!-- field_name -->`` comment, so fields cannot be
#    addressed by name -- only by the COLUMN COORDINATE (``1_2_10``). Every
#    column map below is transcribed from a real capture of 10.1.5.22 AND from
#    that page's own visible header row, which carries the human label under
#    the same coordinate (``<TD class="def_TH alt0" id=1_2_10>Link Status</TD>``
#    -- quoted beside each map).
# 2. The instance prefix is ``1.<row-index>.<row-count>``, NOT ``unit.slot.port``
#    as an early draft of the design assumed: on the 52-port capture the FIRST
#    row is ``NAME=1.0.52.v_1_2_1 VALUE="1/0/1"`` and the last is
#    ``1.51.52 -> "1/0/52"``, i.e. the trailing 52 is the ROW COUNT, identical
#    on every row. Port identity is therefore always taken from the row's own
#    cells (the ifindex column, or the ``1/0/N`` interface name), never from
#    the prefix -- reading the prefix as a port would have labelled all 52
#    ports "52".
_XE_CELL_RE = re.compile(
    r'NAME=(\d+(?:\.\d+)+)\.v_(\d+_\d+_\d+) VALUE="([^"]*)"',
    re.IGNORECASE,
)


def parse_xe_rows(html: str) -> list[dict[str, str]]:
    """Group an XE page's cells into one dict per row instance.

    Returns rows in first-seen (page) order, each mapping the column
    COORDINATE (``"1_2_10"``) to that cell's value. Cells with no instance
    prefix -- the blank ``NAME=v_g_1_2_1`` "global"/template row and page-level
    scalars like ``NAME=v_1_1_1`` (Total MAC Addresses) -- are deliberately
    NOT rows and are skipped. An empty list means the page carries no such
    cells; the caller decides whether that is fatal.
    """
    rows: dict[str, dict[str, str]] = {}
    for instance, coord, value in _XE_CELL_RE.findall(html):
        rows.setdefault(instance, {})[coord] = unescape(value).strip()
    return list(rows.values())


# The S3300-52X (Smart Managed Pro firmware) names physical ports "1/gN"
# (1-48) and 10G uplinks "1/xgN" (49-52) instead of the M4300/GSM7252PS
# fully-managed "1/0/N" -- same Cheetah XE grid, different ifName text. The
# trailing integer IS the port number (verified against SNMP on 10.1.5.11).
_XE_SMART_IFACE_RE = re.compile(r"1/x?g(\d+)")


def _xe_port_from_iface(text: str) -> int | None:
    """``"1/0/7"`` -> 7 (M4300/GSM7252PS), ``"1/g7"``/``"1/xg49"`` -> 7/49
    (S3300-52X Smart firmware). Only a full physical-port name yields a port;
    ``lag 3``/``vlan 5``/``0/15/1``-style service interfaces are handled by the
    callers that need them (see ``parse_xe_macs``)."""
    t = text.strip()
    m = _FASTPATH_IFACE_RE.fullmatch(t)
    if m:
        return int(m.group(3))
    m = _XE_SMART_IFACE_RE.fullmatch(t)
    return int(m.group(1)) if m else None


# portsConfiguration.html column map, from the capture's own header row:
#   1_2_1 Port ("1/0/1")   1_2_4 Port Type      1_2_5 STP mode
#   1_2_6 Admin Mode       1_2_7 LACP Mode      1_2_8 Physical Mode
#   1_2_9 Physical Status  1_2_10 Link Status   1_2_11 Link Trap
#   1_2_12 Maximum Frame Size                   1_2_13 ifindex
_XE_PORT_IFACE = "1_2_1"
_XE_PORT_ADMIN = "1_2_6"
_XE_PORT_PHYS_STATUS = "1_2_9"
_XE_PORT_LINK = "1_2_10"
_XE_PORT_IFINDEX = "1_2_13"


def parse_xe_port_status(html: str) -> list[PortStatus]:
    """GSM7252PS ``portsConfiguration.html`` -> per-port status.

    ``ifindex`` (column 13) is the port number, matching the SNMP backend's
    ifIndex keying. Speed comes from *Physical Status* (column 9, the
    NEGOTIATED result: ``"1000 Mbps"`` / ``"10G Full "`` / ``"Unknown"``), NOT
    from *Physical Mode* (column 8), which is the CONFIGURED mode and reads
    ``"Auto"`` on an auto-negotiating port. A down port's Physical Status is
    ``"Unknown"`` -> ``speed_mbps=None``.
    """
    rows = [r for r in parse_xe_rows(html) if _XE_PORT_LINK in r]
    if not rows:
        raise HttpUnexpectedPageError(
            "portsConfiguration.html: no XE port rows "
            f"(no v_{_XE_PORT_LINK} link-status cells) found"
        )
    out: list[PortStatus] = []
    for r in rows:
        name = r.get(_XE_PORT_IFACE, "")
        port = _int(r[_XE_PORT_IFINDEX]) if _XE_PORT_IFINDEX in r else None
        if port is None:
            port = _xe_port_from_iface(name)
        if port is None:
            raise HttpUnexpectedPageError(
                f"portsConfiguration.html: row without an identifiable port: {r!r}"
            )
        link_up = "up" in r[_XE_PORT_LINK].lower()
        out.append(
            PortStatus(
                port=port,
                name=name or None,
                admin_enabled=r.get(_XE_PORT_ADMIN, "").lower() == "enable",
                link_up=link_up,
                speed_mbps=(
                    _speed_text_to_mbps(r.get(_XE_PORT_PHYS_STATUS, ""))
                    if link_up
                    else None
                ),
            )
        )
    return out


# portStatistics.html column map, from the capture's own header row:
#   1_1_103 Interface ("1/0/1")
#   1_1_2 Total Packets received without Errors
#   1_1_3 Packets received with Errors
#   1_1_4 Broadcast Packets received (unused)
#   1_1_5 Packets transmitted without Errors
#   1_1_6 Transmit Packet Errors
#   1_1_7 Collision Frames (unused)
#   1_1_9 Time since counters last cleared (unused)
_XE_STATS_IFACE = "1_1_103"
_XE_STATS_RX_PKTS = "1_1_2"
_XE_STATS_RX_ERRS = "1_1_3"
_XE_STATS_TX_PKTS = "1_1_5"
_XE_STATS_TX_ERRS = "1_1_6"


def parse_xe_stats(html: str) -> list[PortStats]:
    """GSM7252PS ``portStatistics.html`` -> per-port PACKET counters.

    This page carries no octet column at all (its header row lists only
    packet/frame counts), so ``rx_bytes``/``tx_bytes`` are honestly ``None``
    and a BYTE-level comparison against SNMP is impossible for this model --
    a PACKET-level one is not. Same honest shape as ``parse_m4300_stats``.

    The ``1_1_103`` interface column is required, not just used: the LLDP page
    uses the same ``1_1_*`` coordinate space, so requiring the column only this
    page has keeps a wrong page from parsing into plausible garbage.
    """
    rows = [
        r
        for r in parse_xe_rows(html)
        if _XE_STATS_IFACE in r and _XE_STATS_RX_PKTS in r
    ]
    if not rows:
        raise HttpUnexpectedPageError(
            "portStatistics.html: no XE counter rows "
            f"(no v_{_XE_STATS_IFACE} interface cells) found"
        )
    out: list[PortStats] = []
    for r in rows:
        port = _xe_port_from_iface(r[_XE_STATS_IFACE])
        if port is None:
            continue  # a non-physical interface (lag/vlan) has no port number
        out.append(
            PortStats(
                port=port,
                rx_bytes=None,
                tx_bytes=None,
                rx_packets=_int(r.get(_XE_STATS_RX_PKTS, "")),
                tx_packets=_int(r.get(_XE_STATS_TX_PKTS, "")),
                rx_errors=_int(r.get(_XE_STATS_RX_ERRS, "")),
                tx_errors=_int(r.get(_XE_STATS_TX_ERRS, "")),
            )
        )
    if not out:
        raise HttpUnexpectedPageError(
            "portStatistics.html: no physical-port counter row could be parsed"
        )
    return out


# portPvidConfiguration.html column map, from the capture's own header row:
#   1_2_1 Interface        1_2_4 Configured PVID   1_2_9 Current PVID
#   1_2_5 Acceptable Frame Types                   1_2_6 Configured Ingress
#   1_2_10 Current Ingress Filtering               1_2_8 Port Priority
_XE_PVID_IFACE = "1_2_1"
_XE_PVID_CONFIGURED = "1_2_4"


def parse_xe_pvids(html: str) -> list[tuple[int, int]]:
    """GSM7252PS ``portPvidConfiguration.html`` -> ``(port, pvid)`` pairs.

    Uses the CONFIGURED PVID column (4), not the Current one (9). On the real
    capture the two disagree on the trunk-member ports 1/0/50 and 1/0/51,
    where Current reads 0 and Configured reads 1 -- and the SAME device's SNMP
    capture reports 1, i.e. dot1qPvid is the CONFIGURED value. Reading column 9
    would have made the HTTP backend silently disagree with SNMP on exactly
    the ports a LAG makes interesting.
    """
    rows = [
        r
        for r in parse_xe_rows(html)
        if _XE_PVID_IFACE in r and _XE_PVID_CONFIGURED in r
    ]
    out: list[tuple[int, int]] = []
    for r in rows:
        port = _xe_port_from_iface(r[_XE_PVID_IFACE])
        pvid = _int(r[_XE_PVID_CONFIGURED])
        if port is None or pvid is None:
            continue
        out.append((port, pvid))
    if not out:
        raise HttpUnexpectedPageError(
            "portPvidConfiguration.html: no (port, pvid) pair could be parsed"
        )
    return out


# vlanStatus.html column map, from the capture's own header row:
#   1_1_1 VLAN ID   1_1_2 VLAN Name   1_1_3 VLAN Type
#   1_1_4 Member Ports (egress list)  1_1_5 Routing Interface
_XE_VLAN_ID = "1_1_1"
_XE_VLAN_NAME = "1_1_2"
_XE_VLAN_TYPE = "1_1_3"
_XE_VLAN_MEMBERS = "1_1_4"


def _expand_s3300_port_list(raw: str) -> frozenset[int]:
    """S3300-52X egress list -> the set of PHYSICAL port numbers.

    Real format (captured): ``"1/g1 - 1/g40, 1/g42 - 1/g47, 1/xg49 - 1/xg52,
    lag 1 - lag 26"``, and a range may even MIX the two physical prefixes
    (``"1/g48 - 1/xg52"``). Only the trailing port number identifies the port
    (``1/gN`` -> N, ``1/xgN`` -> N), so the Smart-firmware ``1/x?gN`` ifName is
    matched instead of the ``1/0/N`` the gsm7252ps/M4300 pages use. ``lag N`` is
    a link-aggregation group, NOT a physical port, and is skipped -- expanding
    ``lag 1 - lag 26`` would invent 26 phantom ports (the same refusal
    ``_expand_port_list`` makes)."""
    ports: set[int] = set()
    for part in raw.split(","):
        ends = _XE_SMART_IFACE_RE.findall(part)
        if not ends:
            continue  # "lag N" and any other non-physical interface
        if "-" in part and len(ends) == 2:
            p1, p2 = int(ends[0]), int(ends[1])
            if p1 <= p2:
                ports.update(range(p1, p2 + 1))
                continue
        ports.update(int(p) for p in ends)
    return frozenset(ports)


def _xe_vlan_rows(html: str, expand: Callable[[str], frozenset[int]]) -> list[VLANInfo]:
    """Shared body of the XE/S3300 vlanStatus parsers: one VLANInfo per row,
    differing only in how the Member Ports cell is expanded (``expand``).

    A VLAN with an EMPTY member cell is real (VLANs with no members exist on the
    captured switches, which SNMP confirms), so an empty set is reported rather
    than treated as a parse failure. Neither page distinguishes tagged from
    untagged, so those stay EMPTY rather than guessed."""
    rows = [
        r
        for r in parse_xe_rows(html)
        if _XE_VLAN_ID in r and _XE_VLAN_TYPE in r and _XE_VLAN_MEMBERS in r
    ]
    out: list[VLANInfo] = []
    for r in rows:
        vid = _int(r[_XE_VLAN_ID])
        if vid is None:
            continue
        out.append(
            VLANInfo(
                vlan_id=vid,
                name=r.get(_XE_VLAN_NAME) or None,
                member_ports=expand(r[_XE_VLAN_MEMBERS]),
                tagged_ports=frozenset(),
                untagged_ports=frozenset(),
            )
        )
    if not out:
        raise HttpUnexpectedPageError("vlanStatus.html: no XE VLAN row could be parsed")
    return out


def parse_xe_vlans(html: str) -> list[VLANInfo]:
    """GSM7252PS ``vlanStatus.html`` -> VLANs with their egress member ports.

    The Member Ports cell uses the same FASTPATH egress-list syntax the M4300
    does (``"1/0/46 - 1/0/47, 1/0/49, lag 1, lag 2"``), so ``_expand_port_list``
    is shared -- including its refusal to expand ``lag N`` into physical ports.
    """
    return _xe_vlan_rows(html, _expand_port_list)


def parse_s3300_vlans(html: str) -> list[VLANInfo]:
    """S3300-52X ``vlanStatus.html`` -> VLANs with their egress member ports.

    The page shape is the sibling gsm7252ps XE ``vlanStatus`` exactly, but the
    Member Ports cell uses the Smart firmware's ``1/gN``/``1/xgN`` ifNames (and
    ranges that may mix them, ``"1/g48 - 1/xg52"``), which the ``1/0/N``-only
    ``_expand_port_list`` reads as EMPTY. ``_expand_s3300_port_list`` expands
    them by trailing port number, still skipping ``lag N``. As on the sibling,
    tagged/untagged are left empty (the page does not distinguish them).
    """
    return _xe_vlan_rows(html, _expand_s3300_port_list)


# basicAddressTable.html column map, from the capture's own header row:
#   1_2_1 VLAN ID   1_2_3 MAC Address   1_2_4 Port ("1/0/49"/"lag 1"/"0/5/1")
#   1_2_6 status ("Learned"/"Management")
#   (1_2_2 is an internal <vlan><mac> key with no header cell)
# plus the page-level scalar ``NAME=v_1_1_1`` = "Total MAC Addresses".
_XE_MAC_VLAN = "1_2_1"
_XE_MAC_ADDR = "1_2_3"
_XE_MAC_PORT = "1_2_4"
_XE_MAC_TOTAL_RE = re.compile(r'NAME=v_1_1_1 VALUE="(\d+)"')
_MAC_TEXT_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def parse_xe_macs(html: str) -> list[MacEntry]:
    """GSM7252PS ``basicAddressTable.html`` -> the MAC/FDB table.

    Two real-capture traps, both the same ones ``parse_m4300_macs`` documents:

    1. The Port cell is not always a physical interface. The capture holds 11
       entries learned on ``lag 1`` and one on the ``0/5/1`` service port --
       the latter being the switch's OWN base MAC (status "Management").
       Physical ports on this firmware are ``<unit>/0/<port>``, so a SLOT other
       than 0 is a service/CPU interface: both it and ``lag N`` are skipped
       rather than mis-attributed to physical port 1.
    2. The page states the true table size in "Total MAC Addresses". If it ever
       renders FEWER rows than that, the web UI has paginated and returning the
       first page as the whole FDB would be a silently-wrong answer -- so that
       RAISES and names SNMP as the complete source. (The captured page is not
       paginated: 242 stated, 243 rendered.)
    """
    rows = [r for r in parse_xe_rows(html) if _XE_MAC_ADDR in r and _XE_MAC_PORT in r]
    if not rows:
        raise HttpUnexpectedPageError(
            "basicAddressTable.html: no XE MAC rows "
            f"(no v_{_XE_MAC_ADDR} address cells) found"
        )
    out: list[MacEntry] = []
    for r in rows:
        mac = r[_XE_MAC_ADDR].strip().upper()
        if not _MAC_TEXT_RE.fullmatch(mac):
            continue
        iface = _FASTPATH_IFACE_RE.fullmatch(r[_XE_MAC_PORT].strip())
        if iface is None or iface.group(2) != "0":
            continue  # "lag N" or a service/CPU interface (e.g. 0/5/1)
        out.append(
            MacEntry(
                mac=mac,
                port=int(iface.group(3)),
                vlan_id=_int(r.get(_XE_MAC_VLAN, "")),
            )
        )
    total = _XE_MAC_TOTAL_RE.search(html)
    if total is not None and int(total.group(1)) > len(rows):
        raise HttpUnexpectedPageError(
            f"basicAddressTable.html: the switch reports {total.group(1)} FDB "
            f"entries but this page renders only {len(rows)} -- the web UI "
            "paginates the MAC table. Use the SNMP backend for the complete "
            "FDB rather than a silently truncated page."
        )
    return out


# S3300-52X basicAddressTable.html column map. The Smart-Managed-Pro firmware
# SHIFTS the columns relative to the gsm7252ps XE page: VLAN is v_1_2_2 (not
# v_1_2_1), MAC is v_1_2_3, and the port ifName is v_1_2_4 -- the last rendered
# HTML-entity-escaped, e.g. "1&#x2F;xg51" (&#x2F; = /). parse_xe_rows already
# html-unescapes each cell, so the port reads back as "1/xg51" for
# _xe_port_from_iface. (v_1_2_1 is a control-char index, v_1_2_5 the status.)
_S3300_MAC_VLAN = "1_2_2"
_S3300_MAC_ADDR = "1_2_3"
_S3300_MAC_PORT = "1_2_4"


def parse_s3300_macs(html: str) -> list[MacEntry]:
    """S3300-52X ``basicAddressTable.html`` -> the MAC/FDB table.

    Same XE grid as gsm7252ps but with the columns SHIFTED (see the map above)
    and port names in the Smart firmware's ``1/gN``/``1/xgN`` form. As on the
    gsm7252ps and M4300 parsers, an entry whose port is not a physical
    interface is SKIPPED rather than mis-attributed: the switch's OWN base MAC
    is learned on the CPU interface (rendered ``c1``, status "Management"),
    which ``_xe_port_from_iface`` does not resolve to a physical port. SNMP
    reports that same base MAC on the CPU ifIndex, so the HTTP FDB (physical
    entries only) differs from the SNMP FDB by exactly that one management
    entry -- the same base-MAC omission ``parse_xe_macs`` makes.

    Refuses a paginated (truncated) table rather than returning a partial FDB,
    exactly like the sibling parsers.
    """
    rows = [
        r for r in parse_xe_rows(html) if _S3300_MAC_ADDR in r and _S3300_MAC_PORT in r
    ]
    if not rows:
        raise HttpUnexpectedPageError(
            "basicAddressTable.html: no S3300 MAC rows "
            f"(no v_{_S3300_MAC_ADDR} address cells) found"
        )
    out: list[MacEntry] = []
    for r in rows:
        mac = r[_S3300_MAC_ADDR].strip().upper()
        if not _MAC_TEXT_RE.fullmatch(mac):
            continue
        port = _xe_port_from_iface(r[_S3300_MAC_PORT])
        if port is None:
            continue  # CPU/management interface ("c1"): not a physical port
        out.append(
            MacEntry(mac=mac, port=port, vlan_id=_int(r.get(_S3300_MAC_VLAN, "")))
        )
    total = _XE_MAC_TOTAL_RE.search(html)
    if total is not None and int(total.group(1)) > len(rows):
        raise HttpUnexpectedPageError(
            f"basicAddressTable.html: the switch reports {total.group(1)} FDB "
            f"entries but this page renders only {len(rows)} -- the web UI "
            "paginates the MAC table. Use the SNMP backend for the complete "
            "FDB rather than a silently truncated page."
        )
    return out


def parse_s3300_mgmt(html: str) -> MgmtIpConfig:
    """S3300-52X ``sysInfo.html`` -> base MAC ONLY (no IPv4 address).

    This page really does carry only the switch's ``Base MAC Address`` (a
    labelled cell, ``aid="1_16_1_right"``) -- but the CONCLUSION that used to be
    drawn from that was wrong. It said the IPv4 management address "lives on a
    JS-menu-only page this backend cannot reach", so ``get_mgmt_ip`` returned
    ``UNKNOWN`` mode with a ``None`` address. Live 2026-07-30 on 10.1.5.11:
    ``GET /ipConfiguration.html`` answers 200 with the real address, mask,
    gateway and method. This parser is therefore now used ONLY for the base MAC
    (uppercased, to match the SNMP/NSDP dot1dBaseBridgeAddress formatting),
    which that page does not carry -- see ``http_read._fastpath_base_mac``.
    """
    m = re.search(r"Base MAC Address</td>\s*<td[^>]*>\s*([0-9A-Fa-f:]{17})", html)
    if m is None:
        raise HttpUnexpectedPageError("sysInfo.html: no Base MAC Address cell found")
    return MgmtIpConfig(
        mode=IpMode.UNKNOWN,
        address=None,
        netmask=None,
        gateway=None,
        base_mac=m.group(1).upper(),
    )


# poeInterfaceConfiguration.html column map, from the capture's own header row:
#   1_2_1 Port          1_2_2 Admin Mode      1_2_3 High Power
#   1_2_4 Max Power     1_2_5 Port Priority   1_2_6 High Power Mode
#   1_2_7 Power Limit Type                    1_2_8 Power Limit (mW)
#   1_2_9 Detection Type                      1_2_12 Class
#   1_2_13 Output Voltage (Volts)             1_2_14 Output Current (mA)
#   1_2_15 Output Power (mW)                  1_2_17 Status
#   1_2_18 Fault Status                       1_2_19 Timer Schedule
#   1_2_22 Temperature
_XE_POE_IFACE = "1_2_1"
_XE_POE_ADMIN = "1_2_2"
_XE_POE_OUTPUT_W = "1_2_15"  # "Output Power" cell; unit varies -- see _poe_power_to_mw
_XE_POE_STATUS = "1_2_17"


def parse_xe_poe(html: str) -> list[PoEStatus]:
    """GSM7252PS ``poeInterfaceConfiguration.html`` -> per-port PoE status.

    ``power_mw`` is the "Output Power" column, normalised to milliwatts by
    ``_poe_power_to_mw`` so it matches the vendor mW OID the SNMP backend reads
    (gsm7252ps renders integer mW, the M4300-16X renders decimal watts -- see
    that helper). The Status column's text is matched against the shared
    ``_DETECT_TEXT`` vocabulary; the captured values are "Delivering power",
    "Searching" and "Other Fault" (the last -> FAULT, where SNMP's numeric
    detect map has no code and honestly reports UNKNOWN).
    """
    rows = [
        r for r in parse_xe_rows(html) if _XE_POE_IFACE in r and _XE_POE_STATUS in r
    ]
    if not rows:
        raise HttpUnexpectedPageError(
            "poeInterfaceConfiguration.html: no XE PoE rows "
            f"(no v_{_XE_POE_STATUS} status cells) found"
        )
    out: list[PoEStatus] = []
    for r in rows:
        port = _xe_port_from_iface(r[_XE_POE_IFACE])
        if port is None:
            continue
        status = r[_XE_POE_STATUS].lower()
        detect = next(
            (v for k, v in _DETECT_TEXT.items() if k in status), PoEDetect.UNKNOWN
        )
        out.append(
            PoEStatus(
                port=port,
                admin_enabled=r.get(_XE_POE_ADMIN, "").lower() == "enable",
                detect=detect,
                power_mw=_poe_power_to_mw(r.get(_XE_POE_OUTPUT_W, "")),
            )
        )
    if not out:
        raise HttpUnexpectedPageError(
            "poeInterfaceConfiguration.html: no PoE port row could be parsed"
        )
    return out


# lldpRemoteInventory.html column map, from the capture's own header row:
#   1_1_1 Port (LOCAL interface)   1_1_2 Remote Device ID (an internal index)
#   1_1_15 Management Address      1_1_7 MAC Address (remote chassis id)
#   1_1_8 System Name              1_1_9 Remote Port ID
# hidden (style="display:none") helper columns: 1_1_3 (age), 1_1_6 (chassis-id
# SUBTYPE, "MAC Address"), 1_1_14 (address type, "IPv4").
# There is NO remote-port-DESCRIPTION column on this page.
_XE_LLDP_LOCAL_IFACE = "1_1_1"
_XE_LLDP_CHASSIS = "1_1_7"
_XE_LLDP_SYS_NAME = "1_1_8"
_XE_LLDP_PORT_ID = "1_1_9"


def parse_xe_lldp(html: str) -> list[LLDPNeighbor]:
    """GSM7252PS ``lldpRemoteInventory.html`` -> LLDP neighbours.

    ``remote_port_desc`` is honestly ``None`` for every neighbour: this page
    has no such column (SNMP's lldpRemPortDesc is the source for it). The
    captured neighbour set matches the same device's SNMP capture on chassis
    ID for every shared port.

    An LLDP table with no rows is LEGITIMATELY empty (a switch may simply have
    no neighbours), so this returns ``[]`` rather than raising -- but a page
    that is not this page at all (no ``1_1_1`` local-interface cells anywhere)
    still raises.
    """
    rows = parse_xe_rows(html)
    neighbours = [r for r in rows if _XE_LLDP_LOCAL_IFACE in r]
    if not neighbours and "lldp" not in html.lower():
        raise HttpUnexpectedPageError(
            "lldpRemoteInventory.html: no XE LLDP rows and no LLDP table found"
        )
    out: list[LLDPNeighbor] = []
    for r in neighbours:
        port = _xe_port_from_iface(r[_XE_LLDP_LOCAL_IFACE])
        if port is None:
            continue
        out.append(
            LLDPNeighbor(
                local_port=port,
                remote_sys_name=r.get(_XE_LLDP_SYS_NAME) or None,
                remote_port_desc=None,  # no such column on this page
                remote_chassis_id=r.get(_XE_LLDP_CHASSIS, "").upper() or None,
                remote_port_id=r.get(_XE_LLDP_PORT_ID) or None,
            )
        )
    return out


# --- gsm7252ps sysInfo.html: format (B), plain label/value tables ---------
#
# ``/base/system/management/sysInfo.html`` is NOT an XE-generated page and
# carries no ``v_`` cells at all. Its values are plain table cells: a bold
# LABEL cell followed by its value cell(s) --
#
#   <td class="font10Bold padding4Top">System MAC Address</td>
#   <td class="font10 padding4Top">E0:91:F5:0C:D6:DB</td>
#
# An earlier draft grepped this page for the ``v_`` pattern, found none, and
# concluded the values were JS-populated -- declaring get_sensors/get_mgmt_ip
# HTTP-infeasible. They are not: every value below is present in the static
# HTML of the committed capture.
_XE_LABEL_ROW_RE = re.compile(
    r'<td[^>]*class="[^"]*font10Bold[^"]*"[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)(?:</td>|$)',
    re.DOTALL | re.IGNORECASE,
)
_XE_INPUT_VALUE_RE = re.compile(r'<INPUT[^>]*VALUE="([^"]*)"', re.IGNORECASE)
_XE_TR_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL | re.IGNORECASE)


def _xe_text(cell_html: str) -> str:
    """A sysInfo value cell's text: the ``<INPUT VALUE="...">`` if the cell is
    an editable field (System Name/Location/Contact), else its tag-stripped
    text."""
    m = _XE_INPUT_VALUE_RE.search(cell_html)
    if m:
        return unescape(m.group(1)).strip()
    return unescape(_TAG_RE.sub("", cell_html)).strip()


def parse_xe_labelled_values(html: str) -> dict[str, str]:
    """``sysInfo.html`` -> ``{label: first value cell}`` for every bold-labelled
    row (identity, mgmt IP, and the first UNIT column of the status tables).

    Returns ``{}`` for a page with no such rows -- the caller decides whether
    that is fatal (``parse_xe_mgmt_ip`` does; ``parse_xe_sensors`` does not,
    since it reads the status tables through ``_xe_status_rows`` instead)."""
    return {
        label: _xe_text(value)
        for label, value in (
            (unescape(_TAG_RE.sub("", raw_label)).strip(), raw_value)
            for raw_label, raw_value in _XE_LABEL_ROW_RE.findall(html)
        )
        if label
    }


def _xe_sysinfo_section(html: str, title: str) -> str:
    """The slice of ``sysInfo.html`` belonging to one status table.

    Each block is introduced by its own ``<script>tbhdr('FAN Status',...)``
    call, so a section runs from its ``tbhdr`` to the next one (or EOF). Used
    to keep the three same-shaped tables (Temperature/FAN/Device Status)
    apart -- they share cell classes and would otherwise merge."""
    start = html.find(f"tbhdr('{title}'")
    if start < 0:
        return ""
    nxt = html.find("tbhdr('", start + 1)
    return html[start:nxt] if nxt >= 0 else html[start:]


def _xe_status_rows(section: str) -> list[tuple[str, list[str]]]:
    """One ``(label, per-unit values)`` pair per DATA row of a status table.

    The header row (``Unit ID | 1 | 2 ...``, ``Sensor Type | Unit 1 | ...``)
    is identified by its ``messageTableHeader*`` cell classes and dropped:
    keeping it would turn the literal header text into a sensor named
    "Sensor Type" reading 1.0."""
    rows: list[tuple[str, list[str]]] = []
    for row in _XE_TR_RE.findall(section):
        if "messageTableHeader" in row:
            continue
        cells = [unescape(c) for c in _cells(row)]
        if len(cells) < 2 or not cells[0]:
            continue
        rows.append((cells[0], cells[1:]))
    return rows


def _xe_sensor_name(label: str, unit: int) -> str:
    """Sensor name for a stacked switch: the bare page label on unit 1 (the
    only populated unit on the captured switch), suffixed on any other."""
    return label if unit == 1 else f"{label} unit {unit}"


# The FAN/Device-Status tables report HEALTH AS TEXT ("OK", "Operational"),
# never a number. ``Sensor.value`` is a required float, so these are reported
# with unit "state" -- deliberately NOT "RPM"/"W" -- and the value is a health
# flag: 1.0 = the healthy text this firmware prints, 0.0 = any other REPORTED
# state (e.g. a failed fan). A slot that reports nothing at all ("NA", "N/A",
# blank -- e.g. the unpopulated Fan4/Fan5 and stack units 2-8) is SKIPPED, not
# reported as 0.0, because absence is not failure. SNMP remains the source of
# real fan RPM / PSU watts on this model.
_XE_HEALTHY_TEXT = {"ok", "operational"}
_XE_ABSENT_TEXT = {"", "na", "n/a", "not supported", "-"}
# Rows of the "Device Status" table that are SENSORS; the rest of that table
# (Firmware/Boot/CPLD/PoE version, Serial Number, MAX PoE) is identity, not a
# reading, and must not be emitted as one.
_XE_POWER_ROWS = ("RPS", "Power Module")


def _xe_state_sensors(
    section: str, kind: str, only: tuple[str, ...] | None = None
) -> list[Sensor]:
    out: list[Sensor] = []
    for label, values in _xe_status_rows(section):
        if only is not None and label not in only:
            continue
        for unit, raw in enumerate(values, start=1):
            text = raw.strip().lower()
            if text in _XE_ABSENT_TEXT:
                continue
            out.append(
                Sensor(
                    name=_xe_sensor_name(label, unit),
                    kind=kind,
                    value=1.0 if text in _XE_HEALTHY_TEXT else 0.0,
                    unit="state",
                )
            )
    return out


def parse_xe_sensors(html: str) -> list[Sensor]:
    """GSM7252PS ``sysInfo.html`` -> box sensors.

    Three blocks, all present in the static HTML of the committed capture:

    - **Temperature Status** -- real numeric readings (``29&degC``) per stack
      unit. A sensor reading ``N/A`` (the MAC row on the captured switch) is
      absent, not 0, and is skipped.
    - **FAN Status** -- ``OK``/``NA`` per fan. Reported as ``unit="state"``
      health flags, never as RPM (see ``_XE_HEALTHY_TEXT``).
    - **Device Status** -- only the ``RPS`` and ``Power Module`` rows, as
      ``kind="power"`` state flags; the firmware/serial rows in that same
      table are identity, not sensors.

    Returns ``[]`` for a page with none of those tables; the caller decides.
    """
    out: list[Sensor] = []
    for label, values in _xe_status_rows(
        _xe_sysinfo_section(html, "Temperature Status")
    ):
        for unit, raw in enumerate(values, start=1):
            celsius = _int(raw)
            if celsius is None:
                continue  # "N/A" -- absent, not zero
            out.append(
                Sensor(
                    name=_xe_sensor_name(label, unit),
                    kind="temperature",
                    value=float(celsius),
                    unit="C",
                )
            )
    out += _xe_state_sensors(_xe_sysinfo_section(html, "FAN Status"), "fan")
    out += _xe_state_sensors(
        _xe_sysinfo_section(html, "Device Status"), "power", only=_XE_POWER_ROWS
    )
    return out


def parse_xe_mgmt_ip(html: str) -> MgmtIpConfig:
    """GSM7252PS ``sysInfo.html`` -> management IP + base MAC.

    ``IPv4 Network Interface`` renders as ``addr/netmask`` inside a link to
    ipConfiguration.html; ``System MAC Address`` is a plain labelled cell. The
    page reports neither a gateway nor a DHCP/static indicator, so those stay
    ``None``/``UNKNOWN`` rather than guessed -- which is exactly what the SNMP
    backend reports for this same device (see
    ``tests/fixtures/captures/gsm7252ps.json``).
    """
    fields = parse_xe_labelled_values(html)
    iface = fields.get("IPv4 Network Interface", "")
    addr = netmask = None
    m = re.match(r"\s*([0-9.]+)\s*/\s*([0-9.]+)", iface)
    if m:
        addr, netmask = m.group(1), m.group(2)
    mac = fields.get("System MAC Address", "").strip().upper()
    if not _MAC_TEXT_RE.fullmatch(mac):
        mac = ""
    if addr is None and not mac:
        raise HttpUnexpectedPageError(
            "sysInfo.html: neither IPv4 Network Interface nor System MAC Address found"
        )
    return MgmtIpConfig(
        mode=IpMode.UNKNOWN,
        address=addr,
        netmask=netmask,
        gateway=None,
        base_mac=mac or None,
    )


# A page-level XUI scalar carries NO instance prefix (``NAME=v_1_1_1``), which
# is exactly why ``parse_xe_rows`` skips them -- they are not table rows. The
# service and syslog pages below read them by coordinate instead.
_XE_SCALAR_RE = re.compile(r'NAME=v_(\d+_\d+_\d+) VALUE="([^"]*)"', re.IGNORECASE)


# --- management-service pages (http / https / ssh / telnet) ----------------
#
# LIVE-MEASURED 2026-08-03 on gsm7252ps 10.1.5.22, gsm7228ps 10.1.5.11 and
# m4300-24x 10.1.5.13. These pages come in TWO shapes, and -- this is the part
# that dictates the design -- the shapes are MIXED WITHIN A SINGLE MODEL, so
# the parser cannot be keyed by model or by html_dialect, only per service:
#
#   gsm7252ps  http/https/ssh/telnet  all four XUI labelled scalars
#   m4300-24x  http/https             PLAIN named form (radios + text inputs)
#              ssh/telnet             XUI
#   gsm7228ps  https                  PLAIN;  telnet XUI
#              http                   PLAIN but with NO admin control at all
#              ssh                    HTTP 404
#
# So each service below carries BOTH addresses and the parser tries the XUI
# coordinate first, then the named radio group.
#
# THE RADIO TRAP. On every plain-form page BOTH radios of the group carry a
# checked attribute, spelled two different ways -- verbatim from m4300-24x:
#
#   <INPUT type="radio" name="httpAdmin" id="httpAdminDisable" value="Disable"
#          ... checked="checked" disabled="disabled" >
#   <INPUT type="radio" name="httpAdmin" id="httpAdminEnable"  value="Enable"
#          ... disabled="disabled" CHECKED>
#
# A browser applies them in document order, so the LAST wins and the true state
# is Enable. That reading is self-evidencing here: the page was fetched OVER
# HTTP, so HTTP cannot be disabled. A parser taking the first match would report
# every one of these switches as having HTTP off.
_RADIO_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _radio_group(html: str, name: str) -> list[tuple[str, bool]]:
    """Every radio of group ``name``, in DOCUMENT ORDER, as (value, checked)."""
    pattern = _RADIO_RE_CACHE.get(name)
    if pattern is None:
        pattern = re.compile(
            rf'<INPUT\b(?=[^>]*\btype="radio")(?=[^>]*\bname="{re.escape(name)}")'
            r"[^>]*>",
            re.IGNORECASE,
        )
        _RADIO_RE_CACHE[name] = pattern
    out: list[tuple[str, bool]] = []
    for tag in pattern.findall(html):
        value = re.search(r'\bvalue="([^"]*)"', tag, re.IGNORECASE)
        if value is None:
            continue
        # Both spellings, and `checked` must be its own attribute -- a bare
        # substring test would also match id="...Checked" style names.
        checked = re.search(r'\bchecked\b(?:\s*=\s*"[^"]*")?', tag, re.IGNORECASE)
        out.append((value.group(1), checked is not None))
    return out


def _checked_radio(html: str, name: str) -> str | None:
    """The value the browser would show selected: the LAST checked radio."""
    checked = [value for value, is_checked in _radio_group(html, name) if is_checked]
    return checked[-1] if checked else None


_PLAIN_FORM_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _plain_form_value(html: str, name: str) -> str | None:
    """A plain named text input's ``VALUE=``, or ``None`` if the page has none.

    Deliberately NOT named ``_named_input_value``: this module already has a
    function by that name for the gs110emx/gs105pe identity pages, further
    down. The two are not interchangeable -- that one matches lowercase
    ``value=`` case-SENSITIVELY, which never matches these FASTPATH pages'
    uppercase ``VALUE="80"``, and a same-named second definition would simply
    replace it at import time and break those parsers instead.
    """
    pattern = _PLAIN_FORM_RE_CACHE.get(name)
    if pattern is None:
        pattern = re.compile(
            rf'<INPUT\b(?=[^>]*\bname="{re.escape(name)}")[^>]*\bVALUE="([^"]*)"',
            re.IGNORECASE,
        )
        _PLAIN_FORM_RE_CACHE[name] = pattern
    m = pattern.search(html)
    return m.group(1) if m else None


@dataclass(frozen=True)
class _ServiceFields:
    """Where one service's admin state and port live, in EITHER page shape."""

    #: XUI scalar coordinate carrying Enable/Disable.
    xui_admin: str
    #: XUI scalar coordinate carrying the port, where the page prints one.
    xui_port: str | None
    #: Plain-form radio group name carrying Enable/Disable.
    radio: str | None
    #: Plain-form text input carrying the port.
    form_port: str | None


#: Per service, transcribed from the live pages named above. Each label is that
#: page's own caption for the coordinate.
_SERVICE_FIELDS: Mapping[str, _ServiceFields] = MappingProxyType(
    {
        # "HTTP Access". The XUI page prints NO port row, so xui_port is None
        # and the port stays None there rather than being defaulted to 80.
        "http": _ServiceFields("1_1_1", None, "httpAdmin", "httpPort"),
        # "HTTPS Admin Mode" + "HTTPS Port" (443 on every switch measured).
        "https": _ServiceFields("1_1_1", "1_4_1", "sslAdmin", "httpsPort"),
        # "SSH Admin Mode". v_1_10_1 is the SSH Port -- present on m4300
        # ('22'), ABSENT on gsm7252ps, which is exactly what
        # ServiceStatus.port's docstring already recorded. No plain-form SSH
        # page has been seen, so there is no radio fallback for it.
        "ssh": _ServiceFields("1_1_1", "1_10_1", None, None),
        # "Telnet Server Admin Mode" -- note the 2_x coordinate: this page's
        # first section is the authentication lists, not the admin state.
        "telnet": _ServiceFields("2_5_1", None, None, None),
    }
)

#: The order get_services reports in, matching the CLI backend's.
SERVICE_NAMES: tuple[str, ...] = ("http", "https", "ssh", "telnet")


def parse_service_page(html: str, service: str) -> ServiceStatus:
    """One service's config page -> its :class:`ServiceStatus`.

    Tries the XUI coordinate, then the plain-form radio group. Raises
    ``HttpUnexpectedPageError`` when NEITHER is present rather than reporting
    the service as disabled -- a page that does not carry the control (the
    S3300's httpConfiguration.html genuinely does not) says nothing about
    whether the service is running, and a login redirect says nothing either.
    """
    fields = _SERVICE_FIELDS[service]
    scalars = dict(_XE_SCALAR_RE.findall(html))
    admin = scalars.get(fields.xui_admin)
    if admin is not None:
        port_text = scalars.get(fields.xui_port or "", "")
    else:
        admin = _checked_radio(html, fields.radio) if fields.radio else None
        if admin is None:
            raise HttpUnexpectedPageError(
                f"{service} configuration page: no admin-state control found "
                f"(neither XUI v_{fields.xui_admin} nor a "
                f"{fields.radio!r} radio group)"
            )
        port_text = _plain_form_value(html, fields.form_port or "") or ""
    return ServiceStatus(
        name=service,
        enabled=admin.strip().lower() == "enable",
        port=_int(port_text),
    )


# --- userManagement.html (login accounts) ---------------------------------
#
# LIVE-CAPTURED 2026-08-03 from gsm7252ps 10.1.5.22 and m4300-24x 10.1.5.13,
# whose pages are the same XUI row grid. Coordinates transcribed from each
# page's OWN header row, quoted beside each below.
#
# NOT to be confused with ``userConfiguration.html``, which sounds like this
# page and is not: on every managed switch that is the SNMPv3 user page (Access
# Mode / Authentication Protocol / Encryption Protocol) listing no login
# accounts at all. Reading it here would report SNMPv3 credentials as logins.
_USER_NAME = "1_1_2"  # "User Name"      -> admin / guest
_USER_ACCESS_MODE = "1_1_5"  # "Access Mode"    -> Super User / Read Only

# The password columns ("Password"/"Confirm Password", 1_1_3/1_1_4) are ignored:
# gsm7252ps renders them as a literal "********" and the M4300 as empty, so
# neither carries a secret -- nor anything useful. SwitchUser has no password
# field for the same reason.


def parse_xui_users(html: str) -> list[SwitchUser]:
    """``userManagement.html`` -> the switch's local login accounts.

    Raises ``HttpUnexpectedPageError`` if the page carries no user rows. A
    switch always has at least the account this very request authenticated as,
    so an empty list means the fetch landed somewhere else -- "this switch has
    no accounts" is not an answer any device would give.
    """
    users = [
        SwitchUser(
            name=name,
            # Preserved verbatim: this page says "Super User" where the same
            # switch's own CLI says "Read/Write" or "Privilege-15".
            access_mode=row.get(_USER_ACCESS_MODE, "").strip(),
            privileged=privileged_access(row.get(_USER_ACCESS_MODE, "")),
        )
        for row in parse_xe_rows(html)
        if (name := row.get(_USER_NAME, "").strip())
    ]
    if not users:
        raise HttpUnexpectedPageError(
            "userManagement.html: no user rows on page (a switch always has at "
            "least the account this request authenticated as)"
        )
    return users


# --- syslogConfiguration.html (every FASTPATH model) ----------------------
#
# Coordinates transcribed from a LIVE fetch of syslogConfiguration.html on all
# four managed switches (2026-08-03): gsm7252ps 10.1.5.22, gsm7228ps/S3300
# 10.1.5.11, m4300-24x 10.1.5.13 and m4300-16x 10.1.5.20. Each label below is
# that page's own visible header/field caption for the same coordinate.
#
# The two families' pages are NOT identical -- the M4300s are Cheetah, adding a
# trailing ``<!-- baselogCfg_LogSyslogAdminStatus -->`` comment per cell plus two
# scalars the GSMs lack (1_6_1 source interface, 1_7_1 USB file name) -- but the
# COORDINATES they share are the same on all four, which is why one parser
# serves both rather than a per-dialect pair. That was measured, not assumed:
# the M4300 page was fetched and diffed against the GSM one before this was
# written.
_SYSLOG_ADMIN_STATUS = "1_1_1"  # "Admin Status"       -> Enable/Disable
_SYSLOG_LOCAL_PORT = "1_2_1"  # "Local UDP Port"     -> 514
# Public because the WRITER addresses the same cells (see http_write). The
# column map is the page's own xeData, read off the served M4300 page
# 2026-08-05 -- note the field-name HTML comments TRAIL their cell, so reading
# them as leading labels shifts every column by one:
#   2_1_1 Host Address (string)      2_1_5 row-status, WRITE-ONLY, hidden
#   2_1_2 Status, row-status, READ-ONLY   2_1_6 Host Index (uint, hidden)
#   2_1_3 Port (uint)                2_1_7 IP Address Type (enum)
#   2_1_4 Severity Filter (enum)
SYSLOG_HOST_ADDRESS = "2_1_1"  # "Host Address"       -> 10.1.5.1
SYSLOG_HOST_PORT = "2_1_3"  # "Port"               -> 514
SYSLOG_HOST_SEVERITY = "2_1_4"  # "Severity Filter"    -> Info
#: The cell an ADD sets to "Active" and a DELETE sets to "Delete". NOT 2_1_2,
#: which is the read-only mirror the table displays.
SYSLOG_HOST_ROW_STATUS = "2_1_5"
#: "Host Index" -- the table's own row handle, which SNMP walks as the OID
#: instance and the CLI prints in its Index column. Surfaced so all three
#: backends report the same SyslogServer for the same row; without it the
#: cross-backend equivalence test fails on index=None vs index=1.
SYSLOG_HOST_INDEX = "2_1_6"
_SYSLOG_HOST_ADDRESS = SYSLOG_HOST_ADDRESS
_SYSLOG_HOST_STATUS = "2_1_2"  # "Status"             -> Active
_SYSLOG_HOST_PORT = SYSLOG_HOST_PORT
_SYSLOG_HOST_SEVERITY = SYSLOG_HOST_SEVERITY


def parse_xui_syslog(html: str) -> SyslogConfig:
    """``syslogConfiguration.html`` -> ``SyslogConfig`` (all FASTPATH models).

    The collector rows are ordinary XUI table rows, so ``parse_xe_rows`` groups
    them; the admin status and local port are page-level scalars, read by
    coordinate above. A row whose coordinates are absent is skipped rather than
    defaulted -- the blank ``g_2_1_*`` template row carries no instance prefix
    and never reaches here in the first place.

    Raises ``HttpUnexpectedPageError`` if the admin-status scalar is missing:
    that is the one field every version of this page has, so its absence means
    the fetch landed somewhere else (a login redirect, a 404 body) and an
    ``enabled=False`` answer would be a fabrication.
    """
    scalars = dict(_XE_SCALAR_RE.findall(html))
    admin = scalars.get(_SYSLOG_ADMIN_STATUS)
    if admin is None:
        raise HttpUnexpectedPageError(
            "syslogConfiguration.html: no Admin Status field "
            f"(NAME=v_{_SYSLOG_ADMIN_STATUS}) on page"
        )
    local_port = _int(scalars.get(_SYSLOG_LOCAL_PORT, ""))

    servers: list[SyslogServer] = []
    for row in parse_xe_rows(html):
        host = row.get(_SYSLOG_HOST_ADDRESS, "").strip()
        if not host:
            continue
        port = _int(row.get(_SYSLOG_HOST_PORT, ""))
        index = _int(row.get(SYSLOG_HOST_INDEX, ""))
        servers.append(
            SyslogServer(
                index=index,
                host=host,
                port=port if port is not None else 0,
                # The web UI prints the severity WORD ("Info") where SNMP
                # reports the number (6); syslog_severity() is the shared,
                # measured map and RAISES on a word no device here has printed.
                severity=syslog_severity(row.get(_SYSLOG_HOST_SEVERITY, "")),
                active=row.get(_SYSLOG_HOST_STATUS, "").strip().lower() == "active",
            )
        )
    return SyslogConfig(
        enabled=admin.strip().lower() == "enable",
        local_port=local_port if local_port is not None else 0,
        servers=tuple(servers),
    )


def parse_poe_status(html: str) -> list[PoEStatus]:
    """getPoePortStatus.cgi ``portID`` rows: [1]=port,[2]=state,[3]=power_mw."""
    rows = _ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'getPoePortStatus.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[PoEStatus] = []
    for row in rows:
        c = _cells(row)
        if len(c) < 3:
            raise HttpUnexpectedPageError(
                f"getPoePortStatus.cgi: expected >=3 <td> columns per "
                f"portID row, got {len(c)}"
            )
        port = _int(c[0])
        if port is None:
            raise HttpUnexpectedPageError(
                f"getPoePortStatus.cgi: could not parse a port number "
                f"from column {c[0]!r}"
            )
        detect = _DETECT_TEXT.get(c[1].lower(), PoEDetect.UNKNOWN)
        out.append(
            PoEStatus(
                port=port,
                admin_enabled=detect is not PoEDetect.DISABLED,
                detect=detect,
                power_mw=_int(c[2]),
            )
        )
    return out


def parse_pvids(html: str) -> list[tuple[int, int]]:
    """portPVID.cgi rows: ``sel="text"`` cell = port, ``sel="input"`` cell = PVID."""
    rows = _ROW_RE.findall(html)
    if not rows:
        raise HttpUnexpectedPageError(
            'portPVID.cgi: expected <tr class="portID"> rows, found none'
        )
    out: list[tuple[int, int]] = []
    for m in re.finditer(
        r'<td[^>]*sel="text"[^>]*>(\d+).*?</td>\s*<td[^>]*sel="input"[^>]*>(\d+)</td>',
        html,
        re.DOTALL,
    ):
        out.append((int(m.group(1)), int(m.group(2))))
    if not out:
        raise HttpUnexpectedPageError(
            'portPVID.cgi: expected <td sel="text"> and <td sel="input"> '
            "cells in portID rows, found none matching"
        )
    return out


def parse_vlan_ids(html: str) -> list[int]:
    """8021qCf.cgi VLAN checkboxes: ``name="vlanckN" value="VID"``."""
    matches = list(re.finditer(r'name="vlanck\d+"[^>]*value="(\d+)"', html))
    if not matches:
        raise HttpUnexpectedPageError(
            '8021qCf.cgi: expected at least one name="vlanckN" checkbox, found none'
        )
    return sorted({int(m.group(1)) for m in matches})


def parse_selected_vlan(html: str) -> int | None:
    """8021qMembe.cgi selected VLAN in the dropdown."""
    m = re.search(r'<option[^>]*selected[^>]*value="(\d+)"', html)
    if m:
        return int(m.group(1))
    m = re.search(r'<option[^>]*value="(\d+)"[^>]*selected', html)
    return int(m.group(1)) if m else None


def parse_membership(html: str, port_count: int) -> dict[int, VlanMode]:
    """8021qMembe.cgi ``hiddenMem`` string: per-port 1=Untagged/2=Tagged/3=Excluded."""
    m = re.search(r'id="hiddenMem"[^>]*value="([^"]*)"', html) or re.search(
        r'name="hiddenMem"[^>]*value="([^"]*)"', html
    )
    if not m:
        raise HttpUnexpectedPageError(
            "8021qMembe.cgi: expected a hiddenMem input with the per-port wire "
            "codes, found none"
        )
    raw = m.group(1)
    if len(raw) < port_count:
        raise HttpUnexpectedPageError(
            f"8021qMembe.cgi: hiddenMem value {raw!r} has fewer than "
            f"port_count={port_count} codes"
        )
    result: dict[int, VlanMode] = {}
    for i, ch in enumerate(raw[:port_count]):
        mode = _WIRE_TO_MODE.get(ch)
        if mode is None:
            raise HttpUnexpectedPageError(
                f"8021qMembe.cgi: unknown VLAN wire code {ch!r} at port {i + 1}"
            )
        result[i + 1] = mode
    return result


# ---------------------------------------------------------------------------
# FASTPATH "VLAN Membership" page (switching/dot1q/vlan_port_cfg{,_rw}.html)
#
# LIVE-DISCOVERED 2026-07-30. The page URL is not statically guessable -- fifteen
# FASTPATH-style names (vlanMembership.html, vlanMemberConfiguration.html,
# vlanPortConfiguration.html, ...) all returned HTTP 404 on 10.1.5.22. The real
# URL is a menu leaf in the JS nav tree, /base/js/ng_sideNav.js:
#     str+=FrthLvl("lvl2","VLAN Membership",
#                        "switching/dot1q/vlan_port_cfg.html","none");
# and the same relative path exists on all four managed switches (under /v1/ on
# the M4300s).
#
# Wire codes in hiddenMem are 1=Tagged, 2=Untagged, 3=Excluded -- the INVERSE of
# the Plus-class 8021qMembe.cgi map above (1=Untagged, 2=Tagged), so the two must
# never share an encoder. Grounded in the firmware's own JS: rollover.js's
# toggleImage() writes "1" when the cell image becomes ``*_t.gif`` (tagged), "2"
# for ``*_u.gif`` (untagged) and "3" for ``*_b.gif`` (blank/exclude); the newer
# togImg() does the same for switch_tagged/untagged/blank_*.png.
_FASTPATH_MEM_TO_MODE = {
    "1": VlanMode.TAGGED,
    "2": VlanMode.UNTAGGED,
    "3": VlanMode.EXCLUDED,
}
_MODE_TO_FASTPATH_MEM = {mode: code for code, mode in _FASTPATH_MEM_TO_MODE.items()}

# The real form's own POST target, used to locate the field block (the pages also
# carry document.write()-ed HTML inside <script> blocks, which must NOT be
# scraped as form fields).
_FASTPATH_MEM_ACTION_RE = re.compile(
    r'<form\s+method="?post"?\s+ACTION="([^"]*vlan_port_cfg_rw\.html)"', re.IGNORECASE
)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
# Each attribute, with or without a value: group 2 is None for a bare flag
# (``SELECTED``, ``READONLY``), otherwise groups 3/4/5 hold the double-quoted,
# single-quoted or unquoted value.
_BARE_ATTR_RE = re.compile(r"""([\w.-]+)(\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?""")
_SELECT_RE = re.compile(r"<select\b([^>]*)>(.*?)</select>", re.IGNORECASE | re.DOTALL)
_OPTION_RE = re.compile(r"<option\b([^>]*)>", re.IGNORECASE)
_VLANID_SELECT_RE = re.compile(
    r'<select[^>]*name="vlanId"[^>]*>(.*?)</select>', re.IGNORECASE | re.DOTALL
)

# Grid style A -- gsm7252ps (older XE firmware): a per-cell
# ``toggleImageFirst(this,<0-based slot>,0,'img_unit<N>',<interface number>)``
# handler followed by the cell image whose ``*_[btu].gif`` suffix carries the
# state. The LAG pseudo-unit uses the SAME shape (image ids 418..481), so the
# enclosing grid table's own row label ("Port" vs "LAG") is what separates
# physical ports from LAGs -- see _FASTPATH_GRID_TABLE_RE.
_FASTPATH_GRID_A_RE = re.compile(
    r"toggleImageFirst\(this,(\d+),\d+,'img_unit\d+',(\d+)\)"
    r'.*?<img src="/base/images/(?:grey|blue)_([btu])\.gif" name="imx"',
    re.DOTALL,
)
_FASTPATH_GRID_TABLE_RE = re.compile(
    r'<table[^>]*id="unit\d+tb"[^>]*>(.*?)</table>', re.DOTALL | re.IGNORECASE
)
_FASTPATH_GRID_LABEL_RE = re.compile(r"<td[^>]*>\s*([A-Za-z]+)\s*</td>")

# Grid style B -- gsm7228ps/S3300 + both M4300s (newer jQuery firmware): the cell
# carries the interface's ifName in ``aid`` and a
# ``togImg(this,<1-BASED slot>,0,"hiddenMem")`` handler; the state is in the
# image filename (switch_<state>[_bottom]_inactive.png). LAG cells have
# aid='lag N', which is not a port ifName and so drops out naturally.
_FASTPATH_GRID_B_RE = re.compile(
    r"aid='port-([^']+)'[^>]*?src='[^']*/switch_([a-z]+?)(?:_bottom)?_[a-z]+\.png'"
    r"[^>]*?name='imx'[^>]*?togImg\(this,(\d+),\d+,\"hiddenMem\"\)"
)
_FASTPATH_IMG_TO_MODE = {
    "t": VlanMode.TAGGED,
    "u": VlanMode.UNTAGGED,
    "b": VlanMode.EXCLUDED,
    "tagged": VlanMode.TAGGED,
    "untagged": VlanMode.UNTAGGED,
    "blank": VlanMode.EXCLUDED,
}


def _tag_attrs(raw: str) -> dict[str, str]:
    """Attribute map of one tag's inner text, lower-cased keys.

    Valueless (boolean) attributes are recorded with an empty value, because on
    these pages the one that matters is exactly that shape: real firmware writes
    ``<OPTION class="selectfield" value="4" SELECTED>``, so a key=value-only
    scrape reads the page as having NO selected VLAN.
    """
    out: dict[str, str] = {}
    for m in _BARE_ATTR_RE.finditer(raw):
        key = m.group(1).lower()
        value = m.group(2)
        if value is None:
            out.setdefault(key, "")
            continue
        out[key] = m.group(3) or m.group(4) or m.group(5) or ""
    return out


def _fastpath_physical_port(ifname: str) -> int | None:
    """The physical port number in a FASTPATH ifName, or ``None`` if it is not a
    physical port.

    Three real spellings appear on these pages (all captured):
    ``1/0/49`` (unit/slot/port -- every model's hiddenTagged/hiddenUnTagged list
    and the M4300 grid), ``1/g41``/``1/xg49`` (the S3300 grid's Smart-firmware
    names) and ``0/3/1``/``0/13/1`` -- the LAG pseudo-interfaces, which are NOT
    physical ports. Unit 0 is what marks a non-physical interface: LAGs are
    ``0/<slot>/<n>`` (slot 3 on the gsm72xx, 13 on the M4300), so a bare
    ``\\d+/\\d+/\\d+`` match would wrongly turn ``0/3/64`` into "port 64". That
    exact mistake once expanded ``lag 1 - lag 128`` into 128 phantom ports (see
    ``_expand_port_list``); the guard is kept explicit here for the same reason.
    """
    text = unescape(ifname).strip()
    m = re.fullmatch(r"(\d+)/(\d+)/(\d+)", text)
    if m:
        unit, slot, port = (int(g) for g in m.groups())
        return port if unit != 0 and slot == 0 else None
    m = re.fullmatch(r"(\d+)/x?g(\d+)", text)
    return int(m.group(2)) if m else None


def _fastpath_iface_list(raw: str) -> frozenset[int]:
    """A ``hiddenTagged``/``hiddenUnTagged`` value -> physical port numbers.

    The value is a comma-separated ifName list, HTML-entity-escaped on the newer
    firmwares (``1&#x2F;0&#x2F;49``) and sometimes with a TRAILING comma
    (M4300: ``"1/0/5,"``). LAG entries (``0/3/1``) are skipped.
    """
    ports: set[int] = set()
    for part in unescape(raw).split(","):
        if not part.strip():
            continue
        port = _fastpath_physical_port(part)
        if port is not None:
            ports.add(port)
    return frozenset(ports)


def _fastpath_form_fields(block: str) -> dict[str, str]:
    """Every named ``<input>``/``<select>`` in the membership form, verbatim.

    Text/hidden inputs give their ``value``; a ``<select>`` gives the ``value``
    of its ``selected`` ``<option>`` (falling back to the first option, which is
    what a browser submits when the firmware marks none) -- so re-POSTing this
    map reproduces exactly what the browser would send.
    """
    fields: dict[str, str] = {}
    for m in _INPUT_RE.finditer(block):
        attrs = _tag_attrs(m.group(1))
        name = attrs.get("name")
        if name:
            fields[name] = attrs.get("value", "")
    for m in _SELECT_RE.finditer(block):
        name = _tag_attrs(m.group(1)).get("name")
        if not name:
            continue
        options = [_tag_attrs(o.group(1)) for o in _OPTION_RE.finditer(m.group(2))]
        chosen = next((o for o in options if "selected" in o), None)
        if chosen is None and options:
            chosen = options[0]
        fields[name] = chosen.get("value", "") if chosen else ""
    return fields


def _fastpath_grid(block: str) -> dict[int, tuple[int, VlanMode]]:
    """Port grid -> ``{physical port: (0-based hiddenMem slot, rendered mode)}``.

    Handles both firmware generations (see ``_FASTPATH_GRID_A_RE`` /
    ``_FASTPATH_GRID_B_RE``). Raises if neither shape is present: the page always
    renders a grid on real hardware, so finding none means the wrong page came
    back, not "no ports".
    """
    grid: dict[int, tuple[int, VlanMode]] = {}
    for name, state, slot1 in _FASTPATH_GRID_B_RE.findall(block):
        port = _fastpath_physical_port(name)
        mode = _FASTPATH_IMG_TO_MODE.get(state)
        if port is None or mode is None:
            continue
        # 1-BASED on this firmware: rollover.js's togImg() computes
        # ``j = (index - 1) * 2`` into the comma-separated hiddenMem string.
        grid[port] = (int(slot1) - 1, mode)
    if grid:
        return grid
    for table in _FASTPATH_GRID_TABLE_RE.findall(block):
        label = _FASTPATH_GRID_LABEL_RE.search(table)
        if label is None or label.group(1).lower() != "port":
            continue  # the LAG pseudo-unit table, or a table with no row label
        for slot0, intf, state in _FASTPATH_GRID_A_RE.findall(table):
            mode = _FASTPATH_IMG_TO_MODE.get(state)
            if mode is not None:
                # 0-BASED on this firmware: toggleImage() computes ``j = 2*index``.
                grid[int(intf)] = (int(slot0), mode)
    if not grid:
        raise HttpUnexpectedPageError(
            "vlan_port_cfg.html: no port-membership grid could be parsed (neither "
            "the toggleImageFirst/grey_*.gif nor the togImg/switch_*.png shape)"
        )
    return grid


def _fastpath_vlan_select(block: str) -> tuple[int | None, tuple[int, ...]]:
    """The ``vlanId`` ``<select>`` -> (currently-shown VLAN, every VLAN offered).

    Scoped to that ONE select on purpose: the page carries a second
    ``<select name="select">`` (the Group Operation menu, values ``UntagAll``/
    ``TagAll``/``RemoveAll``) and, inside ``<script>`` blocks, ``document.write``-d
    markup. Real firmware writes the tag uppercase and the attribute bare
    (``<OPTION class="selectfield" value="4" SELECTED>``), so the match is
    case-insensitive -- the existing ``parse_selected_vlan`` (lower-case-only,
    used by the Plus-class pages) reads ``None`` here.
    """
    m = _VLANID_SELECT_RE.search(block)
    if m is None:
        raise HttpUnexpectedPageError(
            'vlan_port_cfg.html: no <select name="vlanId"> -- cannot tell which '
            "VLAN this page is showing"
        )
    selected: int | None = None
    ids: set[int] = set()
    for opt in _OPTION_RE.finditer(m.group(1)):
        attrs = _tag_attrs(opt.group(1))
        value = attrs.get("value", "")
        if not value.isdigit():
            continue
        ids.add(int(value))
        if "selected" in attrs:
            selected = int(value)
    return selected, tuple(sorted(ids))


def parse_fastpath_err(html: str) -> str | None:
    """The FASTPATH page's own error banner, or ``None`` when it reports success.

    Every one of these pages carries a hidden ``err_flag``/``err_msg`` pair, and
    its ``check_error()`` handler alerts the ``err_msg`` when ``err_flag == 1``.
    The page still returns HTTP 200, so this is the ONLY signal that the switch
    refused the write. Returns the message (falling back to a generic string when
    the firmware sets the flag but leaves the text empty) so the caller can
    surface exactly what the device said.
    """
    flag = re.search(r'name="err_flag"[^>]*value="([^"]*)"', html, re.IGNORECASE)
    if flag is None or flag.group(1).strip() in ("", "0"):
        return None
    msg = re.search(r'name="err_msg"[^>]*value="([^"]*)"', html, re.IGNORECASE)
    text = unescape(msg.group(1)).strip() if msg else ""
    return text or f"err_flag={flag.group(1)} with no err_msg"


def parse_fastpath_membership(html: str) -> FastpathMembership:
    """FASTPATH ``switching/dot1q/vlan_port_cfg.html`` -> one VLAN's membership.

    See ``types.FastpathMembership`` for what the two views mean and why they can
    legitimately differ. Raises ``HttpUnexpectedPageError`` if the page is not
    this page (no ``_rw.html`` form, no ``hiddenMem``, no port grid) or if it
    carries a wire code / grid state this parser does not know -- never a
    silently partial result.
    """
    action = _FASTPATH_MEM_ACTION_RE.search(html)
    if action is None:
        raise HttpUnexpectedPageError(
            "vlan_port_cfg.html: no <form ACTION=...vlan_port_cfg_rw.html> -- "
            "this is not the FASTPATH VLAN Membership page"
        )
    block = html[action.end() :]
    fields = _fastpath_form_fields(block)
    if "hiddenMem" not in fields:
        raise HttpUnexpectedPageError(
            "vlan_port_cfg.html: form carries no hiddenMem field"
        )
    hidden_mem = fields["hiddenMem"]
    codes = hidden_mem.split(",")
    grid = _fastpath_grid(block)
    port_slots: dict[int, int] = {}
    configured: dict[int, VlanMode] = {}
    for port, (slot, rendered) in sorted(grid.items()):
        if slot >= len(codes):
            raise HttpUnexpectedPageError(
                f"vlan_port_cfg.html: port {port}'s grid slot {slot} is past the "
                f"end of hiddenMem ({len(codes)} codes)"
            )
        mode = _FASTPATH_MEM_TO_MODE.get(codes[slot])
        if mode is None:
            raise HttpUnexpectedPageError(
                f"vlan_port_cfg.html: unknown hiddenMem code {codes[slot]!r} at "
                f"slot {slot} (port {port})"
            )
        if mode is not rendered:
            # The grid image and hiddenMem are two renderings of the SAME
            # (configured) view and always agreed on every live read; a
            # disagreement means the slot mapping is wrong, so refuse rather
            # than write to the wrong port later.
            raise HttpUnexpectedPageError(
                f"vlan_port_cfg.html: port {port} renders as {rendered.value} but "
                f"hiddenMem slot {slot} says {mode.value} -- grid/hiddenMem "
                "mismatch, refusing to trust the slot mapping"
            )
        port_slots[port] = slot
        configured[port] = mode
    selected, vlan_ids = _fastpath_vlan_select(block)
    return FastpathMembership(
        vlan_id=selected,
        vlan_ids=vlan_ids,
        name=unescape(fields.get("vlan_name", "")) or None,
        vlan_type=unescape(fields.get("vlan_type", "")) or None,
        tagged_ports=_fastpath_iface_list(fields.get("hiddenTagged", "")),
        untagged_ports=_fastpath_iface_list(fields.get("hiddenUnTagged", "")),
        hidden_mem=hidden_mem,
        port_slots=port_slots,
        configured=configured,
        fields=fields,
        action=unescape(action.group(1)),
    )


def fastpath_hidden_mem_with(
    page: FastpathMembership, port: int, mode: VlanMode
) -> str:
    """``page.hidden_mem`` with just ``port``'s code replaced by ``mode``.

    Every other slot -- including the LAG pseudo-interfaces the library does not
    model -- is preserved VERBATIM from what the device rendered, so an apply
    cannot silently rewrite an interface the caller never mentioned. (The same
    reasoning as the SNMP writer preserving the device's own PortList width.)
    Raises ``HttpUnexpectedPageError`` if the page never rendered ``port``.
    """
    slot = page.port_slots.get(port)
    if slot is None:
        raise HttpUnexpectedPageError(
            f"vlan_port_cfg.html: port {port} is not on this switch's membership "
            f"grid (it renders ports {sorted(page.port_slots)!r})"
        )
    codes = page.hidden_mem.split(",")
    codes[slot] = _MODE_TO_FASTPATH_MEM[mode]
    return ",".join(codes)


# ---------------------------------------------------------------------------
# FASTPATH "XE"/Cheetah XUI generic form pages (portsConfiguration.html,
# poeInterfaceConfiguration.html, ipConfiguration.html,
# mgmtVlanIpv4Configuration.html ...).
#
# Every one of these pages carries TWO <FORM>s. The first, ``<page>.html/a0``,
# is the applet/redirect form (applet_port/applet_unit/dbgopt) and holds no
# data; the SECOND, ``<page>.html/a1``, is the read+write form. Everything below
# is scoped to that second form so a field name can never be picked up from the
# wrong one. LIVE-CONFIRMED 2026-07-30 on gsm7252ps 10.1.5.22, gsm7228ps
# 10.1.5.11, m4300-24x 10.1.5.13 and m4300-16x 10.1.5.20:49152.
_XUI_FORM_RE = re.compile(r'<FORM\b[^>]*ACTION="([^"]*/a1)"', re.IGNORECASE)
# The repeating rows of a list page. ``p="1.35.520"`` is the row's coordinate
# attribute; the field NAMES use the ``1.35.52.`` prefix (same digits, no
# trailing column index), which is why the prefix is taken from a field name
# rather than from ``p``.
_XUI_ROW_RE = re.compile(r'<TR\s+p="[\d.]+"[^>]*>(.*?)</TR>', re.IGNORECASE | re.DOTALL)
_XUI_ROW_FIELD_RE = re.compile(r"^((?:\d+\.)+)(v_\d+_\d+_\d+)$")
# The trailing "redirection elements" block every XUI form ends with.
_XUI_HIDDEN_NAMES = (
    "submit_flag",
    "submit_target",
    "err_flag",
    "err_msg",
    "clazz_information",
)
# The page's buttons live in their own trailing ``<div id="xuiButtonsDiv">``.
# Scoped to that div ON PURPOSE rather than matched by name shape: the button
# fields are named ``v_2_1_N``/``v_3_1_N`` depending on the page, and on
# gsm7228ps's ipConfiguration.html ``v_2_1_1`` is NOT a button at all -- it is
# the Management VLAN ID data field. A name-shaped guess would have classified a
# real setting as a button and dropped it from every echoed body.
_XUI_BUTTONS_DIV_RE = re.compile(
    r'<div id="xuiButtonsDiv"[^>]*>(.*?)</div>', re.IGNORECASE | re.DOTALL
)
# Page-level fields that are NOT data cells and must ride along on every apply.
# Today that is exactly the per-page ``CSRFToken`` the AV-era M4300-16X issues
# and whose absence it answers with 403; matched by name rather than by "not a
# v_* field" so a future data field cannot be swept in by accident.
_XUI_TOKEN_RE = re.compile(r"^CSRFToken$", re.IGNORECASE)
# The page's list-NAVIGATION rows -- the "Go To Port" bars the firmware emits
# above and below the table, marked ``class=deftestme``. Their ``v_*`` fields
# scope the list (unit / interface-type filter) and a browser submits them on
# every apply; the GSM7252PS PoE page REFUSES a write without one (see
# ``XuiListPage.nav`` and ``forms.xui_row_apply_form``).
#
# Structural, not a name whitelist, and that is measured rather than assumed:
# across every captured XUI list page of all four managed models
# (gsm7252ps/gsm7228ps/m4300-24x/m4300-16x -- ports, PoE, PVID, statistics, MAC
# table, LLDP, VLAN status), the set of page-level ``v_*`` fields is EXACTLY the
# set inside these rows, with nothing left over. The names themselves are not
# portable: the PoE/ports/PVID pages use ``v_1_1_1``/``v_1_1_2``/``v_1_3_1``, the
# statistics pages ``v_1_2_1``/``v_1_2_2``/``v_1_3_1``, and the MAC tables
# ``v_1_1_1``/``v_1_5_*``/``v_1_3_4``.
_XUI_NAV_ROW_RE = re.compile(
    r"<TR\b[^>]*\bclass=[\"']?deftestme[\"']?[^>]*>(.*?)</TR>",
    re.IGNORECASE | re.DOTALL,
)
# A page-level (unprefixed) data field name: ``v_1_1_1``. Deliberately excludes
# the global "apply to all rows" row's ``v_g_1_2_*`` twins -- echoing those back
# is itself refused (live 2026-07-30 on gsm7252ps 10.1.5.22: a PoE apply that
# carried them answered err_flag=1 "Error! Failed to Set 'Timer <br/> Schedule'
# with ''", because the global row's cells render EMPTY and the firmware tries to
# apply them to every port).
_XUI_PAGE_FIELD_RE = re.compile(r"^v_\d+_\d+_\d+$")

#: The blank TEMPLATE ("global") row an ADD fills in: ``v_g_<table>_<tr>_<col>``.
#: The framework's own ``getTableId``/``getTrId`` in ``/scripts/xui_load.js``
#: special-case this xid shape (``xid.indexOf("g_") != -1`` then slice positions
#: 2..3 and 2..5), which is what identifies it as the global-edit row rather
#: than a data row. Deliberately NOT matched by ``_XUI_PAGE_FIELD_RE`` above --
#: a per-row apply must never carry it.
_XUI_TEMPLATE_RE = re.compile(r"^v_g_(\d+)_(\d+)_(\d+)$")


def _xui_form_block(html: str, page: str) -> tuple[str, str]:
    """``(action, inner HTML)`` of the page's write form, or raise."""
    m = _XUI_FORM_RE.search(html)
    if m is None:
        raise HttpUnexpectedPageError(
            f'{page}: no <FORM ACTION="...(/a1)"> -- this is not a FASTPATH XUI '
            "write page (wrong URL, or the session bounced to the login page)"
        )
    return unescape(m.group(1)), html[m.end() :]


def _xui_inputs(block: str) -> tuple[dict[str, str], list[str]]:
    """``({name: value}, [checkbox names])`` for one XUI form block.

    Deliberately NOT ``_fastpath_form_fields``: that one echoes every input
    because the VLAN-membership form must be byte-faithful to the browser. Here
    two kinds must be separated out instead, or an echoed body would say
    something the browser never says:

    * ``DISABLED`` inputs (``v_1_1_1_extn``, and every button) are NOT submitted
      by a browser -- the firmware enables the one clicked button itself.
    * a ``checkbox`` carries no ``value`` attribute, so echoing it as ``""``
      would silently SELECT that row. Row selection is the one thing these
      pages key their writes off, so it is returned separately and only ever
      set deliberately.
    """
    fields: dict[str, str] = {}
    checkboxes: list[str] = []
    for m in _INPUT_RE.finditer(block):
        attrs = _tag_attrs(m.group(1))
        name = attrs.get("name")
        if not name or "disabled" in attrs:
            continue
        if attrs.get("type", "").lower() == "checkbox":
            checkboxes.append(name)
            continue
        fields[name] = attrs.get("value", "")
    for m in _SELECT_RE.finditer(block):
        attrs = _tag_attrs(m.group(1))
        name = attrs.get("name")
        if not name or "disabled" in attrs:
            continue
        options = [_tag_attrs(o.group(1)) for o in _OPTION_RE.finditer(m.group(2))]
        chosen = next((o for o in options if "selected" in o), None)
        if chosen is None and options:
            chosen = options[0]
        fields[name] = chosen.get("value", "") if chosen else ""
    return fields, checkboxes


def _xui_buttons(html: str) -> dict[str, str]:
    """The page's button fields -> their labels (``v_2_1_2`` -> ``APPLY``).

    Kept even though the inputs are rendered ``DISABLED`` (so a browser would
    not submit them), because the firmware's own ``xuiProcessButtonActions``
    calls ``xuiShed(3, ...)`` to ENABLE the clicked button before
    ``form.submit()`` -- so the real POST does carry exactly one of these, with
    the label as its value. The labels are NOT interchangeable between models:
    the same ``v_2_1_3`` reads ``RESET`` on gsm7252ps/gsm7228ps and
    ``Power Cycle Port(s)`` on both M4300s (live 2026-07-30), which is why the
    value is echoed from the page instead of being a constant.
    """
    div = _XUI_BUTTONS_DIV_RE.search(html)
    if div is None:
        return {}
    out: dict[str, str] = {}
    for m in _INPUT_RE.finditer(div.group(1)):
        attrs = _tag_attrs(m.group(1))
        name = attrs.get("name")
        if name:
            out[name] = unescape(attrs.get("value", ""))
    return out


def parse_xui_list_page(html: str, *, page: str = "XUI list page") -> XuiListPage:
    """A FASTPATH XUI table page -> its write form + one ``XuiRow`` per row.

    Raises ``HttpUnexpectedPageError`` when the write form is missing. An EMPTY
    row tuple is NOT an error and is not swallowed either -- it is a real,
    meaningful answer that the caller interprets: the M4300-24X genuinely has no
    PoE, and its ``/v1/poeInterfaceConfiguration.html`` proves it with an HTTP
    **200** of 28152 bytes carrying the correct ``<TITLE>NETGEAR -  PoE Port
    Configuration</TITLE>``, the full button set and ZERO ``<TR p="...">`` rows
    (live 2026-07-30 on 10.1.5.13). A 404 would have been a missing page; this
    is a present page with no PSE ports.
    """
    action, block = _xui_form_block(html, page)
    rows: list[XuiRow] = []
    for m in _XUI_ROW_RE.finditer(block):
        row_fields, checkboxes = _xui_inputs(m.group(1))
        prefix = next(
            (
                match.group(1)
                for name in row_fields
                if (match := _XUI_ROW_FIELD_RE.match(name)) is not None
            ),
            None,
        )
        if prefix is None:
            continue  # a spacer/label row, not a data row
        rows.append(
            XuiRow(
                prefix=prefix,
                checkbox=next((c for c in checkboxes if c.startswith(prefix)), None),
                fields={k: unescape(v) for k, v in row_fields.items()},
            )
        )
    form_fields, _cbs = _xui_inputs(_XUI_ROW_RE.sub("", block))
    nav: dict[str, str] = {}
    for m in _XUI_NAV_ROW_RE.finditer(block):
        row_fields, _ = _xui_inputs(m.group(1))
        nav.update(
            {
                n: unescape(v)
                for n, v in row_fields.items()
                if _XUI_PAGE_FIELD_RE.match(n)
            }
        )
    return XuiListPage(
        action=action,
        hidden={n: form_fields[n] for n in _XUI_HIDDEN_NAMES if n in form_fields},
        buttons=_xui_buttons(block),
        rows=tuple(rows),
        tokens={
            n: unescape(v) for n, v in form_fields.items() if _XUI_TOKEN_RE.match(n)
        },
        nav=nav,
        # The blank ADD row. It carries no <unit>.<row>.<count>. prefix, so it
        # lands in form_fields rather than in rows -- which is where it went
        # unnoticed: it is named ``v_g_2_1_1``, not ``g_2_1_1``, and a search
        # for the latter finds nothing and reads as "this page has no template
        # row" (it cost two rounds of "needs a browser capture" to find).
        template={
            n: unescape(v) for n, v in form_fields.items() if _XUI_TEMPLATE_RE.match(n)
        },
    )


def parse_xui_form_page(html: str, *, page: str = "XUI page") -> XuiFormPage:
    """A FASTPATH XUI detail page -> its write form's flat field map."""
    action, block = _xui_form_block(html, page)
    fields, _cbs = _xui_inputs(block)
    hidden = {n: fields.pop(n) for n in _XUI_HIDDEN_NAMES if n in fields}
    return XuiFormPage(
        action=action,
        hidden=hidden,
        buttons=_xui_buttons(block),
        fields={k: unescape(v) for k, v in fields.items()},
    )


# The addressing-method values these pages use, mapped to the shared IpMode.
# ``None`` on the gsm72xx ipConfiguration page is FASTPATH's name for "no
# dynamic protocol", i.e. a manually-configured static address (its enum is
# ``["None","Bootp","DHCP"]``); ``Disable``/``Enable`` are the M4300
# mgmtVlanIpv4Configuration radio, whose own metadata spells them out as
# ``xew_1_5_3_Disable = "Manual"`` / ``xew_1_5_3_Enable = "DHCP"``. Anything
# else is left UNKNOWN rather than guessed at.
_XUI_IP_MODE = {
    "none": IpMode.STATIC,
    "manual": IpMode.STATIC,
    "disable": IpMode.STATIC,
    "dhcp": IpMode.DHCP,
    "enable": IpMode.DHCP,
    "bootp": IpMode.DHCP,
}


def parse_xui_mgmt_ip(
    html: str,
    *,
    address_field: str,
    netmask_field: str,
    gateway_field: str,
    mode_field: str,
    page: str = "XUI management-IP page",
) -> MgmtIpConfig:
    """A FASTPATH XUI management-IP page -> ``MgmtIpConfig`` (without base MAC).

    Field names are passed in rather than assumed: the two Cheetah families put
    the same four values under different names, and one of those names means
    different things on two switches of the SAME family -- see
    ``endpoints.XuiMgmtIpFields``. ``base_mac`` is left ``None`` here because
    neither family's mgmt page carries the switch's BASE MAC (gsm7228ps's page
    has no MAC row at all; the M4300's ``v_4_4_1`` is the management
    interface's MAC, one off from the base MAC SNMP reports) -- the reader
    merges it from ``sysinfo_path``.
    """
    fields, _cbs = _xui_inputs(_xui_form_block(html, page)[1])
    missing = [
        f for f in (address_field, netmask_field, gateway_field) if f not in fields
    ]
    if missing:
        raise HttpUnexpectedPageError(
            f"{page}: no {missing!r} field(s) -- wrong management-IP page for "
            "this model?"
        )
    return MgmtIpConfig(
        mode=_XUI_IP_MODE.get(
            unescape(fields.get(mode_field, "")).strip().lower(), IpMode.UNKNOWN
        ),
        address=unescape(fields[address_field]).strip() or None,
        netmask=unescape(fields[netmask_field]).strip() or None,
        gateway=unescape(fields[gateway_field]).strip() or None,
        base_mac=None,
    )


# GS110EMX port_settings.html rows: each ``<tr class="portID">`` carries its own
# hidden PORT_NO/PHYSICAL_MODE/FLOW_CONTROL_MODE inputs, which the page's own
# ``sendPortStatusForm()`` reads back before POSTing. Real hardware never closes
# these rows with ``</tr>`` -- see _OPEN_ROW_RE, the same quirk the status
# parser handles.
_EMX_PORT_ROW_RE = re.compile(
    r'<tr class="portID">(.*?)(?=<tr|</table>)', re.DOTALL | re.IGNORECASE
)
_EMX_HIDDEN_RE = re.compile(
    r'<input[^>]*name="(\w+)"[^>]*value="([^"]*)"', re.IGNORECASE
)


def parse_gs110emx_port_form_fields(html: str) -> dict[int, dict[str, str]]:
    """``{port: {field: value}}`` from ``port_settings.html``'s per-port rows.

    Used to echo a port's CURRENT ``FLOW_CONTROL_MODE`` back on an admin-mode
    apply, exactly as the page's JS does -- inventing a value there would
    silently rewrite the port's flow control as a side effect of enabling it.
    """
    out: dict[int, dict[str, str]] = {}
    for m in _EMX_PORT_ROW_RE.finditer(html):
        fields = dict(_EMX_HIDDEN_RE.findall(m.group(1)))
        port = _int(fields.get("PORT_NO", ""))
        if port is not None:
            out[port] = fields
    if not out:
        raise HttpUnexpectedPageError(
            'port_settings.html: no <tr class="portID"> rows with a PORT_NO'
        )
    return out


def parse_reboot_ok(html: str) -> bool:
    """A reboot response that does not contain an error banner."""
    return "error" not in html.lower()


def _labeled_cell(html: str, label: str) -> str | None:
    """GS110EMX sysInfo.html's ``<td>Label</td><td>value</td>`` row shape."""
    m = re.search(rf"<td[^>]*>{re.escape(label)}</td>\s*<td[^>]*>([^<]*)</td>", html)
    return m.group(1).strip() if m else None


def _named_input_value(html: str, name: str) -> str | None:
    """sysInfo.html's ``<input name="NAME" ... value="...">`` fields."""
    m = re.search(
        rf'name=["\']{re.escape(name)}["\'][^>]*value=["\']([^"\']*)["\']', html
    )
    return m.group(1) if m else None


def parse_sysinfo(html: str) -> HttpSysInfo:
    """GS110EMX ``sysInfo.html`` -> device identity + mgmt-IP config.

    GROUNDED in ``gs110emx_sysinfo.html`` (a real capture) -- see
    ``HttpSysInfo`` for field provenance, including the ``ip_mode``
    ``data-select-value`` inference. Raises ``HttpUnexpectedPageError``
    naming whichever field(s) are missing rather than fabricating a partial
    result -- this page is never legitimately missing any of these on a real
    switch.
    """
    fields = {
        "Product Name": _labeled_cell(html, "Product Name"),
        "Serial Number": _labeled_cell(html, "Serial Number"),
        "MAC Address": _labeled_cell(html, "MAC Address"),
        "Firmware Version": _labeled_cell(html, "Firmware Version"),
        "switch_name": _named_input_value(html, "switch_name"),
        "IP_ADDRESS": _named_input_value(html, "IP_ADDRESS"),
        "SUBNET_MASK": _named_input_value(html, "SUBNET_MASK"),
        "GATEWAY_ADDRESS": _named_input_value(html, "GATEWAY_ADDRESS"),
    }
    dhcp_select = re.search(r'<tr data-select-value="(\d+)"', html)
    missing = [name for name, val in fields.items() if val is None]
    if dhcp_select is None:
        missing.append("DHCP data-select-value")
    if missing:
        raise HttpUnexpectedPageError(
            f"sysInfo.html: missing expected field(s): {', '.join(missing)}"
        )
    assert dhcp_select is not None  # for mypy; guarded by `missing` above
    ip_mode = IpMode.DHCP if dhcp_select.group(1) == "1" else IpMode.STATIC
    return HttpSysInfo(
        product_name=fields["Product Name"] or "",
        switch_name=fields["switch_name"] or "",
        serial_number=fields["Serial Number"] or "",
        mac_address=fields["MAC Address"] or "",
        firmware_version=fields["Firmware Version"] or "",
        ip_mode=ip_mode,
        ip_address=fields["IP_ADDRESS"] or "",
        subnet_mask=fields["SUBNET_MASK"] or "",
        gateway_address=fields["GATEWAY_ADDRESS"] or "",
    )


# --- gs728tpp GoAhead ``wcd`` XML API (GOAHEAD_XML dialect) -----------------
#
# Every read is a ``GET <sess>/wcd?{file=/path/X.xml}{Object}..`` whose body is
# a template of ``BIND=`` placeholders followed by a trailing
# ``<DeviceConfiguration>`` data block of ``<Object type="section">`` elements
# (scalars, or repeated ``<Interface>``/``<Entry>``/``<VLAN>`` rows). GROUNDED
# in real captures of the live switch 10.2.5.10 (tmp/gs728tpp_ground_truth.json).
# Only the data block is parsed -- as XML, via ElementTree; the surrounding
# template markup is NOT even well-formed XML (unclosed <script>/<link>, a
# ``class=xui"`` typo), so it is sliced off first rather than parsed.
#
# Enum wire codes, read from the pages' own <ENUM> blocks / observed values:
#   adminState/adminEnable 1=enabled 2=disabled;  linkState 1=up 2=down
#   taggingMode 1=untagged 2=tagged
#   PoE detectionStatus 1=Disabled 2=Searching 3=DeliveringPower 4=Fault
#                       5=Test 6=OtherFault
#   Diagnostics *Status 1=OK 2=Fail 5=N/A(absent slot)
_GOAHEAD_PORT_RE = re.compile(r"^g(\d+)$")
_GOAHEAD_POE_DETECT = {
    "1": PoEDetect.DISABLED,
    "2": PoEDetect.SEARCHING,
    "3": PoEDetect.DELIVERING,
    "4": PoEDetect.FAULT,
    "6": PoEDetect.FAULT,  # OtherFault -- still a fault
}
# Diagnostics-status codes that mean the slot is ABSENT (unpopulated fan bay,
# no redundant PSU): reported as nothing, not as a failed sensor.
_GOAHEAD_ABSENT_STATUS = {"", "5"}


def _goahead_data_block(body: str) -> ElementTree.Element:
    """The parsed ``<DeviceConfiguration>`` element of a wcd response.

    The surrounding template is deliberately NOT parsed (it is not well-formed
    XML); this slices out just the data block, which IS clean XML. Raises
    ``HttpUnexpectedPageError`` if the block is absent (the wrong page came
    back) or malformed.

    XXE/entity-expansion hardening without a new dependency (``defusedxml`` is
    not a project dependency and the stdlib ``ElementTree`` is mandated):
    slicing to ``<DeviceConfiguration>`` already excludes the XML prolog where a
    DTD would live, and any ``<!DOCTYPE``/``<!ENTITY`` appearing INSIDE the data
    block is rejected outright below -- so a billion-laughs/XXE payload cannot be
    parsed. (expat resolves no external entities by default, so undefined entity
    refs simply raise ``ParseError``, which is caught.)"""
    start = body.find("<DeviceConfiguration>")
    end = body.find("</DeviceConfiguration>")
    if start < 0 or end < 0:
        raise HttpUnexpectedPageError(
            "wcd response: no <DeviceConfiguration> data block found"
        )
    block = body[start : end + len("</DeviceConfiguration>")]
    if "<!DOCTYPE" in block or "<!ENTITY" in block:
        raise HttpUnexpectedPageError(
            "wcd response: DTD/entity declaration in data block rejected"
        )
    try:
        return ElementTree.fromstring(block)
    except ElementTree.ParseError as exc:
        raise HttpUnexpectedPageError(
            f"wcd response: <DeviceConfiguration> is not valid XML: {exc}"
        ) from exc


def _goahead_section(body: str, name: str) -> ElementTree.Element:
    """The ``<name type="section">`` element of a wcd data block, or raise."""
    sec = _goahead_data_block(body).find(name)
    if sec is None:
        raise HttpUnexpectedPageError(
            f"wcd response: no <{name}> section (wrong page?)"
        )
    return sec


def _goahead_port_num(name: str) -> int | None:
    """``"g24"`` -> 24. A LAG (``"LAG3"``) or any non-physical interface name
    yields ``None`` so callers skip it rather than mis-attributing it."""
    m = _GOAHEAD_PORT_RE.match(name.strip())
    return int(m.group(1)) if m else None


def _gtext(el: ElementTree.Element, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


#: ``duplexOperMode`` -> full_duplex, DECODED AGAINST SNMP rather than guessed.
#: Measured on the live GS728TPP (10.2.5.10, firmware 6.0.1.30, 2026-08-03) by
#: reading this page and dot3StatsDuplexStatus for all 28 ports at once:
#: every link-UP port reads 2 here and 3 (fullDuplex) there, every link-DOWN
#: port reads 4 here and 1 (unknown) there.
#:
#: 4 is therefore mapped to None, not False. Nothing is claimed about codes 1
#: and 3: that fleet had no half-duplex link to observe, and inventing the rest
#: of an enum from one observation is how a plausible-but-wrong mapping gets in.
#: An unmapped code yields None, which is the honest answer for "not known".
#:
#: Note this is NOT the same enum as ``duplexAdminMode``, where the page's own
#: JS uses 2=half / 3=full (see protocols/http/goahead.py).
_GOAHEAD_DUPLEX_OPER = {"2": True}

#: ``flowControlOperType`` -> flow_control. Measured in the same read: every
#: port reads 2 here while dot3PauseOperMode reads 1 (disabled), so 2 is
#: disabled -- consistent with this UI's usual 1=enabled/2=disabled pairing
#: (``adminState``, ``linkState``). Every port on that switch had flow control
#: off, so "1 means enabled" is inference from the UI's convention rather than
#: observation, and any other code stays None.
_GOAHEAD_FLOW_CONTROL = {"1": True, "2": False}


def _goahead_speed_config(entry: ElementTree.Element) -> PortSpeed | None:
    """The CONFIGURED speed of one ``Standard802_3List`` Entry.

    Decoded exactly as the page's own JS decodes it for display::

        if (field.autoNegotiationAdminEnabled == "1") str = "Auto";
        else str = field.speedAdmin + "M" + (duplexAdminMode=="3" ? " Full"
                                                                 : " Half");

    ``autoNegotiationAdminEnabled`` is authoritative and ``speedAdmin`` is
    IGNORED while it is 1 -- which is not a detail one could skip. In the live
    capture every auto-negotiating port carries ``speedAdmin`` 1000 alongside
    ``autoNegotiationAdminEnabled`` 1, so decoding on the rate alone would
    report the whole switch as forced to 1000.
    """
    autoneg = _gtext(entry, "autoNegotiationAdminEnabled")
    if autoneg == "1":
        return PortSpeed(autonegotiate=True)
    if autoneg != "2":
        return None  # neither code the page knows: honestly unknown
    rate = _int(_gtext(entry, "speedAdmin"))
    duplex = _gtext(entry, "duplexAdminMode")
    if rate is None or duplex not in {"2", "3"}:
        return None
    return PortSpeed(autonegotiate=False, speed_mbps=rate, full_duplex=duplex == "3")


def parse_goahead_ports(body: str) -> list[PortStatus]:
    """GS728TPP ``Standard802_3List`` -> per-port status.

    Only physical ``g<n>`` ports are returned; the page also lists LAG
    aggregations (``LAG1``..), which are not ports. ``speed_mbps`` is the
    negotiated ``speedOper`` while the link is up, and honestly ``None`` on a
    down port (whose ``speedOper`` still reports the configured rate).

    ``duplexOperMode`` and ``flowControlOperType`` are decoded against SNMP
    rather than against a guess -- see ``_GOAHEAD_DUPLEX_OPER`` and
    ``_GOAHEAD_FLOW_CONTROL``."""
    sec = _goahead_section(body, "Standard802_3List")
    out: list[PortStatus] = []
    for e in sec.findall("Entry"):
        port = _goahead_port_num(_gtext(e, "interfaceName"))
        if port is None:
            continue  # a LAG/aggregation row, not a physical port
        link_up = _gtext(e, "linkState") == "1"
        out.append(
            PortStatus(
                port=port,
                name=_gtext(e, "interfaceName") or None,
                admin_enabled=_gtext(e, "adminState") == "1",
                link_up=link_up,
                speed_mbps=_int(_gtext(e, "speedOper")) if link_up else None,
                description=_gtext(e, "interfaceDescription") or None,
                full_duplex=_GOAHEAD_DUPLEX_OPER.get(_gtext(e, "duplexOperMode")),
                flow_control=_GOAHEAD_FLOW_CONTROL.get(
                    _gtext(e, "flowControlOperType")
                ),
                speed_config=_goahead_speed_config(e),
            )
        )
    if not out:
        raise HttpUnexpectedPageError(
            "Standard802_3List: no physical-port Entry rows found"
        )
    return out


def parse_goahead_pvids(body: str) -> list[tuple[int, int]]:
    """GS728TPP ``VLANInterfaceList`` -> ``(port, pvid)`` pairs (physical only)."""
    sec = _goahead_section(body, "VLANInterfaceList")
    out: list[tuple[int, int]] = []
    for iface in sec.findall("Interface"):
        port = _goahead_port_num(_gtext(iface, "interfaceName"))
        pvid = _int(_gtext(iface, "PVID"))
        if port is None or pvid is None:
            continue
        out.append((port, pvid))
    if not out:
        raise HttpUnexpectedPageError(
            "VLANInterfaceList: no (port, pvid) pair could be parsed"
        )
    return out


def parse_goahead_vlan_names(body: str) -> dict[int, str | None]:
    """GS728TPP ``VLANList`` -> ``{vlan_id: name or None}``."""
    sec = _goahead_section(body, "VLANList")
    names: dict[int, str | None] = {}
    for v in sec.findall("VLAN"):
        vid = _int(_gtext(v, "VLANID"))
        if vid is None:
            continue
        names[vid] = _gtext(v, "VLANName") or None
    if not names:
        raise HttpUnexpectedPageError("VLANList: no VLAN row could be parsed")
    return names


def parse_goahead_port_vlan_membership(
    body: str,
) -> dict[int, tuple[frozenset[int], frozenset[int]]]:
    """GS728TPP ``VLANInterfaceList`` -> ``{vlan_id: (tagged, untagged)}``.

    Built from each physical port's inline ``JoinVLANList`` (``taggingMode``
    1=untagged, 2=tagged), which carries the complete per-port membership --
    so no separate per-VLAN membership request is needed."""
    sec = _goahead_section(body, "VLANInterfaceList")
    tagged: dict[int, set[int]] = {}
    untagged: dict[int, set[int]] = {}
    for iface in sec.findall("Interface"):
        port = _goahead_port_num(_gtext(iface, "interfaceName"))
        jvl = iface.find("JoinVLANList")
        if port is None or jvl is None:
            continue
        for ve in jvl.findall("VLANEntry"):
            vid = _int(_gtext(ve, "VLANID"))
            if vid is None:
                continue
            bucket = untagged if _gtext(ve, "taggingMode") == "1" else tagged
            bucket.setdefault(vid, set()).add(port)
    return {
        vid: (frozenset(tagged.get(vid, ())), frozenset(untagged.get(vid, ())))
        for vid in set(tagged) | set(untagged)
    }


def parse_goahead_vlans(vlans_body: str, membership_body: str) -> list[VLANInfo]:
    """GS728TPP VLANs: ``VLANList`` names + per-port ``VLANInterfaceList``
    membership -> full ``VLANInfo`` list (member/tagged/untagged sets)."""
    names = parse_goahead_vlan_names(vlans_body)
    membership = parse_goahead_port_vlan_membership(membership_body)
    out: list[VLANInfo] = []
    for vid in sorted(set(names) | set(membership)):
        tagged, untagged = membership.get(vid, (frozenset(), frozenset()))
        out.append(
            VLANInfo(
                vlan_id=vid,
                name=names.get(vid),
                member_ports=tagged | untagged,
                tagged_ports=tagged,
                untagged_ports=untagged,
            )
        )
    return out


def parse_goahead_macs(body: str) -> list[MacEntry]:
    """GS728TPP ``ForwardingTable`` -> the dynamic MAC/FDB table.

    Only entries learned on a physical ``g<n>`` port are returned; a LAG
    aggregation carries no port number and is skipped rather than
    mis-attributed. An empty table is legitimate (a freshly-booted switch)."""
    sec = _goahead_section(body, "ForwardingTable")
    out: list[MacEntry] = []
    for e in sec.findall("Entry"):
        port = _goahead_port_num(_gtext(e, "interfaceName"))
        if port is None:
            continue
        mac = _gtext(e, "MACAddress").upper()
        if not _MAC_TEXT_RE.fullmatch(mac):
            continue
        out.append(MacEntry(mac=mac, port=port, vlan_id=_int(_gtext(e, "VLANID"))))
    return out


def parse_goahead_poe(body: str) -> list[PoEStatus]:
    """GS728TPP ``PoEPSEInterfaceList`` -> per-port PoE status.

    ``power_mw`` is ``outputPower`` (the live draw, mW) and ``detect`` maps the
    ``detectionStatus`` wire code; the ``Test`` code (5) has no RFC3621 detect
    equivalent and reads UNKNOWN rather than being invented."""
    sec = _goahead_section(body, "PoEPSEInterfaceList")
    out: list[PoEStatus] = []
    for iface in sec.findall("Interface"):
        port = _goahead_port_num(_gtext(iface, "interfaceName"))
        if port is None:
            continue
        out.append(
            PoEStatus(
                port=port,
                admin_enabled=_gtext(iface, "adminEnable") == "1",
                detect=_GOAHEAD_POE_DETECT.get(
                    _gtext(iface, "detectionStatus"), PoEDetect.UNKNOWN
                ),
                power_mw=_int(_gtext(iface, "outputPower")),
            )
        )
    if not out:
        raise HttpUnexpectedPageError(
            "PoEPSEInterfaceList: no PoE port row could be parsed"
        )
    return out


_MAC_COLON_HEX_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def _canon_lldp_id(text: str) -> str:
    """Canonicalize an LLDP chassis/port-id to match the SNMP formatting.

    A MAC-address subtype id (colon-hex, six octets) is upper-cased -- the same
    canonical form the SNMP parser emits for a raw-MAC lldpRemChassisId /
    lldpRemPortId (see ``snmp.parse._format_mac_octetstring``) -- so the two
    backends' values are LITERALLY equal, not merely case-insensitively so. Any
    other id (a plain interface-name string) is returned unchanged, matching the
    SNMP side's text passthrough."""
    return text.upper() if _MAC_COLON_HEX_RE.match(text) else text


def parse_goahead_lldp(body: str) -> list[LLDPNeighbor]:
    """GS728TPP ``LLDPMEDNeighborList`` -> LLDP neighbours.

    An empty neighbour list is LEGITIMATE (a switch with no neighbours), so
    this returns ``[]`` rather than raising; ``_goahead_section`` still raises
    if the whole section is absent (wrong page). Chassis/port-id MACs are
    canonicalized to upper-case (``_canon_lldp_id``) so they equal the SNMP
    reader's formatting exactly."""
    sec = _goahead_section(body, "LLDPMEDNeighborList")
    out: list[LLDPNeighbor] = []
    for ne in sec.findall("NeighborEntry"):
        port = _goahead_port_num(_gtext(ne, "interfaceName"))
        if port is None:
            continue
        out.append(
            LLDPNeighbor(
                local_port=port,
                remote_sys_name=_gtext(ne, "systemName") or None,
                remote_port_desc=_gtext(ne, "portDescription") or None,
                remote_chassis_id=_canon_lldp_id(_gtext(ne, "deviceID")) or None,
                remote_port_id=_canon_lldp_id(_gtext(ne, "advertisedPortID")) or None,
            )
        )
    return out


def _goahead_state_sensor(
    entry: ElementTree.Element, tag: str, name: str, kind: str
) -> list[Sensor]:
    """One ``unit="state"`` health-flag Sensor for a Diagnostics status field,
    or ``[]`` for an absent slot (status 5/blank -- absence is not failure)."""
    raw = _gtext(entry, tag)
    if raw in _GOAHEAD_ABSENT_STATUS:
        return []
    return [
        Sensor(name=name, kind=kind, value=1.0 if raw == "1" else 0.0, unit="state")
    ]


def parse_goahead_sensors(body: str) -> list[Sensor]:
    """GS728TPP ``DiagnosticsUnitList`` -> box sensors.

    Fans and PSUs report a health STATUS code (1=OK), not RPM/watts, so they
    are emitted as ``unit="state"`` flags (1.0 healthy, 0.0 any other reported
    state); an absent slot (status 5) is skipped. ``tempSensorValue`` is emitted
    as a numeric temperature only when it is a positive reading -- a 0 with
    ``tempSensorStatus`` 2 (this unit's captured value) is not a real reading
    and is not fabricated as 0 C. SNMP remains the source of real fan RPM / PSU
    watts on this model."""
    sec = _goahead_section(body, "DiagnosticsUnitList")
    entry = sec.find("Entry")
    if entry is None:
        return []
    out: list[Sensor] = []
    for n in range(1, 6):
        out += _goahead_state_sensor(entry, f"fan{n}Status", f"Fan{n}", "fan")
    out += _goahead_state_sensor(entry, "mainPSStatus", "Main PS", "power")
    out += _goahead_state_sensor(entry, "redundantPSStatus", "Redundant PS", "power")
    temp = _int(_gtext(entry, "tempSensorValue"))
    if temp is not None and temp > 0:
        out.append(
            Sensor(name="Temperature", kind="temperature", value=float(temp), unit="C")
        )
    return out


def parse_goahead_base_mac(body: str) -> str | None:
    """GS728TPP ``SystemInfo`` (``DeviceBasicInfo``) -> the switch's base MAC.

    ``DeviceBasicInfo/MacAddre`` carries the switch's own base MAC (e.g.
    ``"b0:39:56:77:54:29"``). Uppercased to match the SNMP
    dot1dBaseBridgeAddress / NSDP identity-MAC formatting (see
    ``models.MgmtIpConfig.base_mac``), so the HTTP and SNMP mgmt-IP reads agree
    field-for-field. The IPConf page has no MAC row, so ``get_mgmt_ip`` reads
    this from the separate SystemInfo page. Absent -> ``None`` (never
    fabricated)."""
    mac = _gtext(_goahead_section(body, "DeviceBasicInfo"), "MacAddre")
    return mac.upper() or None


def parse_goahead_hostname(body: str) -> str:
    """GS728TPP ``SystemInfo`` (``DeviceBasicInfo``) -> the switch's host name.

    ``DeviceBasicInfo/deviceName`` is the host name, not merely a cosmetic
    label: MEASURED on the live switch (10.2.5.10, firmware 6.0.1.30,
    2026-08-03) it reads ``sw-netgear-gs728tpp``, byte-for-byte what SNMP
    reports through sysName.

    Returns the raw value including ``""``. An empty name is a REAL state on a
    switch that has never been named, so it must not be turned into None, which
    the caller would read as "this backend cannot tell you".
    """
    return _gtext(_goahead_section(body, "DeviceBasicInfo"), "deviceName")


def parse_goahead_mgmt_ip(body: str) -> MgmtIpConfig:
    """GS728TPP ``IPConf_master.xml`` -> management IP + gateway.

    ``IPv4InterfaceList/ifEntry`` carries the address/netmask (on the mgmt VLAN
    interface) and ``IPv4GatewayList/GWEntry`` the default gateway. The page
    carries no DHCP/static indicator and no base MAC (that is on the SystemInfo
    page), so ``mode`` is UNKNOWN and ``base_mac`` is None rather than guessed."""
    root = _goahead_data_block(body)
    addr = netmask = gateway = None
    iface_list = root.find("IPv4InterfaceList")
    if iface_list is not None:
        ent = iface_list.find("ifEntry")
        if ent is not None:
            addr = _gtext(ent, "IPAddr") or None
            netmask = _gtext(ent, "subnetMask") or None
    gw_list = root.find("IPv4GatewayList")
    if gw_list is not None:
        ge = gw_list.find("GWEntry")
        if ge is not None:
            gateway = _gtext(ge, "IPAddr") or None
    if addr is None and gateway is None:
        raise HttpUnexpectedPageError(
            "IPConf: no IPv4 interface address or gateway found"
        )
    return MgmtIpConfig(
        mode=IpMode.UNKNOWN,
        address=addr,
        netmask=netmask,
        gateway=gateway,
        base_mac=None,
    )
