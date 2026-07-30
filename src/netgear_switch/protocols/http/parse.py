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
from html import unescape

from ...errors import HttpUnexpectedPageError
from ...models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStats,
    PortStatus,
    Sensor,
    VLANInfo,
    VlanMode,
)
from .types import HttpSysInfo

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


def parse_xe_vlans(html: str) -> list[VLANInfo]:
    """GSM7252PS ``vlanStatus.html`` -> VLANs with their egress member ports.

    The Member Ports cell uses the same FASTPATH egress-list syntax the M4300
    does (``"1/0/46 - 1/0/47, 1/0/49, lag 1, lag 2"``), so ``_expand_port_list``
    is shared -- including its refusal to expand ``lag N`` into physical ports.
    A VLAN with an EMPTY member cell is real (VLANs 7/21/89 on the captured
    switch have no members, which that device's SNMP capture confirms), so an
    empty set is reported rather than treated as a parse failure.

    Like the M4300's, this page does NOT distinguish tagged from untagged, so
    ``tagged_ports``/``untagged_ports`` stay EMPTY rather than guessed.
    """
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
                member_ports=_expand_port_list(r[_XE_VLAN_MEMBERS]),
                tagged_ports=frozenset(),
                untagged_ports=frozenset(),
            )
        )
    if not out:
        raise HttpUnexpectedPageError("vlanStatus.html: no XE VLAN row could be parsed")
    return out


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


def parse_goahead_ports(body: str) -> list[PortStatus]:
    """GS728TPP ``Standard802_3List`` -> per-port status.

    Only physical ``g<n>`` ports are returned; the page also lists LAG
    aggregations (``LAG1``..), which are not ports. ``speed_mbps`` is the
    negotiated ``speedOper`` while the link is up, and honestly ``None`` on a
    down port (whose ``speedOper`` still reports the configured rate)."""
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
