"""Pure (I/O-free) parsers mapping web-UI HTML -> shared ``models`` types.

Regex-based (no ``lxml``/``bs4`` dependency), matching the documented HTML
shape the virtual renderer (``virtual/web.py``, Slice 6 Task 10) emits and
that the captured/synthetic fixtures under ``tests/fixtures/http/`` mirror.
Real-device column offsets are UNVERIFIED-pending-capture; confirm against
captured HTML before production use (each such fixture is headed
``UNVERIFIED-pending-capture``).

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
from html import unescape

from ...errors import HttpUnexpectedPageError
from ...models import (
    IpMode,
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
    the port description (``None`` when blank, as it is on a factory switch);
    ``admin_enabled`` is reported ``True`` -- this status page shows link state,
    not administrative state, exactly like the NSDP ``PORT_STATUS`` backend
    (``nsdp_read._ports``), so the two agree field-for-field on the data both
    protocols actually expose (port/link_up/speed_mbps).
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
                admin_enabled=True,
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
    column layout -- link at [2] and speed at [4] -- differs from BOTH gs305ep's
    dashboard.cgi and gs110emx's port_settings.html, hence its own parser.
    ``admin_enabled`` is ``True`` (this page reports link, not admin, state) and
    ``name`` is ``None`` (no description column), matching the NSDP backend so
    the two agree on what both protocols expose."""
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
                admin_enabled=True,
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


_M4300_IFACE_RE = re.compile(r"(\d+)/(\d+)/(\d+)")


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
        ends = _M4300_IFACE_RE.findall(part)
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
        r for r in parse_cheetah_rows(html)
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
    """M4300 ``basicAddressTable.html`` -> the MAC/FDB table."""
    rows = [
        r for r in parse_cheetah_rows(html)
        if "SwitchingmacAddrGroup_MacAddress" in r
    ]
    out: list[MacEntry] = []
    for r in rows:
        mac = r.get("SwitchingmacAddrGroup_MacAddress", "").strip().upper()
        if not mac:
            continue
        name = r.get("SwitchingmacAddrGroup_Intf", "")
        port = _int(name.rsplit("/", 1)[-1]) if "/" in name else _int(name)
        out.append(
            MacEntry(
                mac=mac,
                port=port or 0,
                vlan_id=_cheetah_int(r, "SwitchingmacAddrGroup_vlanIndex"),
            )
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
    mac_m = re.search(
        r"System MAC Address</td>\s*<td[^>]*>\s*([0-9A-Fa-f:]{17})", html
    )
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
    Its FAN block is deliberately NOT returned: it reports a non-numeric state
    (``Fan-1 OK``) and ``Sensor.value`` is a required ``float`` -- emitting a
    fan would mean inventing a number. The SNMP backend, which reads real fan
    RPM, is the honest source for fan sensors on this model.
    """
    return [
        Sensor(
            name=label.strip(), kind="temperature", value=float(celsius), unit="C"
        )
        for label, celsius in re.findall(
            r"<td[^>]*>([A-Za-z ]{2,28})</td>\s*<td[^>]*>\s*(\d+)\s*&#8451;", html
        )
    ]


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
    m = re.search(
        rf'<td[^>]*>{re.escape(label)}</td>\s*<td[^>]*>([^<]*)</td>', html
    )
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
