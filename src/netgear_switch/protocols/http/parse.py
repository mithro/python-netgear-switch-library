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

from ...errors import HttpUnexpectedPageError
from ...models import IpMode, PoEDetect, PoEStatus, PortStats, PortStatus, VlanMode
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
