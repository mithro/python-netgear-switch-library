"""Byte-faithful GS110EMX web-UI page templates (Gambit token session).

The literal HTML in ``web_gs110emx_templates.py`` is the REAL captured
content from a physical GS110EMX (``tests/fixtures/http/gs110emx_*.html``)
with only the dynamic values swapped for marker placeholders -- everything
else (JS boilerplate, attribute names, and critically the malformed
*never-closed* ``<tr class="portID">`` rows on interface_stats.html -- see
``protocols/http/parse.py``'s ``_OPEN_ROW_RE``) is copied byte-for-byte from
the capture, so the mock is byte-equivalent to real hardware whenever seeded
with the same values. Substitution is plain ``str.replace`` (not
``.format()``/f-strings) because the captured pages' inline JavaScript is
full of literal ``{``/``}`` characters that would need escaping.

One known, deliberate byte-level deviation: the real capture's LAST
``portID`` row (port 10) is followed by 2 fewer whitespace characters before
``</table>`` than every other row -- a capture idiosyncrasy of the real
device, not a parsing-relevant difference. ``render_interface_stats`` renders
every row (including the last) with the same trailing whitespace for
simplicity, so a byte-diff against the original 10-port capture differs by
exactly those 2 bytes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from . import web_gs110emx_templates as _t

if TYPE_CHECKING:
    from .state import VirtualSwitchState


def render_login(rand: str) -> str:
    """GET / login page -- byte-identical to gs110emx_login.html but for the
    ``rand`` nonce."""
    return _t.LOGIN.replace("__RAND__", rand)


def render_redirect(token: str) -> str:
    """POST /redirect.html login response -- byte-identical to
    gs110emx_redirect.html but for the Gambit token. ``token=""`` (a
    rejected login) renders a Gambit field with an empty value, which
    ``parse.parse_gambit_token`` reads back as falsy."""
    return _t.REDIRECT.replace("__GAMBIT__", token)


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def render_sysinfo(state: VirtualSwitchState, token: str) -> str:
    """GET /iss/specific/sysInfo.html?Gambit=<token> -- byte-identical to
    gs110emx_sysinfo.html but for the state-driven device identity / mgmt-IP
    fields. ``dhcp_select`` mirrors the captured page's ``data-select-value``
    attribute (0=static/Disable, 1=DHCP/Enable) -- see
    ``protocols/http/parse.py``'s ``parse_sysinfo``/``HttpSysInfo`` for the
    read-side grounding of this convention."""
    dhcp_select = "1" if state.mgmt.mode == "dhcp" else "0"
    return (
        _t.SYSINFO.replace("__GAMBIT__", token)
        .replace("__PRODUCT_NAME__", state.model_name or "GS110EMX")
        .replace("__SWITCH_NAME__", state.hostname)
        .replace("__SERIAL__", state.serial)
        .replace("__MAC__", _format_mac(state.nsdp_mac))
        .replace("__FIRMWARE__", state.firmware)
        .replace("__DHCP_SELECT__", dhcp_select)
        .replace("__IP__", state.mgmt.address)
        .replace("__NETMASK__", state.mgmt.netmask)
        .replace("__GATEWAY__", state.mgmt.gateway)
    )


def render_interface_stats(state: VirtualSwitchState, token: str) -> str:
    """GET /iss/specific/interface_stats.html?Gambit=<token> -- byte-identical
    to gs110emx_interface_stats.html but for the per-port counters. The real
    device NEVER closes a ``<tr class="portID">`` with ``</tr>`` (rows run on
    until the next ``<tr>`` or the table close); this reproduces that exact
    malformed-but-real shape row-for-row, which is why
    ``parse.parse_interface_stats`` (not gs305ep's ``parse_port_stats``) is
    needed to read it back. Missing counters (``None``) render as ``0``,
    matching the real device's own zeroed idle-port rows."""
    rows = "".join(
        '<tr class="portID"> \n'
        + _t.STATS_ROW.replace("__PORT__", str(port))
        .replace("__RX__", str(sim.rx_octets or 0))
        .replace("__TX__", str(sim.tx_octets or 0))
        .replace("__CRC__", str(sim.rx_errors or 0))
        for port, sim in sorted(state.ports.items())
    )
    return _t.STATS_PREFIX.replace("__GAMBIT__", token) + rows + _t.STATS_SUFFIX
