"""GS105PE web-UI page renderers driven by ``VirtualSwitchState``.

Structurally faithful to the REAL captured pages (see
``tests/fixtures/http/gs105pe_*.html``) -- same row markers, same column
order, and critically the same two quirks real firmware has, so the mock
exercises exactly the code paths real hardware does:

- ``portStatistics.cgi`` leaves the first counter's ``<td>`` EMPTY and carries
  every counter as a hidden ``(hi, lo)`` 32-bit pair (see
  ``protocols/http/parse.py``'s ``parse_gs105pe_stats``), and writes its rows as
  ``<tr class="portID" name="portID">`` -- an extra attribute the other pages
  lack.
- ``8021qMembe.cgi`` carries a per-page CSRF ``hash`` and marks the currently
  selected VLAN with ``<option ... selected>``; the reader reuses that page for
  the selected VLAN rather than re-POSTing it (which makes real hardware drop
  the connection).

Byte-for-byte fidelity to the capture is deliberately NOT attempted here (that
is what the fixture-driven parser tests in ``tests/test_http_read.py`` prove);
this face's job is to serve the SAME STATE the NSDP face serves, so the
HTTP<->NSDP cross-verification is meaningful.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .state import VirtualSwitchState

# The mock's fixed CSRF token. Real firmware regenerates this per page load;
# the reader only has to scrape it and echo it back, so a constant is enough
# to exercise that round trip.
VIRTUAL_CSRF_HASH = "18007"


def _speed_text(mbps: int) -> str:
    """State speed (Mbps) -> status.cgi speed text. Inverse of
    ``parse._speed_text_to_mbps`` so a state -> page -> reader round trip
    reproduces the state value exactly."""
    if mbps >= 1000 and mbps % 1000 == 0:
        return f"{mbps // 1000}G"
    return f"{mbps}M"


def render_status(state: VirtualSwitchState) -> str:
    """GET /status.cgi -- per-port link + speed, the columns
    ``parse_gs105pe_port_status`` reads ([1]=port, [2]=link, [4]=speed)."""
    rows = "".join(
        '<tr class="portID">\n'
        '<td class="def firstCol def_center"><input type="checkbox"></td>\n'
        f'<td class="def" sel="text">{port}</td>\n'
        f'<td class="def" sel="text">{"Up" if sim.link else "Down"}</td>\n'
        '<td class="def" sel="text">Auto</td>\n'
        f'<td class="def" sel="text">'
        f"{_speed_text(sim.speed) if sim.link else 'No Speed'}</td>\n"
        '<td class="def" sel="text">Disable</td>\n'
        '<td class="def" sel="text">16349</td>\n'
        for port, sim in sorted(state.ports.items())
    )
    return (
        "<html><body><form method=post action=status.cgi>"
        '<table id="tbl1">\n' + rows + "</table></form></body></html>\n"
    )


def render_port_statistics(state: VirtualSwitchState) -> str:
    """GET /portStatistics.cgi -- reproduces the real page's quirks: rows are
    ``<tr class="portID" name="portID">``, the Bytes-Received cell is rendered
    EMPTY, and each counter is a hidden ``(hi, lo)`` 32-bit pair."""

    def halves(value: int) -> str:
        return (
            f'<input type="hidden" value="{value >> 32}">\n'
            f'<input type="hidden" value="{value & 0xFFFFFFFF}">\n'
        )

    rows = ""
    for port, sim in sorted(state.ports.items()):
        rx, tx, crc = sim.rx_octets or 0, sim.tx_octets or 0, sim.rx_errors or 0
        rows += (
            '<tr class="portID" name="portID">\n'
            f'<td class="def firstCol" sel="text">{port}</td>\n'
            '<td class="def" sel="text">\n</td>\n'
            + halves(rx)
            + f'<td class="def" sel="text">{tx}\n</td>\n'
            + halves(tx)
            + f'<td class="def" sel="text">{crc}\n</td>\n'
            + halves(crc)
        )
    return (
        "<html><body><form method=post action=portStatistics.cgi>"
        '<table id="tbl1">\n' + rows + "</table></form></body></html>\n"
    )


def render_pvid(state: VirtualSwitchState) -> str:
    """GET /portPVID.cgi -- [1]=port, [2]=PVID."""
    rows = "".join(
        '<tr class="portID">\n'
        '<td class="def firstCol def_center"><input type="checkbox"></td>\n'
        f'<td class="def" sel="text">{port}</td>\n'
        f'<td class="def" sel="input">{pvid}</td>\n'
        for port, pvid in sorted(state.pvids.items())
    )
    return (
        "<html><body><form method=post action=portPVID.cgi>"
        '<table id="tbl1">\n' + rows + "</table></form></body></html>\n"
    )


def render_vlan_config(state: VirtualSwitchState) -> str:
    """GET /8021qCf.cgi -- the VLAN list as ``vlanckN`` checkboxes (the shape
    gs305ep's ``parse_vlan_ids`` reads, which gs105pe shares)."""
    boxes = "".join(
        f'<input type="checkbox" name="vlanck{i}" value="{vid}">\n'
        for i, vid in enumerate(sorted(state.vlans), start=1)
    )
    return (
        "<html><body><form method=post action=8021qCf.cgi>"
        f'<input type="hidden" name="hash" value="{VIRTUAL_CSRF_HASH}">\n'
        + boxes
        + "</form></body></html>\n"
    )


def render_vlan_membership(state: VirtualSwitchState, selected_vid: int) -> str:
    """GET/POST /8021qMembe.cgi -- the per-port ``hiddenMem`` wire codes
    (1=untagged, 2=tagged, 3=excluded) for ``selected_vid``, plus the CSRF
    ``hash`` and a ``<option ... selected>`` marking which VLAN is shown."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    vsim = state.vlans.get(selected_vid)
    codes = ""
    for port in range(1, port_count + 1):
        if vsim is not None and port in vsim.untagged:
            codes += "1"
        elif vsim is not None and port in vsim.member:
            codes += "2"
        else:
            codes += "3"
    options = "".join(
        f'<option value="{vid}"{" selected" if vid == selected_vid else ""}>'
        f"{vid}</option>\n"
        for vid in sorted(state.vlans)
    )
    return (
        "<html><body><form method=post action=8021qMembe.cgi>"
        f'<input type="hidden" name="hash" value="{VIRTUAL_CSRF_HASH}">\n'
        f'<select name="VLAN_ID" id="vlanIdOption">\n{options}</select>\n'
        f'<input name="hiddenMem" id="hiddenMem" value="{codes}" type="hidden">\n'
        "</form></body></html>\n"
    )


def render_switch_info(state: VirtualSwitchState) -> str:
    """GET /switch_info.cgi -- device identity + mgmt-IP, in the labelled-cell
    and lowercase-input shape ``parse_gs105pe_sysinfo`` reads."""
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    dhcp_selected = state.mgmt.mode == "dhcp"
    return (
        "<html><body><form method=post action=switch_info.cgi>"
        "<table>\n"
        f"<tr><td>Product Name</td><td>{state.model_name or 'GS105PE'}</td></tr>\n"
        f"<tr><td>Serial Number</td><td>{state.serial}</td></tr>\n"
        f"<tr><td>MAC Address</td><td>{mac}</td></tr>\n"
        f"<tr><td>Firmware Version</td><td>{state.firmware}</td></tr>\n"
        "</table>\n"
        f'<input type="text" name="switch_name" value="{state.hostname}">\n'
        '<select name="dhcpMode" id="dhcpMode">\n'
        f'<option value="0"{"" if dhcp_selected else " selected"}>Disable</option>\n'
        f'<option value="1"{" selected" if dhcp_selected else ""}>Enable</option>\n'
        "</select>\n"
        f'<input type="text" name="ip_address" value="{state.mgmt.address}">\n'
        f'<input type="text" name="subnet_mask" value="{state.mgmt.netmask}">\n'
        f'<input type="text" name="gateway_address" value="{state.mgmt.gateway}">\n'
        "</form></body></html>\n"
    )
