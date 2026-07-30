"""S3300-52X-PoE+ (gsm7228ps) "XE FASTPATH" page renderers from state.

The S3300 Smart-Managed-Pro web UI shares the sibling gsm7252ps Cheetah XE
cell grid for ports/stats/PVIDs/VLANs/PoE/LLDP, so those pages are rendered by
the exact gsm7252ps renderers (see ``web_gsm7252ps``) -- the reader keys off
the ifindex/port columns, which are identical. Only three pages differ and are
rendered here, matching the real captures in
``tests/fixtures/http/gsm7228ps_*.html`` and the S3300-specific parsers:

- ``basicAddressTable.html`` -- the MAC/FDB columns are SHIFTED (VLAN in
  v_1_2_2, not v_1_2_1) and the port ifName is HTML-entity-escaped in the
  Smart firmware's ``1/gN``/``1/xgN`` form (``&#x2F;`` = ``/``); the switch's
  own base MAC is learned on the CPU interface, rendered ``c1`` / status
  "Management", which ``parse_s3300_macs`` skips as non-physical (SNMP reports
  that same base MAC on the CPU ifIndex).
- ``sysInfo.html`` -- exposes only the ``Base MAC Address`` (no IPv4 mgmt
  address on the statically-reachable page), which is all
  ``parse_s3300_mgmt`` reads.

Sensors are NOT served as a live table: the S3300 sysInfo has no fan/temp
readings, so ``get_sensors`` over HTTP is unsupported (SNMP only) -- see
``HtmlDialect.S3300`` and ``http_read._supports_sensors``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import web_gsm7252ps as _xe

if TYPE_CHECKING:
    from .state import VirtualSwitchState

# The gsm7252ps XE renderers whose page shape the S3300 shares byte-for-byte
# (the reader keys off the ifindex/port-number columns, not the port ifName).
render_port_statistics = _xe.render_port_statistics
render_pvids = _xe.render_pvids
render_lldp = _xe.render_lldp

# The S3300's per-row selection checkboxes, from the LIVE 10.1.5.11 pages: they
# are NOT the gsm7252ps spellings even though the grid is otherwise identical.
#   portsConfiguration        -> 1.<row>.52.gecb10
#   poeInterfaceConfiguration -> 1.<row>.48.gecb164
_PORTS_CHECKBOX = "gecb10"
_POE_CHECKBOX = "gecb164"


def _s3300_iface(port: int) -> str:
    """S3300 ifName for a port number: ``1/gN`` (1-48), ``1/xgN`` (49-52), and
    ``c1`` for the CPU/management interface (any other ifIndex, e.g. the 313
    the switch's own base MAC is learned on)."""
    if 1 <= port <= 48:
        return f"1/g{port}"
    if 49 <= port <= 52:
        return f"1/xg{port}"
    return "c1"


def render_ports(state: VirtualSwitchState, *, err_msg: str = "") -> str:
    """``/portsConfiguration.html`` in the Smart firmware's spelling.

    Same XE grid as gsm7252ps, but the Port cell is ``1/g12``/``1/xg49``, not
    ``1/0/12`` -- live-confirmed on 10.1.5.11. It used to be aliased straight to
    the gsm7252ps renderer, which made the mock print ``1/0/N`` here and hid the
    fact that a writer locating its row by ifName has to handle BOTH spellings.
    """
    return _xe.render_ports(
        state, err_msg=err_msg, iface=_s3300_iface, checkbox=_PORTS_CHECKBOX
    )


def apply_ports(state: VirtualSwitchState, form: dict[str, str]) -> str:
    return _xe.apply_ports(state, form, checkbox=_PORTS_CHECKBOX)


def render_poe(state: VirtualSwitchState, *, err_msg: str = "") -> str:
    """``/poeInterfaceConfiguration.html`` in the Smart firmware's spelling."""
    return _xe.render_poe(
        state, err_msg=err_msg, iface=_s3300_iface, checkbox=_POE_CHECKBOX
    )


def apply_poe(state: VirtualSwitchState, form: dict[str, str]) -> str:
    # unit_required=False: this firmware's PoE rows carry their own hidden
    # ``v_1_2_21`` "Unit" key (``xk_1_2_21 = 1`` in its
    # _xe_poeInterfaceConfiguration.js), so the row is self-identifying and the
    # apply lands with no page-level unit field -- live-proven on 10.1.5.11
    # 2026-07-30, which is exactly why the sibling gsm7252ps's refusal looked
    # like a device fault instead of the missing field it was.
    return _xe.apply_poe(state, form, checkbox=_POE_CHECKBOX, unit_required=False)


def render_vlans(state: VirtualSwitchState) -> str:
    """``/vlanStatus.html`` -- VLANs with their egress port list (S3300 ifNames).

    The egress cell uses the Smart firmware's ``1/gN``/``1/xgN`` names (which
    ``parse_s3300_vlans`` reads, unlike the ``1/0/N``-only XE expander), with
    LAG ifIndexes rendered ``lag N`` -- not expanded into physical ports."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    body = _xe._header(
        {
            "1_1_1": "VLAN <br/> ID",
            "1_1_2": "VLAN Name",
            "1_1_3": "VLAN Type",
            "1_1_4": "Member Ports",
        }
    )
    vlans = sorted(state.vlans.items())
    for row, (vid, vsim) in enumerate(vlans):
        inst = f"1.{row}.{len(vlans)}"
        physical = [p for p in sorted(vsim.member) if p <= port_count]
        lags = [p for p in sorted(vsim.member) if p > port_count]
        parts = [_s3300_iface(p) for p in physical]
        parts += [f"lag {i}" for i, _ in enumerate(lags, start=1)]
        body += _xe._cell(inst, "1_1_1", str(vid))
        body += _xe._cell(inst, "1_1_2", vsim.name or "")
        body += _xe._cell(inst, "1_1_3", "Default" if vid == 1 else "Static")
        body += _xe._cell(inst, "1_1_4", ", ".join(parts))
    return _xe._page(body)


def _escape_slash(text: str) -> str:
    """Render ``/`` as the ``&#x2F;`` entity the real S3300 page emits in the
    MAC-table port cell -- ``parse_xe_rows`` html-unescapes it back."""
    return text.replace("/", "&#x2F;")


def render_mac_table(state: VirtualSwitchState) -> str:
    """``/basicAddressTable.html`` -- the learned MAC/FDB table (S3300 columns).

    VLAN in v_1_2_2, MAC in v_1_2_3, escaped port ifName in v_1_2_4, status in
    v_1_2_5 -- the shifted layout ``parse_s3300_macs`` reads. The "Total MAC
    Addresses" scalar (v_1_1_1) carries the true row count so the reader's
    anti-truncation guard sees a legitimately complete page.
    """
    body = (
        "<TR id=1_1 class=deftestme>\n"
        "<TD class=defleft id=1_1_1>Total MAC Addresses</TD>\n"
        f"<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden "
        f'NAME=v_1_1_1 VALUE="{len(state.macs)}"></TD>\n</TR>\n'
    )
    body += _xe._header(
        {
            "1_2_2": "VLAN ID",
            "1_2_3": "MAC Address",
            "1_2_4": "Port",
            "1_2_5": "status",
        }
    )
    for row, entry in enumerate(state.macs):
        inst = f"1.{row}.{len(state.macs)}"
        mac = ":".join(f"{b:02X}" for b in entry.mac_bytes)
        port = state.bridge_ports.get(entry.bridge_port, entry.bridge_port)
        iface = _escape_slash(_s3300_iface(port))
        status = "Management" if _s3300_iface(port) == "c1" else "Learned"
        body += _xe._cell(inst, "1_2_2", str(entry.vlan))
        body += _xe._cell(inst, "1_2_3", mac)
        body += _xe._cell(inst, "1_2_4", iface)
        body += _xe._cell(inst, "1_2_5", status)
    return _xe._page(body)


def render_sysinfo(state: VirtualSwitchState) -> str:
    """``/base/system/management/sysInfo.html`` -- Base MAC Address only.

    The S3300 Smart UI's statically-reachable sysInfo exposes the switch's base
    MAC (labelled cell, ``aid="1_16_1_right"``) but NOT the IPv4 management
    address (that page is behind a JS-only menu), and carries no live fan/temp
    sensor table. ``parse_s3300_mgmt`` reads back the base MAC; ``get_sensors``
    is unsupported over HTTP for this model.
    """
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    return (
        "<html><body><form>\n<table>\n"
        '<tr><td class="defaultFontBold" aid="1_1_1_left">Product Name</td>'
        f'<td class="defaultFont" aid="1_1_1_right">{state.model_name}</td></tr>\n'
        '<tr><td class="defaultFontBold" aid="1_16_1_left">Base MAC Address</td>'
        f'<td class="defaultFont" aid="1_16_1_right">{mac}</td></tr>\n'
        '<tr><td class="defaultFontBold">Temperature traps range</td>'
        '<td class="defaultFont"> 0 to 90 degrees (Celsius)</td></tr>\n'
        "</table></form></body></html>\n"
    )
