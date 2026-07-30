"""M4300 "Cheetah /v1" page renderers driven by ``VirtualSwitchState``.

Reproduces the real page encoding rather than a convenient one: every value is
a hidden input whose ``NAME`` carries the ROW INSTANCE, followed by an HTML
comment naming the field --

    <TD id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
         VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->

which is exactly what ``parse.parse_cheetah_rows`` reads back, so the mock
exercises the same field-name-addressed parsing path real hardware does.
Interface names are HTML-escaped (``1&#x2F;0&#x2F;1``) because the real
firmware escapes them -- that escaping once collapsed every parsed port number
to 1, so reproducing it keeps the regression visible in CI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import web_fastpath_xui as xui

if TYPE_CHECKING:
    from .state import VirtualSwitchState

_ESCAPED_SLASH = "&#x2F;"


def _iface(port: int) -> str:
    """``1/0/<port>`` with the slashes HTML-escaped, as real firmware emits."""
    return f"1{_ESCAPED_SLASH}0{_ESCAPED_SLASH}{port}"


def _cell(instance: str, xid: str, value: str, field: str) -> str:
    return (
        f'<TD class="def" id={xid}><INPUT xid={xid} TYPE=hidden '
        f'NAME={instance}.v_{xid} VALUE="{value}">{value}</TD><!-- {field} -->\n'
    )


def _speed_text(mbps: int) -> str:
    if mbps >= 1000 and mbps % 1000 == 0:
        return f"{mbps // 1000}G Full"
    return f"{mbps}M Full"


def _page(body: str) -> str:
    return f"<html><body><form>\n{body}</form></body></html>\n"


def _physical_ports(state: VirtualSwitchState) -> list[int]:
    """Just the PHYSICAL ports, in order.

    The seeds carry SNMP ifIndex-keyed entries that also include LAG/CPU/VLAN
    interfaces (ifIndex 769+ on an M4300). The real portsConfiguration/
    portStatistics/portPvidConfiguration pages list ONLY physical ports, so
    rendering the extras would make the HTTP reader report interfaces the web
    UI never shows -- and disagree with SNMP on ports that do not exist."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    return [p for p in sorted(state.ports) if p <= port_count]


# The M4300 ports page's per-row selection checkbox, from the LIVE pages on
# BOTH SKUs (10.1.5.13 and 10.1.5.20:49152): ``1.<row>.<count>.gecb_1_2`` -- a
# third spelling, different again from gsm7252ps's gecb5 and gsm7228ps's gecb10.
_PORTS_CHECKBOX = "gecb_1_2"
_POE_CHECKBOX = "gecb_1_2"


def render_ports(state: VirtualSwitchState, *, err_msg: str = "") -> str:
    """``/v1/portsConfiguration.html`` -- per-port admin/link/speed.

    COLUMN COORDINATES CORRECTED against the real page (10.1.5.13, 2026-07-30):
    Admin Mode is ``v_1_2_6`` and ifIndex is ``v_1_2_13`` (a ``display:none``
    column), and the row prefix is ``1.<0-based row>.<row count>``. The mock
    used to emit ``v_1_2_3``/``v_1_2_2`` and ``1.<port>.24``, which the
    comment-keyed read parsers tolerated but which does not exist on any switch
    -- so a writer addressing the real Admin Mode column would have found
    nothing here while working on hardware.
    """
    body = ""
    ports = _physical_ports(state)
    for index, port in enumerate(ports):
        sim = state.ports[port]
        inst = xui.instance(index, len(ports))
        cells = _cell(inst, "1_2_1", _iface(port), "baseinterfaceListing_Interfaces")
        cells += _cell(
            inst, "1_2_6", "Enable" if sim.admin else "Disable", "baseport_AdminMode"
        )
        cells += _cell(
            inst,
            "1_2_10",
            "Link Up" if sim.link else "Link Down",
            "baseport_LinkStatus2",
        )
        cells += _cell(
            inst,
            "1_2_9",
            _speed_text(sim.speed) if sim.link else "",
            "baseport_PhysicalStatus",
        )
        cells += _cell(inst, "1_2_13", str(port), "baseport_ifIndex")
        body += xui.row(inst, cells, checkbox=_PORTS_CHECKBOX)
    return xui.page(
        "/v1/portsConfiguration.html",
        f"{xui.nav_rows()}<table>\n{body}</table>\n",
        buttons={"2_1_1": "Cancel", "2_1_2": "Apply"},
        err_msg=err_msg,
        title="NETGEAR -  Port Configuration",
    )


def apply_ports(state: VirtualSwitchState, form: dict[str, str]) -> str:
    """Apply a /v1/portsConfiguration POST; returns the firmware ``err_msg``."""
    ports = _physical_ports(state)
    return xui.apply_port_admin(
        state, form, checkbox=_PORTS_CHECKBOX, ports=ports, count=len(ports)
    )


def render_poe(state: VirtualSwitchState, *, err_msg: str = "") -> str:
    """``/v1/poeInterfaceConfiguration.html`` (M4300-16X only; the 24X has no
    PoE and its spec leaves the path None).

    The cell grid is byte-identical to the gsm7252ps XE page, so that renderer
    is reused -- but with THREE M4300-specific differences, each live-measured:
    the power column is decimal watts, the row checkbox is ``gecb_1_2``, and the
    reset button reads ``Power Cycle Port(s)`` rather than ``RESET``.
    """
    from . import web_gsm7252ps as _xe

    return _xe.render_poe(
        state,
        watts=True,
        err_msg=err_msg,
        iface=_iface,
        checkbox=_POE_CHECKBOX,
        reset_label="Power Cycle Port(s)",
        path="/v1/poeInterfaceConfiguration.html",
    )


def apply_poe(state: VirtualSwitchState, form: dict[str, str]) -> str:
    from . import web_gsm7252ps as _xe

    # unit_required=False: like the gsm7228ps and unlike the gsm7252ps, this
    # firmware's PoE rows carry their own hidden ``v_1_2_21`` "Unit" key, so the
    # apply lands with no page-level unit field -- live-proven on 10.1.5.20:49152
    # 2026-07-30. See web_gsm7252ps.apply_poe's ``unit_required``.
    return _xe.apply_poe(state, form, checkbox=_POE_CHECKBOX, unit_required=False)


def render_port_statistics(state: VirtualSwitchState) -> str:
    """``/v1/portStatistics.html`` -- FRAME counters (this UI has no octets).

    The virtual state stores octet counters, so the frame columns are seeded
    from the packet counters when present and 0 otherwise -- never from the
    octet values, which would imply this page reports bytes when it does not.
    """
    body = ""
    for port in _physical_ports(state):
        sim = state.ports[port]
        inst = f"1.{port}.24"
        body += _cell(inst, "1_2_1", _iface(port), "baseinterfaceListing_Interfaces")
        body += _cell(inst, "1_2_2", str(port), "baseport_ifIndex")
        body += _cell(
            inst, "1_3_1", str(sim.rx_ucast or 0), "basePortStats_TotalFramesRx"
        )
        body += _cell(
            inst, "1_3_2", str(sim.tx_ucast or 0), "basePortStats_TotalFramesTx"
        )
        body += _cell(
            inst, "1_3_3", str(sim.rx_errors or 0), "basePortStats_TotalErrorFramesRx"
        )
        body += _cell(
            inst, "1_3_4", str(sim.tx_errors or 0), "basePortStats_TotalErrorFramesTx"
        )
    return _page(body)


def render_pvids(state: VirtualSwitchState) -> str:
    """``/v1/portPvidConfiguration.html`` -- per-port PVID."""
    body = ""
    physical = set(_physical_ports(state))
    for port, pvid in sorted(state.pvids.items()):
        if port not in physical:
            continue
        inst = f"1.{port}.24"
        body += _cell(inst, "1_2_1", _iface(port), "baseinterfaceListing_Interfaces")
        body += _cell(inst, "1_2_2", str(port), "baseport_ifIndex")
        body += _cell(inst, "1_4_1", str(pvid), "SwitchingVlanPortConfig_Pvid")
    return _page(body)


def render_vlans(state: VirtualSwitchState) -> str:
    """``/v1/vlanStatus.html`` -- VLANs with their egress port list.

    The egress list is rendered in the real firmware's format, including the
    ``lag N`` entries that must NOT be expanded into physical ports."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    body = ""
    for vid, vsim in sorted(state.vlans.items()):
        inst = f"1.{vid}.30"
        # Real firmware renders PHYSICAL members as unit/slot/port and
        # aggregation members as "lag N". The seeds carry SNMP ifIndex-based
        # member sets, where indexes above the physical port count are LAGs --
        # rendering those as "1/0/<ifIndex>" would make the reader report
        # hundreds of bogus physical ports.
        physical = [p for p in sorted(vsim.member) if p <= port_count]
        lags = [p for p in sorted(vsim.member) if p > port_count]
        parts = [f"1/0/{p}" for p in physical]
        parts += [f"lag {i}" for i, _ in enumerate(lags, start=1)]
        egress = ", ".join(parts)
        body += _cell(inst, "1_5_1", str(vid), "SwitchingVlanStaticConfig_VlanIndex")
        body += _cell(
            inst, "1_5_2", vsim.name or "", "SwitchingVlanStaticConfig_VlanName"
        )
        body += _cell(
            inst,
            "1_5_4",
            egress,
            "SwitchingVlanCurrentConfig_VlanCurrentEgressPortList",
        )
    return _page(body)


def render_mac_table(state: VirtualSwitchState) -> str:
    """``/v1/basicAddressTable.html`` -- the learned MAC/FDB table."""
    body = ""
    for i, entry in enumerate(state.macs, start=1):
        inst = f"1.{i}.40"
        mac = ":".join(f"{b:02X}" for b in entry.mac_bytes)
        body += _cell(inst, "1_6_1", mac, "SwitchingmacAddrGroup_MacAddress")
        body += _cell(
            inst, "1_6_2", _iface(entry.bridge_port), "SwitchingmacAddrGroup_Intf"
        )
        body += _cell(inst, "1_6_3", str(entry.vlan), "SwitchingmacAddrGroup_vlanIndex")
    return _page(body)


def render_sysinfo(state: VirtualSwitchState) -> str:
    """``/v1/base/system/management/sysInfo.html`` -- mgmt IP, base MAC and the
    temperature block. Plain labelled cells (this page has no xid cells)."""
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    # Real firmware labels the temperature row with a TEXT name ("MAC"), and
    # parse_m4300_sensors' label group is [A-Za-z ] accordingly. Rendering the
    # seed's numeric SensorSim.instance here made the mock's sensor block
    # unparseable, so a virtual M4300 holding a real temperature answered
    # get_sensors() with an empty list -- the mock silently disagreeing with
    # both the real page and its own state.
    temps = "".join(
        f"<tr><td>MAC</td><td>{s.raw} &#8451;</td></tr>\n"
        for s in state.sensors
        if s.kind == "temperature" and s.raw.isdigit()
    )
    return (
        "<html><body><table>\n"
        "<tr><td>IPv4 Management Address</td>"
        f"<td><a href='/v1/mgmtVlanIpv4Configuration.html'>{state.mgmt.address}"
        f"/{state.mgmt.netmask}</a></td></tr>\n"
        f"<tr><td>System MAC Address</td><td>{mac}</td></tr>\n"
        f"{temps}"
        "</table></body></html>\n"
    )
