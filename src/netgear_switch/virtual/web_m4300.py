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


def render_ports(state: VirtualSwitchState) -> str:
    """``/v1/portsConfiguration.html`` -- per-port admin/link/speed."""
    body = ""
    for port in _physical_ports(state):
        sim = state.ports[port]
        inst = f"1.{port}.24"
        body += _cell(inst, "1_2_1", _iface(port), "baseinterfaceListing_Interfaces")
        body += _cell(inst, "1_2_2", str(port), "baseport_ifIndex")
        body += _cell(
            inst, "1_2_3", "Enable" if sim.admin else "Disable", "baseport_AdminMode"
        )
        body += _cell(
            inst, "1_2_10", "Link Up" if sim.link else "Link Down",
            "baseport_LinkStatus2",
        )
        body += _cell(
            inst, "1_2_9",
            _speed_text(sim.speed) if sim.link else "",
            "baseport_PhysicalStatus",
        )
    return _page(body)


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
        body += _cell(
            inst, "1_5_1", str(vid), "SwitchingVlanStaticConfig_VlanIndex"
        )
        body += _cell(
            inst, "1_5_2", vsim.name or "", "SwitchingVlanStaticConfig_VlanName"
        )
        body += _cell(
            inst, "1_5_4", egress,
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
        body += _cell(
            inst, "1_6_3", str(entry.vlan), "SwitchingmacAddrGroup_vlanIndex"
        )
    return _page(body)


def render_sysinfo(state: VirtualSwitchState) -> str:
    """``/v1/base/system/management/sysInfo.html`` -- mgmt IP, base MAC and the
    temperature block. Plain labelled cells (this page has no xid cells)."""
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    temps = "".join(
        f"<tr><td>{s.instance}</td><td>{s.raw} &#8451;</td></tr>\n"
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
