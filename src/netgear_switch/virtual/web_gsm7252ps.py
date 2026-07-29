"""GSM7252PS "XE FASTPATH" page renderers driven by ``VirtualSwitchState``.

Reproduces the real page encoding rather than a convenient one. Every data
cell is a hidden input whose ``NAME`` carries the ROW INSTANCE and whose
``id``/``xid`` carry the COLUMN COORDINATE, with NO field-name comment --

    <TD class="def alt0" p="1.0.520" id=1_2_10><INPUT xid=1_2_10 TYPE=hidden
         NAME=1.0.52.v_1_2_10 VALUE="Link Up">Link Up</TD>

which is exactly what ``parse.parse_xe_rows`` reads back, so the mock
exercises the same column-coordinate-addressed parsing path real hardware
does. Two details of the real encoding are deliberately reproduced because
getting them wrong is what a parser regression would look like:

- the instance prefix is ``1.<row-index>.<row-count>`` (NOT unit/slot/port),
  so a parser that tried to read a port number out of it would produce
  nonsense here too, exactly as it does on hardware;
- each page's own HEADER row is emitted with the same coordinates, so the
  fixture and the mock document the column map identically.

``sysInfo.html`` is NOT an XE page (see ``render_sysinfo``): it uses plain
bold-label/value cells and three status tables, which is what
``parse_xe_labelled_values``/``parse_xe_sensors``/``parse_xe_mgmt_ip`` read.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .state import SensorSim, VirtualSwitchState


def _iface(port: int) -> str:
    return f"1/0/{port}"


def _cell(instance: str, xid: str, value: str) -> str:
    return (
        f'<TD class="def alt0" p="{instance}0" id={xid}>'
        f'<INPUT xid={xid} TYPE=hidden NAME={instance}.v_{xid} '
        f'VALUE="{value}">{value}</TD>\n'
    )


def _header(labels: dict[str, str]) -> str:
    return "".join(
        f'<TD class="def_TH alt0" id={xid}>{text}</TD>\n'
        for xid, text in labels.items()
    )


def _speed_text(mbps: int) -> str:
    """Real firmware's Physical Status text: "1000 Mbps" / "10G Full "."""
    if mbps >= 1000 and mbps % 1000 == 0:
        return f"{mbps // 1000}G Full "
    return f"{mbps} Mbps"


def _page(body: str) -> str:
    return f"<html><body><form>\n<table>\n{body}</table></form></body></html>\n"


def _physical_ports(state: VirtualSwitchState) -> list[int]:
    """Just the PHYSICAL ports, in order.

    The seeds carry SNMP ifIndex-keyed entries that also include LAG/CPU/VLAN
    interfaces. The real XE port/statistics/PVID/PoE pages list only physical
    ports, so rendering the extras would make the HTTP reader report
    interfaces the web UI never shows -- and disagree with SNMP about which
    ports exist."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    return [p for p in sorted(state.ports) if p <= port_count]


def render_ports(state: VirtualSwitchState) -> str:
    """``/portsConfiguration.html`` -- per-port admin/link/speed + ifindex."""
    body = _header(
        {
            "1_2_1": "Port",
            "1_2_6": "Admin <br/> Mode",
            "1_2_9": "Physical Status",
            "1_2_10": "Link Status",
            "1_2_13": "ifindex",
        }
    )
    ports = _physical_ports(state)
    for row, port in enumerate(ports):
        sim = state.ports[port]
        inst = f"1.{row}.{len(ports)}"
        body += _cell(inst, "1_2_1", _iface(port))
        body += _cell(inst, "1_2_6", "Enable" if sim.admin else "Disable")
        # A down port's Physical Status reads "Unknown" on real hardware.
        body += _cell(inst, "1_2_9", _speed_text(sim.speed) if sim.link else "Unknown")
        body += _cell(inst, "1_2_10", "Link Up" if sim.link else "Link Down")
        body += _cell(inst, "1_2_13", str(port))
    return _page(body)


def render_port_statistics(state: VirtualSwitchState) -> str:
    """``/portStatistics.html`` -- PACKET counters (this page has no octets).

    The virtual state stores octet counters too, but they are deliberately NOT
    rendered here: the real page has no octet column, and emitting one would
    let a regression that reads bytes off this page pass CI.
    """
    body = _header(
        {
            "1_1_103": "Interface",
            "1_1_2": "Total Packets received without Errors",
            "1_1_3": "Packets received with Errors",
            "1_1_5": "Packets transmitted without Errors",
            "1_1_6": "Transmit Packet Errors",
        }
    )
    ports = _physical_ports(state)
    for row, port in enumerate(ports):
        sim = state.ports[port]
        inst = f"1.{row}.{len(ports)}"
        body += _cell(inst, "1_1_103", _iface(port))
        body += _cell(inst, "1_1_2", str(sim.rx_ucast or 0))
        body += _cell(inst, "1_1_3", str(sim.rx_errors or 0))
        body += _cell(inst, "1_1_5", str(sim.tx_ucast or 0))
        body += _cell(inst, "1_1_6", str(sim.tx_errors or 0))
    return _page(body)


def render_pvids(state: VirtualSwitchState) -> str:
    """``/portPvidConfiguration.html`` -- Configured + Current PVID columns."""
    body = _header(
        {
            "1_2_1": "Interface",
            "1_2_4": "Configured <br/> PVID",
            "1_2_9": "Current <br/> PVID",
        }
    )
    physical = _physical_ports(state)
    rows = [(p, state.pvids[p]) for p in physical if p in state.pvids]
    for row, (port, pvid) in enumerate(rows):
        inst = f"1.{row}.{len(rows)}"
        body += _cell(inst, "1_2_1", _iface(port))
        body += _cell(inst, "1_2_4", str(pvid))
        body += _cell(inst, "1_2_9", str(pvid))
    return _page(body)


def render_vlans(state: VirtualSwitchState) -> str:
    """``/vlanStatus.html`` -- VLANs with their egress port list.

    The egress list is rendered in the real firmware's format, including the
    ``lag N`` entries that must NOT be expanded into physical ports."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    body = _header(
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
        # Seeds carry SNMP ifIndex-based member sets where indexes above the
        # physical port count are LAGs; rendering those as "1/0/<ifIndex>"
        # would make the reader report ports that do not exist.
        physical = [p for p in sorted(vsim.member) if p <= port_count]
        lags = [p for p in sorted(vsim.member) if p > port_count]
        parts = [_iface(p) for p in physical]
        parts += [f"lag {i}" for i, _ in enumerate(lags, start=1)]
        body += _cell(inst, "1_1_1", str(vid))
        body += _cell(inst, "1_1_2", vsim.name or "")
        body += _cell(inst, "1_1_3", "Default" if vid == 1 else "Static")
        body += _cell(inst, "1_1_4", ", ".join(parts))
    return _page(body)


def render_mac_table(state: VirtualSwitchState) -> str:
    """``/basicAddressTable.html`` -- the learned MAC/FDB table.

    The "Total MAC Addresses" scalar the real page carries is rendered too,
    with the true row count, so the reader's anti-truncation guard is
    exercised against a page that is legitimately complete."""
    body = (
        '<TR id=1_1 class=deftestme>\n'
        '<TD class=defleft id=1_1_1>Total MAC Addresses</TD>\n'
        f'<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden '
        f'NAME=v_1_1_1 VALUE="{len(state.macs)}"></TD>\n</TR>\n'
    )
    body += _header(
        {
            "1_2_1": "VLAN ID",
            "1_2_3": "MAC Address",
            "1_2_4": "Port",
            "1_2_6": "status",
        }
    )
    for row, entry in enumerate(state.macs):
        inst = f"1.{row}.{len(state.macs)}"
        mac = ":".join(f"{b:02X}" for b in entry.mac_bytes)
        # The page names the INTERFACE an address was learned on, which is the
        # ifIndex-keyed port -- not the bridge-port index. Rendering the raw
        # bridge port would make this page disagree with SNMP's get_macs
        # (which joins through dot1dBasePortIfIndex) on exactly the entries
        # whose join is not the identity.
        port = state.bridge_ports.get(entry.bridge_port, entry.bridge_port)
        body += _cell(inst, "1_2_1", str(entry.vlan))
        body += _cell(inst, "1_2_3", mac)
        body += _cell(inst, "1_2_4", _iface(port))
        body += _cell(inst, "1_2_6", "Learned")
    return _page(body)


# RFC3621 pethPsePortDetectionStatus -> the real page's Status text. Only the
# codes the virtual state actually uses are mapped; anything else renders as
# the firmware's catch-all fault text rather than a fabricated status.
_DETECT_TEXT = {1: "Disabled", 2: "Searching", 3: "Delivering power"}


def render_poe(state: VirtualSwitchState, *, watts: bool = False) -> str:
    """``/poeInterfaceConfiguration.html`` -- per-port PoE admin/status/power.

    ``watts`` selects the "Output Power" cell format to MATCH the emulated
    firmware: the gsm7252ps renders integer milliwatts (``watts=False``, e.g.
    "3500"); the M4300-16X renders watts with two decimals (``watts=True``,
    e.g. "4.60"). Both decode back to the same milliwatts via
    ``parse._poe_power_to_mw`` -- see the parity note there."""
    body = _header(
        {
            "1_2_1": "Port",
            "1_2_2": "Admin <br/> Mode",
            "1_2_15": "Ouput <br/> Power <br/> (mW)",
            "1_2_17": "Status",
        }
    )
    poe = sorted(state.poe.items())
    for row, (port, sim) in enumerate(poe):
        inst = f"1.{row}.{len(poe)}"
        body += _cell(inst, "1_2_1", _iface(port))
        body += _cell(inst, "1_2_2", "Enable" if sim.admin else "Disable")
        power = sim.power_mw or 0
        cell = f"{power / 1000:.2f}" if watts else str(power)
        body += _cell(inst, "1_2_15", cell)
        body += _cell(inst, "1_2_17", _DETECT_TEXT.get(sim.detect, "Other Fault"))
    return _page(body)


def render_lldp(state: VirtualSwitchState) -> str:
    """``/lldpRemoteInventory.html`` -- LLDP neighbours.

    This page has NO remote-port-DESCRIPTION column, so ``LldpSim.port_desc``
    is deliberately not rendered: the mock must not expose data the real page
    does not have."""
    body = _header(
        {
            "1_1_1": "Port",
            "1_1_7": "MAC Address",
            "1_1_8": "System Name",
            "1_1_9": "Remote Port ID",
        }
    )
    for row, nb in enumerate(state.lldp):
        inst = f"1.{row}.{len(state.lldp)}"
        chassis = ":".join(f"{ord(c):02X}" for c in nb.chassis)
        body += _cell(inst, "1_1_1", _iface(nb.local_port))
        body += _cell(inst, "1_1_7", chassis)
        body += _cell(inst, "1_1_8", nb.sys_name)
        body += _cell(inst, "1_1_9", nb.port_id)
    return _page(body)


def _status_table(title: str, rows: list[tuple[str, str]]) -> str:
    """One ``sysInfo.html`` status table: a header row of unit columns plus one
    labelled row per sensor (only unit 1 is populated, as on a single-unit
    switch)."""
    header = "".join(
        f'<td class="messageTableHeaderBorder messageTableHeaderVerticalBorder">'
        f"{n}</td>\n"
        for n in ("Unit ID", "1")
    )
    body = "".join(
        f'<tr>\n<td class="messageTableWhiteBorder font10Bold">{label}</td>\n'
        f'<td class="messageTableWhiteBorder font10">{value}</td>\n</tr>\n'
        for label, value in rows
    )
    return (
        f"<tr><td colspan=\"3\"><script>tbhdr('{title}','x')</script></td></tr>\n"
        f'<tr class="white10Bold">\n{header}</tr>\n{body}'
    )


def _sensor_label(sensor: SensorSim) -> str:
    """The page label for a seeded HTTP sysInfo sensor.

    For the sysInfo sensor set (``state.sysinfo_sensors``) the ``instance``
    field carries the page's OWN row label -- "System"/"CPU"/"MAC-A" for
    temperatures, "Fan1/PWR"/"Fan2/CPU" for fans, "RPS"/"Power Module" for the
    device rows -- exactly as the real gsm7252ps_sysInfo.html prints them."""
    return sensor.instance


def render_sysinfo(state: VirtualSwitchState) -> str:
    """``/base/system/management/sysInfo.html`` -- mgmt IP, base MAC and the
    three status tables.

    Renders the model's HTTP sysInfo sensor set (``state.sysinfo_sensors``),
    which on this device is DIFFERENT from its SNMP set: the web UI exposes a
    Temperature Status table (numeric degC, "N/A" for an unpopulated slot which
    the parser skips), a FAN Status table reporting fan HEALTH as text
    ("OK"/"NA", never RPM), and a Device Status table with the RPS + Power
    Module operational flags. Each cell is the sensor's literal captured page
    text, so the parser reads back exactly the real hardware's HTTP sensors.
    """
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    sensors = state.sysinfo_sensors
    temps = [
        (_sensor_label(s), f"{s.raw}&degC" if s.raw.isdigit() else "N/A")
        for s in sensors
        if s.kind == "temperature"
    ]
    fans = [(_sensor_label(s), s.raw) for s in sensors if s.kind == "fan"]
    device = [
        ("Firmware Version", state.firmware),
        ("Serial Number", state.serial),
    ]
    device += [(_sensor_label(s), s.raw) for s in sensors if s.kind == "power"]
    return (
        "<html><body><form>\n<table>\n"
        '<tr><td class="font10Bold">Product Name</td>'
        f'<td class="font10">{state.model_name}</td></tr>\n'
        '<tr><td class="font10Bold">System Name</td>'
        f'<td><INPUT class="input" type="TEXT" name="sysName" '
        f'VALUE="{state.hostname}"></td></tr>\n'
        '<tr><td class="font10Bold">IPv4 Network Interface</td>'
        f'<td class="font10"><a href="/ipConfiguration.html">'
        f"{state.mgmt.address}/{state.mgmt.netmask}</a></td></tr>\n"
        '<tr><td class="font10Bold">System MAC Address</td>'
        f'<td class="font10">{mac}</td></tr>\n'
        f"{_status_table('FAN Status', fans)}"
        f"{_status_table('Temperature Status', temps)}"
        f"{_status_table('Device Status', device)}"
        "</table></form></body></html>\n"
    )
