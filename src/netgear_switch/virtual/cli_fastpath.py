"""Render FASTPATH CLI ``show`` output from a ``VirtualSwitchState``.

The CLI analogue of ``virtual/web_gsm7252ps.py``: pure functions turning device
state into the exact fixed-width text shapes the ``protocols.cli.parse`` parsers
consume, so a ``VirtualSwitch`` answers the FASTPATH CLI like real hardware.
Only PHYSICAL ports (ifIndex <= the model's port_count) are ever printed -- the
CPU/LAG pseudo-interfaces in state (417/418 on the gsm7252ps) never appear on a
``show port all`` / ``show vlan`` page, exactly as on the real switch.

Values are rendered so the parsers reconstruct the SAME model objects the SNMP
face projects for the ops both serve (ports/pvids/vlans/poe/macs/mgmt-IP), which
is what the cross-backend test asserts. Where the two hardware interfaces
genuinely diverge (LLDP has no port-desc column in the CLI; sysInfo temperatures
vs SNMP fan RPM), that is documented at the renderer and the test compares the
shared projection only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import get_model

if TYPE_CHECKING:
    from .state import VirtualSwitchState


def _phys_ports(state: VirtualSwitchState) -> list[int]:
    port_count = get_model(state.model_key).port_count
    return sorted(p for p in state.ports if 1 <= p <= port_count)


def _is_m4300(state: VirtualSwitchState) -> bool:
    """True for the M4300 FASTPATH image, whose ``show poe``/``show environment``
    column shapes differ from the gsm7252ps image (no PoE ``Temperature`` column;
    the PSU sub-table is headed ``Power Modules:`` not ``Power supplies:``). Real
    fixtures: tests/fixtures/cli/m4300_16x_show_{poe_port_info_all,environment}.txt.
    """
    return state.model_key.startswith("m4300")


def _dotted(label: str, value: object) -> str:
    fill = max(2, 46 - len(label))
    return f"{label}{'.' * fill} {value}"


def _table(headers: list[str], widths: list[int], rows: list[list[object]]) -> str:
    lines = [" ".join(h.ljust(w) for h, w in zip(headers, widths, strict=False))]
    lines.append(" ".join("-" * w for w in widths))
    for row in rows:
        lines.append(
            " ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=False))
        )
    return "\n".join(lines)


def _mac_text(raw: bytes | tuple[int, ...] | str) -> str:
    if isinstance(raw, str):
        return ":".join(f"{ord(c):02X}" for c in raw)
    return ":".join(f"{b:02X}" for b in raw)


def _speed_text(mbps: int) -> str:
    if mbps >= 1000 and mbps % 1000 == 0:
        return f"{mbps // 1000}G Full"
    return f"{mbps} Full"


# --- show version / show network -------------------------------------------


def render_version(state: VirtualSwitchState) -> str:
    model = get_model(state.model_key)
    descr = state.sys_descr or f"NETGEAR {model.display_name} Managed Switch"
    return "\n".join(
        [
            "Switch: 1",
            "",
            _dotted("System Description", descr),
            _dotted("Machine Model", state.model_name or model.display_name),
            _dotted("Serial Number", state.serial),
            _dotted("Burned In MAC Address", _mac_text(state.nsdp_mac)),
            _dotted("Software Version", state.firmware),
        ]
    )


def render_network(state: VirtualSwitchState) -> str:
    proto = "DHCP" if state.mgmt.mode == "dhcp" else "None"
    return "\n".join(
        [
            _dotted("Interface Status", "Up"),
            _dotted("IP Address", state.mgmt.address),
            _dotted("Subnet Mask", state.mgmt.netmask),
            _dotted("Default Gateway", state.mgmt.gateway),
            _dotted("Burned In MAC Address", _mac_text(state.nsdp_mac)),
            _dotted("Configured IPv4 Protocol", proto),
            _dotted("Management VLAN ID", "1"),
        ]
    )


# --- show port all ----------------------------------------------------------


def render_ports(state: VirtualSwitchState) -> str:
    headers = [
        "Intf",
        "Type",
        "Admin",
        "Physical",
        "Physical",
        "Link",
        "Link",
        "LACP",
        "Flow",
    ]
    widths = [9, 6, 9, 10, 10, 6, 7, 6, 7]
    rows: list[list[object]] = []
    for p in _phys_ports(state):
        sim = state.ports[p]
        phys_status = _speed_text(sim.speed) if (sim.link and sim.speed) else ""
        rows.append(
            [
                f"1/0/{p}",
                "",
                "Enable" if sim.admin else "Disable",
                "Auto",
                phys_status,
                "Up" if sim.link else "Down",
                "Enable",
                "Enable",
                "Disable",
            ]
        )
    return _table(headers, widths, rows)


# --- show vlan brief / show vlan <id> --------------------------------------


def render_vlan_brief(state: VirtualSwitchState) -> str:
    headers = ["VLAN ID", "VLAN Name", "VLAN Type"]
    widths = [7, 32, 19]
    rows: list[list[object]] = []
    for vid in sorted(state.vlans):
        vsim = state.vlans[vid]
        vtype = "Default" if vid == 1 else "Static"
        rows.append([vid, vsim.name, vtype])
    return _table(headers, widths, rows)


def render_vlan_detail(state: VirtualSwitchState, vid: int) -> str:
    vsim = state.vlans.get(vid)
    header = [
        f"VLAN ID: {vid}",
        f"VLAN Name: {vsim.name if vsim else ''}",
        "VLAN Type: Static" if vid != 1 else "VLAN Type: Default",
        "",
    ]
    headers = ["Interface", "Current", "Configured", "Tagging"]
    widths = [10, 8, 11, 8]
    rows: list[list[object]] = []
    member = vsim.member if vsim else set()
    untagged = vsim.untagged if vsim else set()
    for p in _phys_ports(state):
        if p in member:
            current, configured = "Include", "Include"
            tagging = "Untagged" if p in untagged else "Tagged"
        else:
            current, configured, tagging = "Exclude", "Autodetect", "Untagged"
        rows.append([f"1/0/{p}", current, configured, tagging])
    return "\n".join(header) + "\n" + _table(headers, widths, rows)


# --- show vlan port all (PVIDs) --------------------------------------------


def render_pvids(state: VirtualSwitchState) -> str:
    headers = [
        "Interface",
        "Port",
        "Port",
        "Acceptable",
        "Ingress",
        "Ingress",
        "GVRP",
        "Default",
    ]
    widths = [9, 10, 8, 11, 10, 9, 7, 8]
    rows: list[list[object]] = []
    for p in _phys_ports(state):
        pvid = state.pvids.get(p, 1)
        rows.append(
            [f"1/0/{p}", pvid, pvid, "Admit All", "Disable", "Disable", "Enable", 0]
        )
    return _table(headers, widths, rows)


# --- show mac-addr-table ----------------------------------------------------


def render_mac_table(state: VirtualSwitchState) -> str:
    headers = ["VLAN ID", "MAC Address", "Interface", "IfIndex", "Status"]
    widths = [7, 18, 21, 7, 12]
    rows: list[list[object]] = []
    for msim in state.macs:
        ifindex = state.bridge_ports.get(msim.bridge_port, msim.bridge_port)
        sim = state.ports.get(ifindex)
        iface = sim.name if sim is not None else f"1/0/{ifindex}"
        rows.append([msim.vlan, _mac_text(msim.mac_bytes), iface, ifindex, "Learned"])
    return _table(headers, widths, rows)


# --- show lldp remote-device all -------------------------------------------


def render_lldp(state: VirtualSwitchState) -> str:
    headers = ["Interface", "RemID", "Chassis ID", "Port ID", "System Name"]
    widths = [9, 8, 20, 18, 18]
    rows: list[list[object]] = []
    for nb in state.lldp:
        rows.append(
            [
                f"1/0/{nb.local_port}",
                nb.rem_idx,
                _mac_text(nb.chassis) if nb.chassis else "",
                nb.port_id,
                nb.sys_name,
            ]
        )
    title = ["LLDP Remote Device Summary", "", "Local"]
    return "\n".join(title) + "\n" + _table(headers, widths, rows)


# --- show poe port info all -------------------------------------------------


def render_poe(state: VirtualSwitchState) -> str:
    # Full FASTPATH column names (the real switch wraps them over several header
    # lines; a single-line header of the same names parses identically). The
    # parser locates columns by NAME -- "Power (mW)" is the live draw, distinct
    # from "Max Power (mW)"; "Status" is the PSE state, distinct from "Fault
    # Status" -- so these exact strings matter.
    # The M4300 FASTPATH image omits the "Temperature" column the gsm7252ps
    # prints (real fixtures differ 9-vs-10 columns -- see parse.py:452-461). The
    # parser locates columns by NAME so either shape parses, but the mock must
    # emit whichever the driving model really prints.
    m4300 = _is_m4300(state)
    headers = [
        "Intf",
        "High Power",
        "Max Power (mW)",
        "Class",
        "Power (mW)",
        "Output Current (mA)",
        "Output Voltage (V)",
        *([] if m4300 else ["Temperature"]),
        "Status",
        "Fault Status",
    ]
    widths = [7, 11, 15, 9, 11, 20, 19, *([] if m4300 else [13]), 18, 13]
    rows: list[list[object]] = []
    for p in sorted(state.poe):
        psim = state.poe[p]
        status = "Delivering Power" if psim.detect == 3 else "Searching"
        rows.append(
            [
                f"1/0/{p}",
                "Yes" if p <= 8 else "No",
                32000 if p <= 8 else 18000,
                4 if psim.power_mw else "Unknown",
                psim.power_mw,
                0,
                54 if psim.power_mw else 0,
                *([] if m4300 else [30]),
                status,
                "No Error",
            ]
        )
    return _table(headers, widths, rows)


# --- show environment -------------------------------------------------------


def render_environment(state: VirtualSwitchState) -> str:
    temps = [s for s in state.sensors if s.kind == "temperature"]
    fans = [s for s in state.sensors if s.kind == "fan"]
    psus = [s for s in state.sensors if s.kind == "power"]

    out = [
        _dotted("Temp (C)", temps[0].raw if temps else "36"),
        _dotted("Fan Speed, RPM", fans[0].raw if fans else "Not Supported"),
        "",
        "Temperature Sensors:",
    ]
    out.append(
        _table(
            ["Unit", "Sensor", "Description", "Temp (C)", "State", "Max_Temp (C)"],
            [4, 6, 16, 10, 14, 14],
            [[1, i + 1, s.instance, s.raw, "Normal", 55] for i, s in enumerate(temps)],
        )
    )
    out += ["", "Fans:"]
    out.append(
        _table(
            ["Unit", "Fan", "Description", "Type", "Speed", "Duty", "State"],
            [4, 3, 14, 9, 13, 13, 14],
            [
                [1, i + 1, s.instance, "Fixed", s.raw, "Not Supported", "Operational"]
                for i, s in enumerate(fans)
            ],
        )
    )
    # gsm7252ps heads the PSU sub-table "Power supplies:"; the M4300 image heads
    # it "Power Modules:" (parse.py:574-577 accepts either). Emit the shape the
    # driving model really prints.
    out += ["", "Power Modules:" if _is_m4300(state) else "Power supplies:"]
    out.append(
        _table(
            ["Unit", "Power supply", "Description", "Type", "State"],
            [4, 12, 16, 10, 14],
            [
                [1, i + 1, s.instance, "Fixed", "Operational"]
                for i, s in enumerate(psus)
            ],
        )
    )
    return "\n".join(out)


# --- show interface ethernet <intf> ----------------------------------------


def render_interface_counters(state: VirtualSwitchState, port: int) -> str:
    sim = state.ports.get(port)
    rx_octets = sim.rx_octets if sim else 0
    tx_octets = sim.tx_octets if sim else 0
    rx_ucast = sim.rx_ucast if sim else 0
    tx_ucast = sim.tx_ucast if sim else 0
    rx_errors = sim.rx_errors if sim else 0
    tx_errors = sim.tx_errors if sim else 0
    return "\n".join(
        [
            _dotted("Total Packets Received (Octets)", rx_octets or 0),
            _dotted("Unicast Packets Received", rx_ucast or 0),
            _dotted("Total Packets Received with MAC Errors", rx_errors or 0),
            _dotted("Total Packets Transmitted (Octets)", tx_octets or 0),
            _dotted("Unicast Packets Transmitted", tx_ucast or 0),
            _dotted("Total Transmit Errors", tx_errors or 0),
            _dotted("Time Since Counters Last Cleared", "1 day 0 hr 0 min 0 sec"),
        ]
    )
