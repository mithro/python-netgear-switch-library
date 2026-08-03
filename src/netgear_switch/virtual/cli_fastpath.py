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
    from .state import PoeSim, VirtualSwitchState


def _phys_ports(state: VirtualSwitchState) -> list[int]:
    port_count = get_model(state.model_key).port_count
    return sorted(p for p in state.ports if 1 <= p <= port_count)


def _iface(state: VirtualSwitchState, port: int) -> str:
    """The ifName the CLI prints for a physical ``port``.

    Uses the seeded ``PortSim.name`` when present -- so the Smart-firmware
    S3300-52X (gsm7228ps) renders "1/gN"/"1/xgN" exactly as the real switch does,
    while the Fully Managed line keeps "1/0/N". Falls back to the "1/0/N" form for
    a port with no seeded name (e.g. an LLDP local port absent from ``ports``).
    """
    sim = state.ports.get(port)
    return sim.name if sim is not None and sim.name else f"1/0/{port}"


def port_for_iface(state: VirtualSwitchState, iface: str) -> int | None:
    """Inverse of ``_iface``: the physical port an ifName addresses, else None.

    The mock's CLI face needs to resolve the interface name a COMMAND carries
    ("show interface ethernet 1/xg49", "interface 1/g5") back to a port number,
    and it must accept exactly the names this renderer prints -- otherwise the
    mock would answer for names the real switch does not use (or, as it used to
    with a hardcoded ``\\d+/0/(\\d+)`` regex, reject the ``1/g<n>``/``1/xg<n>``
    names the Smart-firmware S3300-52X really prints). Resolving through
    ``_iface`` keeps the two directions in one place.
    """
    wanted = iface.strip()
    return next((p for p in state.ports if _iface(state, p) == wanted), None)


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


# --- show hosts -------------------------------------------------------------


def render_hosts(state: VirtualSwitchState) -> str:
    """``show hosts``, transcribed from real output captured 2026-08-02.

    From m4300-24x (10.1.5.13), m4300-16x (10.1.5.20) and gsm7252ps
    (10.1.5.22). All three label the name exactly "Host name", and the resolver
    and static-mapping sections around it are reproduced because the reader has
    to pick one field out of them -- a mock emitting only the wanted line would
    not exercise that at all.

    The trailing static-mapping tables are the empty form all three returned;
    none had a host-to-address mapping configured.
    """
    return "\n".join(
        [
            _dotted("Host name", state.hostname),
            _dotted("Default domain", "Domain name is not configured"),
            _dotted("Default domain list", "Domain Name List is not configured"),
            _dotted("Domain Name Lookup", "Enabled"),
            _dotted("Number of retries", "2"),
            _dotted("Retry timeout period", "3"),
            _dotted("Name servers (Preference order)", "10.1.5.1"),
            "",
            "Configured host name-to-address mapping:",
            "",
            " Host                                Addresses",
            "------------------------ ----------------------",
            "No host name is configured to IP address",
            "",
            " Host                   Total   Elapsed    Type        Addresses",
            "---------------------- -------  -------    ----        --------------",
            "No hostname is mapped to an IP address",
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
                _iface(state, p),
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
        rows.append([_iface(state, p), current, configured, tagging])
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
            [
                _iface(state, p),
                pvid,
                pvid,
                "Admit All",
                "Disable",
                "Disable",
                "Enable",
                0,
            ]
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
                _iface(state, nb.local_port),
                nb.rem_idx,
                _mac_text(nb.chassis) if nb.chassis else "",
                nb.port_id,
                nb.sys_name,
            ]
        )
    title = ["LLDP Remote Device Summary", "", "Local"]
    return "\n".join(title) + "\n" + _table(headers, widths, rows)


# --- show poe port info all -------------------------------------------------


def _poe_status_text(psim: PoeSim) -> str:
    """The ``Status`` column text a real switch prints for one PSE port.

    ``show poe port info all`` has NO admin column -- the reader infers admin
    state from this text (see ``protocols.cli.parse.parse_poe``: anything other
    than "Disabled" means admin-enabled), so an admin-OFF port MUST render as
    "Disabled" or the mock would report a PoE-disabled port as still enabled and
    hide a broken ``set_poe``. Fault detect codes (RFC3621 4=fault,
    6=otherFault) render as "Fault", which is what lets the CLI and SNMP faces
    agree about a faulted port instead of the CLI calling it "Searching".

    A just-re-enabled port still reports ``Disabled`` for one read, because that
    is what the hardware does (see ``PoeSim.cli_status_lag_reads``): this column
    is a detection state and lags the admin write. Rendering it consumes the lag,
    exactly as re-reading the table on the device eventually shows the new state.
    """
    if psim.cli_status_lag_reads > 0:
        psim.cli_status_lag_reads -= 1
        return "Disabled"
    if not psim.admin:
        return "Disabled"
    if psim.detect == 3:
        return "Delivering Power"
    if psim.detect in (4, 6):
        return "Fault"
    return "Searching"


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
        status = _poe_status_text(psim)
        rows.append(
            [
                _iface(state, p),
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


def render_port_description(state: VirtualSwitchState, iface: str) -> str:
    """``show port description <iface>``.

    Layout transcribed from live output on a GSM7252PS (10.1.5.22,
    2026-08-03)::

        Interface....... 1/0/8
        ifIndex......... 8
        Description.....
        MAC address..... E0:91:F5:0C:D6:DD
        Bit Offset Val.. 8

    An unset description prints the label with NOTHING after it -- which is why
    the parser maps an empty value to None rather than "". A port the switch
    does not have answers with the same rejection any unknown argument gets.
    """
    port = next(
        (p for p in _phys_ports(state) if _iface(state, p) == iface),
        None,
    )
    if port is None:
        return "% Invalid input detected at '^' marker."
    sim = state.ports[port]
    mac = ":".join(f"{b:02X}" for b in state.nsdp_mac)
    return "\n".join(
        [
            f"Interface....... {iface}",
            f"ifIndex......... {port}",
            f"Description..... {sim.description or ''}".rstrip(),
            f"MAC address..... {mac}",
            f"Bit Offset Val.. {port}",
        ]
    )
