"""Pure web-UI projection of ``VirtualSwitchState`` (render + apply).

The exact inverse of the Task-3 parsers and Task-4 form encoders: ``render_page``
turns device state into the documented HTML shape the parsers consume, and
``apply_form`` mutates the state from a POSTed form body. No network here — the
``VirtualHttpFace`` (Task 11) wraps these in an ``http.server`` handler.

The rendered HTML is deliberately minimal but carries every field the parsers
read, including a constant CSRF ``hash`` token on each writable page. Routing
(deciding whether a requested path is one a given model's ``http_spec``
actually advertises, and returning a 404-equivalent for anything else) is
Task 11's job at the I/O boundary; this module renders/applies whatever page
its caller already resolved against ``spec``.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..protocols.http.endpoints import HttpModelSpec
    from .state import PoeSim, VirtualSwitchState

_HASH = "virtualhash"
_DETECT_TEXT = {3: "Delivering", 1: "Searching", 2: "Disabled", 4: "Fault"}


def render_login(rand: str) -> str:
    return (
        f'<html><body><form>'
        f'<input type="hidden" id="rand" name="rand" value="{rand}">'
        f'<input type="hidden" name="hash" value="{_HASH}">'
        f"</form></body></html>"
    )


def _hash_input() -> str:
    return f'<input type="hidden" name="hash" value="{_HASH}">'


def render_page(
    state: VirtualSwitchState, spec: HttpModelSpec, path: str, form: dict[str, str]
) -> str:
    if path == spec.dashboard_path:
        return _render_dashboard(state)
    if path == spec.stats_path:
        return _render_stats(state)
    if path == spec.poe_status_path:
        return _render_poe_status(state)
    if path == spec.pvid_path:
        return _render_pvid(state)
    if path == spec.vlan_config_path:
        return _render_vlan_cfg(state)
    if path == spec.vlan_membership_path:
        vid = int(form.get("VLAN_ID", "1"))
        return _render_membership(state, vid)
    if path == spec.poe_config_path:
        return f"<html><body>{_hash_input()}</body></html>"
    return f"<html><body>OK{_hash_input()}</body></html>"


def _render_dashboard(state: VirtualSwitchState) -> str:
    rows = "".join(
        f'<tr class="portID"><td><input type="checkbox"></td>'
        f"<td>{p}</td>"
        f'<td>{("Up " + str(sim.speed) + "M") if sim.link else "Down"}</td>'
        f'<td>{"Enabled" if sim.admin else "Disabled"}</td>'
        f"<td>{sim.name}</td></tr>"
        for p, sim in sorted(state.ports.items())
    )
    return f"<html><body>{_hash_input()}<table>{rows}</table></body></html>"


def _render_stats(state: VirtualSwitchState) -> str:
    rows = "".join(
        f'<tr class="portID"><td>{p}</td>'
        f"<td>{sim.rx_octets or 0}</td><td>{sim.tx_octets or 0}</td>"
        f"<td>{sim.rx_errors or 0}</td></tr>"
        for p, sim in sorted(state.ports.items())
    )
    return f"<html><body><table>{rows}</table></body></html>"


def _render_poe_status(state: VirtualSwitchState) -> str:
    def _detect_text(psim: PoeSim) -> str:
        if not psim.admin:
            return "Disabled"
        return _DETECT_TEXT.get(psim.detect, "Disabled")

    rows = "".join(
        f'<tr class="portID"><td>{p}</td>'
        f"<td>{_detect_text(psim)}</td>"
        f"<td>{psim.power_mw}</td></tr>"
        for p, psim in sorted(state.poe.items())
    )
    return f"<html><body>{_hash_input()}<table>{rows}</table></body></html>"


def _render_pvid(state: VirtualSwitchState) -> str:
    rows = "".join(
        f'<tr class="portID"><td><input type="checkbox" name="port{p - 1}"></td>'
        f'<td sel="text">{p}<input type="hidden" value="1"></td>'
        f'<td sel="input">{state.pvids.get(p, 1)}</td></tr>'
        for p in sorted(state.ports)
    )
    return f"<html><body>{_hash_input()}<table>{rows}</table></body></html>"


def _render_vlan_cfg(state: VirtualSwitchState) -> str:
    boxes = "".join(
        f'<input type="checkbox" name="vlanck{i}" value="{vid}">'
        for i, vid in enumerate(sorted(state.vlans))
    )
    return f"<html><body>{_hash_input()}{boxes}</body></html>"


def _render_membership(state: VirtualSwitchState, vid: int) -> str:
    vsim = state.vlans.get(vid)
    port_count = max(state.ports) if state.ports else 0
    chars = []
    for p in range(1, port_count + 1):
        if vsim is None or p not in vsim.member:
            chars.append("3")
        elif p in vsim.untagged:
            chars.append("1")
        else:
            chars.append("2")
    hidden = "".join(chars)
    options = "".join(
        f'<option {"selected " if v == vid else ""}value="{v}">VLAN {v}</option>'
        for v in sorted(state.vlans)
    )
    return (
        f"<html><body><form>{_hash_input()}{options}"
        f'<input name="hiddenMem" id="hiddenMem" value="{hidden}" type="hidden">'
        f"</form></body></html>"
    )


def apply_form(
    state: VirtualSwitchState, spec: HttpModelSpec, path: str, form: dict[str, str]
) -> None:
    if path == spec.poe_config_path:
        _apply_poe(state, form)
    elif path == spec.pvid_path:
        _apply_pvid(state, form)
    elif path == spec.vlan_membership_path and "hiddenMem" in form:
        _apply_membership(state, form)
    elif path == spec.vlan_config_path:
        _apply_vlan_cfg(state, form)


def _apply_poe(state: VirtualSwitchState, form: dict[str, str]) -> None:
    if form.get("ACTION") == "Apply" and "portID" in form:
        port = int(form["portID"]) + 1
        if port in state.poe:
            on = form.get("ADMIN_MODE") == "1"
            state.poe[port].admin = on
            state.poe[port].detect = 3 if on else 1
    elif form.get("ACTION") == "Reset":
        for key in form:
            m = re.fullmatch(r"port(\d+)", key)
            if m:
                port = int(m.group(1)) + 1
                if port in state.poe:
                    state.poe[port].detect = 3 if state.poe[port].admin else 1


def _apply_pvid(state: VirtualSwitchState, form: dict[str, str]) -> None:
    vlan = int(form.get("pvid", "0"))
    if vlan <= 0:
        return
    for key in form:
        m = re.fullmatch(r"port(\d+)", key)
        if m:
            state.pvids[int(m.group(1)) + 1] = vlan


def _apply_membership(state: VirtualSwitchState, form: dict[str, str]) -> None:
    vid = int(form["VLAN_ID"])
    vsim = state.vlans.get(vid)
    if vsim is None:
        return
    hidden = form["hiddenMem"]
    member: set[int] = set()
    untagged: set[int] = set()
    for i, ch in enumerate(hidden):
        port = i + 1
        if ch == "1":
            member.add(port)
            untagged.add(port)
        elif ch == "2":
            member.add(port)
    vsim.member = member
    vsim.untagged = untagged


def _apply_vlan_cfg(state: VirtualSwitchState, form: dict[str, str]) -> None:
    from .state import VlanSim

    action = form.get("ACTION")
    if action == "Add" and "ADD_VLANID" in form:
        vid = int(form["ADD_VLANID"])
        state.vlans.setdefault(vid, VlanSim(name=""))
    elif action == "Delete":
        for key, val in form.items():
            if re.fullmatch(r"vlanck\d+", key):
                state.vlans.pop(int(val), None)
