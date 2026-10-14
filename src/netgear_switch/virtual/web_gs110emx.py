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


def _speed_mbps_to_text(mbps: int) -> str:
    """State ``speed`` (Mbps) -> the port_settings.html speed text. Inverse of
    ``parse._speed_text_to_mbps`` so a round trip (state -> HTTP page -> reader)
    reproduces the state value, and so HTTP ``speed_mbps`` equals the NSDP
    backend's for the same state (the HTTP<->NSDP cross-verification)."""
    if mbps >= 1000 and mbps % 1000 == 0:
        return f"{mbps // 1000}G Full"
    return f"{mbps}M Full"


def render_port_settings(state: VirtualSwitchState, token: str) -> str:
    """GET port_settings.html -- port link/speed/description from state, so the
    HTTP port-status read matches the NSDP PORT_STATUS read on this switch."""
    rows = "".join(
        _t.PORT_SETTINGS_ROW.replace("__PORT__", str(port))
        .replace("__DESC__", sim.description or sim.name or "")
        .replace("__LINK__", "Up" if sim.link else "Down")
        # The mode cell IS the admin state on this model (its Physical Mode
        # select's only "off" option is Disable) -- see parse_gs110emx_port_status.
        .replace("__MODE__", "Auto" if sim.admin else "Disable")
        .replace("__PHYSMODE__", "1" if sim.admin else "6")
        .replace(
            "__SPEED__",
            _speed_mbps_to_text(sim.speed) if sim.link else "No Speed",
        )
        for port, sim in sorted(state.ports.items())
    )
    return (
        _t.PORT_SETTINGS_PREFIX.replace("__GAMBIT__", token)
        + rows
        + _t.PORT_SETTINGS_SUFFIX
    )


# The GS110EMX's PORT_CTRL_MODE wire values (from the firmware's own
# function.js: PHYSICAL_MODE 1 "Auto" -> 1, PHYSICAL_MODE 6 "Disable" -> 3).
_EMX_CTRL_MODE_DISABLE = "3"


def apply_port_settings(state: VirtualSwitchState, form: dict[str, str]) -> str:
    """Apply a ``port_settings.html`` POST; returns the page's reply BODY.

    The real page answers an AJAX apply with a bare ``SUCCESS`` (its own JS
    checks ``resText != "SUCCESS"``), not a re-rendered page. ``PORT_NO`` is the
    SEMICOLON-TERMINATED selected-port list its ``saveSelectedPorts()`` builds
    (``"3;"``), and a body that sends a bare number selects nothing and applies
    nothing -- reproduced here, because that is exactly the mistake that a
    lenient mock would have hidden (it was caught on real hardware instead).
    """
    if form.get("ACTION") != "apply":
        return "SUCCESS"
    raw = form.get("PORT_NO", "")
    if not raw.endswith(";"):
        return "SUCCESS"  # nothing selected -- the switch applies nothing
    enabled = form.get("PORT_CTRL_MODE") != _EMX_CTRL_MODE_DISABLE
    for part in raw.split(";"):
        if not part.strip().isdigit():
            continue
        port = int(part)
        if port in state.ports:
            state.ports[port].admin = enabled
    return "SUCCESS"


def render_pvid(state: VirtualSwitchState, token: str, err_msg: str = "") -> str:
    """vlan_pvidsetting.html -- per-port PVID from state, byte-identical to the
    real page (``gs110emx_fw1028_pvid.html``) for the same values."""
    rows = "".join(
        _t.PVID_ROW.replace("__PORT__", str(port)).replace("__PVID__", str(pvid))
        for port, pvid in sorted(state.pvids.items())
    )
    return (
        _t.PVID_PREFIX.replace("__GAMBIT__", token)
        + rows
        + _t.PVID_SUFFIX.replace("__ERRMSG__", err_msg)
    )


def apply_pvid(state: VirtualSwitchState, token: str, form: dict[str, str]) -> str:
    """Apply a ``vlan_pvidsetting.html`` POST; returns the re-rendered page.

    MEASURED 2026-10-14 on gs110emx1 (10.1.5.25, firmware 1.0.2.8), on
    link-down ports 2 and 3 with throwaway VLAN 4001:

    * ``PORT_NO=2;  PORT_PVID=1``    -> applied, ``errMsg`` empty.
    * ``PORT_NO=2   PORT_PVID=4001`` -> applied as well. Unlike
      ``port_settings.html`` (see ``apply_port_settings``), this page does NOT
      need the trailing ``;`` its own ``saveSelectedPorts()`` appends.
    * ``PORT_NO=3;  PORT_PVID=4001`` with port 3 outside VLAN 4001 -> nothing
      changes, ``errMsg`` = ``Port 3 is not a member of VLAN 4001!``.
    * ``PORT_NO=2;  PORT_PVID=4094`` with no VLAN 4094 -> nothing changes,
      ``errMsg`` = ``VLAN 4094 does not exist.``.

    Only single-port requests were measured. A list naming several ports is
    applied port by port here because that is what the field is for, but its
    behaviour on a partial refusal is NOT known -- the library never sends one.
    """
    ports = [int(p) for p in form.get("PORT_NO", "").split(";") if p.strip().isdigit()]
    pvid_text = form.get("PORT_PVID", "")
    if not ports or not pvid_text.isdigit():
        return render_pvid(state, token)
    vid = int(pvid_text)
    if vid not in state.vlans:
        return render_pvid(state, token, f"VLAN {vid} does not exist.")
    for port in ports:
        if port not in state.vlans[vid].member:
            return render_pvid(
                state, token, f"Port {port} is not a member of VLAN {vid}!"
            )
    for port in ports:
        if port in state.pvids:
            state.pvids[port] = vid
    return render_pvid(state, token)


def render_cf8021q(state: VirtualSwitchState, token: str) -> str:
    """GET Cf8021q.html -- the VLAN list (with member ports) from state. The
    reader only scrapes the VID column (``parse_gs110emx_vlan_ids``); the member
    list is rendered for fidelity."""
    rows = "".join(
        _t.CF8021Q_ROW.replace("__VID__", str(vid)).replace(
            "__MEMBERS__", " ".join(str(p) for p in sorted(vsim.member)) + " "
        )
        for vid, vsim in sorted(state.vlans.items())
    )
    return _t.CF8021Q_PREFIX.replace("__GAMBIT__", token) + rows + _t.CF8021Q_SUFFIX


# hiddenMem wire code -> the CSS class the page paints that port with.
_MEM_IMAGE = {"1": "untImg", "2": "tagImg", "3": "remImg"}


def _membership_codes(state: VirtualSwitchState, vid: int) -> str:
    """``hiddenMem`` for ``vid``: one code per port, 1=untagged, 2=tagged,
    3=excluded. A VLAN the switch does not have reads as all-excluded, which is
    what the real page renders for one (see ``handle_vlan_membership``)."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    vsim = state.vlans.get(vid)
    codes = []
    for port in range(1, port_count + 1):
        if vsim is not None and port in vsim.untagged:
            codes.append("1")
        elif vsim is not None and port in vsim.member:
            codes.append("2")
        else:
            codes.append("3")
    return "".join(codes)


def render_vlan_membership(
    state: VirtualSwitchState, token: str, shown_vid: int, err_msg: str = ""
) -> str:
    """One vlanMembership.html page, rendering ``shown_vid``.

    Byte-identical to the real page (``gs110emx_fw1028_vlanmembership_vlan*.html``)
    for the same values: the VLAN ``<option>`` list, the hidden ``vlanIdSel``
    naming the VLAN shown (the page marks no ``<option selected>``), one
    ``portImage`` per port, the ``hiddenMem`` codes, and ``errMsg``. The wire
    codes are the SAME scheme gs305ep's 8021qMembe.cgi uses, so
    ``parse.parse_membership`` reads it back.
    """
    codes = _membership_codes(state, shown_vid)
    options = "".join(
        f'<option value = "{vid}">{vid} </option>\n' for vid in sorted(state.vlans)
    )
    images = "".join(
        f"<div class='portMember margin'><span class='portword'>{port}</span>"
        f"<div class='panels'><div class='portImage {_MEM_IMAGE[code]}'></div>"
        "</div></div>\n"
        for port, code in enumerate(codes, start=1)
    )
    return (
        _t.VLANMEM_PAGE.replace("__GAMBIT__", token)
        .replace("__VLAN_OPTIONS__", options)
        .replace("__VLAN_SHOWN__", str(shown_vid))
        .replace("__PORT_IMAGES__", images)
        .replace("__HIDDENMEM__", codes)
        .replace("__ERRMSG__", err_msg)
    )


def handle_vlan_membership(
    state: VirtualSwitchState, token: str, form: dict[str, str]
) -> str:
    """GET or POST vlanMembership.html; returns the reply BODY.

    Every branch is MEASURED, 2026-10-14, firmware 1.0.2.8 -- the request rule
    on all three of gs110emx1/2/3 (10.1.5.25-27), the apply and its refusal on
    gs110emx1 against throwaway VLAN 4001 and link-down port 2:

    * GET -> the FIRST VLAN's page, always; a select is not remembered.
    * ``vlanIdSel`` absent, empty or ``0`` -> a 0-byte body.
    * ``vlanIdSel`` != ``VLAN_ID`` -> ``VLAN_ID``'s page. This is the browser's
      dropdown change, which posts the whole form: a ``hiddenMem`` riding along
      is IGNORED (VLAN 1's ``1111121122`` posted at VLAN 4001 left 4001 at
      ``3333333333``). A VLAN the switch does not have (4094) still renders, as
      all-excluded, with ``vlanIdSel`` echoing the request.
    * ``vlanIdSel`` == ``VLAN_ID`` -> the Apply (``ACTION`` stays empty either
      way, so it does not distinguish the two). With no ``hiddenMem`` there is
      nothing to apply and the reply is a 0-byte body -- the shape the library
      used to send as a "select" (issue #16).
    * An apply that would EXCLUDE a port from the VLAN its PVID names changes
      nothing and re-renders the page with ``errMsg`` set; making that port
      tagged instead is accepted.

    An apply changes that VLAN only: no other VLAN's membership and no PVID
    moved when port 2 went excluded -> tagged -> untagged in VLAN 4001.
    """
    if "VLAN_ID" not in form:
        return render_vlan_membership(state, token, min(state.vlans))
    vid_text, shown = form["VLAN_ID"], form.get("vlanIdSel", "")
    if not shown.isdigit() or int(shown) == 0:
        return ""
    vid = int(vid_text)
    if shown != vid_text:
        return render_vlan_membership(state, token, vid)
    hidden = form.get("hiddenMem")
    if hidden is None:
        return ""
    current = _membership_codes(state, vid)
    if (
        vid not in state.vlans
        or len(hidden) != len(current)
        or set(hidden) - set(_MEM_IMAGE)
    ):
        # NOT measured: an apply naming a VLAN the switch lacks, or a hiddenMem
        # of the wrong length / with an unknown code. Refused rather than
        # guessed at, so a writer that sends one cannot pass here by accident.
        return ""
    for port, code in enumerate(hidden, start=1):
        if code == "3" and state.pvids.get(port) == vid:
            return render_vlan_membership(
                state,
                token,
                vid,
                f"You can not remove port {port} from this VLAN. "
                "Change its PVID first!",
            )
    vsim = state.vlans[vid]
    for port, code in enumerate(hidden, start=1):
        vsim.member.discard(port)
        vsim.untagged.discard(port)
        if code != "3":
            vsim.member.add(port)
        if code == "1":
            vsim.untagged.add(port)
    return render_vlan_membership(state, token, vid)


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
