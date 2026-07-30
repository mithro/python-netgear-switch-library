"""The managed FASTPATH "VLAN Membership" page, rendered from + applied to state.

Reproduces ``switching/dot1q/vlan_port_cfg.html`` (GET) and its
``..._rw.html`` form target (POST, used for BOTH a VLAN-select re-render and an
apply) as the real firmware serves them. Grounded in live captures taken
2026-07-30 from all four managed switches -- gsm7252ps 10.1.5.22, gsm7228ps
(S3300-52X) 10.1.5.11, m4300-24x 10.1.5.13 and m4300-16x 10.1.5.20:49152 -- which
are checked in as ``tests/fixtures/http/*vlan[Pp]ort[Cc]fg*.html``.

The behaviours below are reproduced BECAUSE hardware does them, and each one is
something a lenient mock would have hidden:

* **Two different views of the same VLAN.** ``hiddenTagged``/``hiddenUnTagged``
  are the CURRENT (operational) egress lists; ``hiddenMem`` and the port grid are
  the CONFIGURED participation. They genuinely differ -- see
  ``state.VlanSim.configured_only``, seeded from the real GSM7252PS.
* **``submt`` is the apply flag.** ``submt=0`` (what the VLAN ``<select>``'s
  ``screen_refresh()`` posts) re-renders WITHOUT applying; only ``submt=16``
  (``0x10``, what ``submitform()`` sets) writes. A mock that applied on every
  POST would let a broken reader silently corrupt VLANs and still pass.
* **The page shows whichever VLAN ``vlanId`` selected**, and an unknown VLAN
  falls back to the lowest -- so a reader that forgets to check which VLAN came
  back gets caught here instead of on hardware.
* **Two grid encodings, two index bases.** Older firmware (gsm7252ps) emits
  ``toggleImageFirst(this,<0-based slot>,...)`` + ``grey_[btu].gif``; newer
  (S3300/M4300) emits ``togImg(this,<1-based slot>,...)`` + ``switch_*.png``. Both
  are rendered, per model, from the seeded ``VlanMembershipPageSim.grid``.
* **LAG pseudo-interfaces occupy hiddenMem slots after the physical ports** (64
  on the gsm7252ps, 26 on the S3300, 128 on the M4300s) and are rendered in their
  own grid table. A writer that assumed ``slot == port - 1`` and truncated the
  string would drop them; here it cannot.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..protocols.http.parse import _FASTPATH_MEM_TO_MODE
from .web_gsm7228ps import _s3300_iface

if TYPE_CHECKING:
    from ..protocols.http.endpoints import HttpModelSpec
    from .state import VirtualSwitchState, VlanMembershipPageSim

# Wire code -> the grid-image token each firmware generation renders for it.
# Inverted from the parser's own map so the two cannot drift apart on the CODE,
# while the IMAGE NAMES are the device's (measured from the captures).
_MODE_TO_CODE = {mode: code for code, mode in _FASTPATH_MEM_TO_MODE.items()}
_GIF_IMG = {"1": "grey_t", "2": "grey_u", "3": "grey_b"}
_PNG_IMG = {"1": "tagged", "2": "untagged", "3": "blank"}

# ``submitform()`` in the firmware's rollover.js sets submt = 0x10 before
# submitting; anything else is a read-only re-render (``screen_refresh()``).
_APPLY = "16"


def _page_sim(state: VirtualSwitchState) -> VlanMembershipPageSim:
    page = state.vlan_membership_page
    if page is None:  # pragma: no cover - guarded by the caller's spec check
        raise ValueError(
            f"{state.model_key!r} has no measured vlan_membership_page geometry; "
            "seed one from a real capture rather than inventing a page"
        )
    return page


def _physical_ports(state: VirtualSwitchState) -> list[int]:
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    return [p for p in sorted(state.ports) if p <= port_count]


def _lag_base(state: VirtualSwitchState) -> int:
    """The 0-based ``hiddenMem`` slot where the LAG pseudo-interfaces start.

    It is the number of PHYSICAL ports the page renders -- NOT
    ``model.port_count``. Those differ: the registry gives the M4300-24X
    ``port_count=28`` while the real switch's grid renders 24 cells and puts
    lag 1 at slot 24 (its hiddenMem is 152 slots = 24 + 128). Using the registry
    count here would shift every LAG slot by four and make the mock disagree with
    the capture.
    """
    return len(_physical_ports(state))


def _esc(text: str, page: VlanMembershipPageSim) -> str:
    """HTML-entity-escape a ifName list the way the newer firmware does."""
    return text.replace("/", "&#x2F;") if page.escape else text


def _iface(state: VirtualSwitchState, port: int) -> str:
    """The ifName the model's grid uses for a physical port.

    The S3300's Smart firmware writes ``1/gN``/``1/xgN`` in the grid's ``aid``
    attribute (the same names its MAC table uses); every other model writes the
    FASTPATH ``1/0/N``. Both appear in the real captures.
    """
    from ..protocols.http.endpoints import HtmlDialect, http_spec
    from ..registry import get_model

    if http_spec(get_model(state.model_key)).html_dialect is HtmlDialect.S3300:
        return _s3300_iface(port)
    return f"1/0/{port}"


def _codes(state: VirtualSwitchState, vid: int) -> list[str]:
    """The full ``hiddenMem`` code list for ``vid``: one per slot.

    Physical ports come from the VLAN's CONFIGURED sets (``hiddenMem`` is the
    configured view); the LAG slots that follow are rendered Excluded unless the
    seed put a LAG ifIndex in the VLAN, in which case its position among the
    VLAN's LAG members selects the slot -- the same convention
    ``web_gsm7252ps.render_vlans`` uses for the ``lag N`` egress names.
    """
    from ..registry import get_model

    page = _page_sim(state)
    port_count = get_model(state.model_key).port_count
    vsim = state.vlans.get(vid)
    codes = [_MODE_TO_CODE[_FASTPATH_MEM_TO_MODE["3"]]] * page.slots
    if vsim is None:
        return codes
    for port in _physical_ports(state):
        if port not in vsim.configured:
            continue
        untagged = port in vsim.untagged or port in vsim.configured_only
        codes[port - 1] = "2" if untagged else "1"
    lags = [p for p in sorted(vsim.configured) if p > port_count]
    for i, lag in enumerate(lags):
        slot = _lag_base(state) + i
        if slot < page.slots:
            codes[slot] = "2" if lag in vsim.untagged else "1"
    return codes


def _iface_lists(state: VirtualSwitchState, vid: int) -> tuple[str, str]:
    """``(hiddenTagged, hiddenUnTagged)`` -- the CURRENT egress ifName lists.

    Built from ``member``/``untagged`` only, deliberately EXCLUDING
    ``configured_only``: that is precisely the divergence real firmware shows
    (see the module docstring). LAG members are rendered with the model's own LAG
    slot (``0/3/N`` or ``0/13/N``), which is what makes a parser that treats a
    bare ``\\d+/\\d+/\\d+`` as a physical port produce phantom ports here too.
    """
    from ..registry import get_model

    page = _page_sim(state)
    port_count = get_model(state.model_key).port_count
    vsim = state.vlans.get(vid)
    if vsim is None:
        return "", ""
    tagged: list[str] = []
    untagged: list[str] = []
    for port in _physical_ports(state):
        if port not in vsim.member:
            continue
        (untagged if port in vsim.untagged else tagged).append(_iface(state, port))
    lags = [p for p in sorted(vsim.member) if p > port_count]
    for i, lag in enumerate(lags, start=1):
        name = f"0/{page.lag_slot}/{i}"
        (untagged if lag in vsim.untagged else tagged).append(name)
    tail = "," if page.trailing_comma else ""
    return (
        _esc(",".join(tagged) + (tail if tagged else ""), page),
        _esc(",".join(untagged) + (tail if untagged else ""), page),
    )


def _grid_gif(state: VirtualSwitchState, codes: list[str]) -> str:
    """The older gsm7252ps grid: ``toggleImageFirst`` + ``grey_[btu].gif`` cells,
    with the physical unit table and the LAG table each labelled by their first
    row cell ("Port" / "LAG") -- which is what tells them apart."""

    page = _page_sim(state)
    base = _lag_base(state)

    def cells(items: list[tuple[int, int]], unit: str) -> str:
        return "".join(
            f'<td><a style="cursor: pointer" onClick="toggleImageFirst('
            f"this,{slot},0,'img_unit{unit}',{intf});return false\" >"
            f'<img src="/base/images/{_GIF_IMG[codes[slot]]}.gif" name="imx" '
            f'id="{intf}"></a></td>\n'
            for slot, intf in items
        )

    ports = [(p - 1, p) for p in _physical_ports(state)]
    # Real firmware numbers LAG grid cells with their internal interface ids
    # (418..481 on the captured GSM7252PS), NOT 1..64 -- so the mock does too.
    lag_id_base = 418
    lags = [(base + i, lag_id_base + i) for i in range(page.slots - base)]
    return (
        '<table class="tableStyle" id="unit1tb"><tbody>\n'
        '<tr class="font10Bold messageTableWhite">\n<td >Port</td>\n'
        + "".join(f"<td>{p}</td>\n" for _s, p in ports)
        + '</tr>\n<tr class="messageTableGrey">\n<td>&nbsp;</td>\n'
        + cells(ports, "1")
        + "</tr>\n</tbody></table>\n"
        + '<table class="tableStyle" id="unit25tb"><tbody>\n'
        '<tr class="font10Bold messageTableWhite">\n<td >LAG</td>\n'
        + "".join(f"<td>{i + 1}</td>\n" for i in range(len(lags)))
        + '</tr>\n<tr class="messageTableGrey">\n<td>&nbsp;</td>\n'
        + cells(lags, "25")
        + "</tr>\n</tbody></table>\n"
    )


def _grid_png(state: VirtualSwitchState, codes: list[str]) -> str:
    """The newer S3300/M4300 grid: ``aid='port-<ifName>'`` + ``togImg`` cells with
    a 1-BASED hiddenMem index, and ``switch_<state>[_bottom]_inactive.png``
    images (``_bottom`` on the even ports, which the real page draws on the lower
    row of the port panel)."""

    page = _page_sim(state)
    base = _lag_base(state)
    out = [
        "<table class='tableStyle tableWidthAuto' id='unit1tb'>\n"
        "<tr class='fontTableTitle' id='unit1_view'>\n"
        "<td class='intStyle'>Ports</td>\n"
    ]
    for port in _physical_ports(state):
        bottom = "_bottom" if port % 2 == 0 else ""
        out.append(
            f"<td><div class='titleUp'>{port}</div>\n<div class='panel'>"
            f"<a href='javascript:void(0)'><img class='panPad' "
            f"aid='port-{_iface(state, port)}' "
            f"src='/base/images/switch_{_PNG_IMG[codes[port - 1]]}{bottom}"
            f"_inactive.png' name='imx' onclick='onClick(this); "
            f'togImg(this,{port},0,"hiddenMem"); enablebtn(1);\'/></a></div></td>\n'
        )
    out.append("</tr>\n</table>\n")
    out.append(
        "<table class='tableStyle tableWidthAuto' id='unit2tb'>\n"
        "<tr class='fontTableTitle'>\n<td class='intStyle'>LAG</td>\n"
    )
    for i in range(page.slots - base):
        slot1 = base + i + 1
        out.append(
            f"<td><div class='titleUp'>{i + 1}</div>\n<div class='panel'>"
            f"<a href='javascript:void(0)'><img class='panPad' aid='lag {i + 1}' "
            f"src='/base/images/switch_{_PNG_IMG[codes[slot1 - 1]]}_inactive.png' "
            f"name='imx' onclick='onClick(this); "
            f'togImg(this,{slot1},0,"hiddenMem"); enablebtn(1);\'/></a></div></td>\n'
        )
    out.append("</tr>\n</table>\n")
    return "".join(out)


def _shown_vlan(state: VirtualSwitchState, form: dict[str, str]) -> int:
    """Which VLAN this render is for.

    A ``vlanId`` naming a VLAN the switch does not have falls back to the lowest
    one, exactly as the firmware's ``<select>`` does -- so the reader's
    "is this the VLAN I asked for?" guard is exercised rather than bypassed.
    """
    requested = form.get("vlanId", "")
    if requested.isdigit() and int(requested) in state.vlans:
        return int(requested)
    return min(state.vlans, default=1)


def refusal(state: VirtualSwitchState, form: dict[str, str]) -> str | None:
    """The ``err_msg`` this apply would be refused with, or ``None`` if allowed.

    Reproduces the M4300 firmware's precondition: a port whose ``switchport mode``
    is access or trunk cannot be given explicit VLAN membership, and the web UI
    reports that as ``err_flag=1`` + ``err_msg`` on an otherwise-200 page rather
    than an HTTP error. Quoted verbatim from 10.1.5.13 -- see
    ``VirtualSwitchState.vlan_membership_locked_ports``.
    """
    if form.get("submt") != _APPLY or not state.vlan_membership_locked_ports:
        return None
    vid = _shown_vlan(state, form)
    codes = [c for c in form.get("hiddenMem", "").split(",") if c != ""]
    vsim = state.vlans.get(vid)
    for port in state.vlan_membership_locked_ports:
        code = codes[port - 1] if 0 < port <= len(codes) else None
        mode = _FASTPATH_MEM_TO_MODE.get(code or "")
        if mode is None:
            continue
        if vsim is None or port not in vsim.configured:
            was = _FASTPATH_MEM_TO_MODE["3"]
        elif port in vsim.untagged or port in vsim.configured_only:
            was = _FASTPATH_MEM_TO_MODE["2"]
        else:
            was = _FASTPATH_MEM_TO_MODE["1"]
        if mode is not was:
            return f"Unable to set VLAN membership for VLAN ( {vid} )"
    return None


def render_membership(
    state: VirtualSwitchState,
    spec: HttpModelSpec,
    form: dict[str, str],
    *,
    err_msg: str = "",
) -> str:
    """Render the VLAN Membership page for the VLAN ``form`` selected."""
    page = _page_sim(state)
    vid = _shown_vlan(state, form)
    codes = _codes(state, vid)
    hidden_mem = ",".join(codes) + ("," if page.trailing_comma else "")
    tagged, untagged = _iface_lists(state, vid)
    vsim = state.vlans.get(vid)
    options = "".join(
        f'<OPTION class="selectfield" value="{v}"'
        f"{' SELECTED' if v == vid else ''}>{v}\n"
        for v in sorted(state.vlans)
    )
    csrf = (
        '<INPUT TYPE="hidden" NAME="CSRFToken" ID="CSRFToken" VALUE="virtualcsrf">\n'
        if page.csrf
        else ""
    )
    grid = _grid_gif(state, codes) if page.grid == "gif" else _grid_png(state, codes)
    action = spec.vlan_membership_post_path or ""
    return (
        '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">\n'
        "<HTML><HEAD><TITLE>VLAN Configuration</TITLE></HEAD>\n"
        "<body onLoad='check_error()'>\n"
        f'<FORM method="post" ACTION="{action}">\n'
        '<table class="tableStyle" id="tbl1">\n<tr><td>VLAN ID</td><td>\n'
        f'<SELECT name="vlanId" class="select" onChange="screen_refresh()">\n'
        f"{options}</SELECT></td>\n"
        '<td>Group Operation</td><td><SELECT name="select" class="select" '
        'id="groupOpera" onChange="imgtag(\'groupOpera\');enableImage()">\n'
        '<OPTION value="UntagAll" selected="selected" >Untag All</option>\n'
        '<OPTION value="TagAll" >Tag All</option>\n'
        '<OPTION value="RemoveAll" >Remove All</option>\n'
        "</SELECT></td></tr>\n"
        f'<tr><td>VLAN Name</td><td><INPUT name="vlan_name" type="text" '
        f'class="inputDisabled" READONLY VALUE="{vsim.name if vsim else ""}">'
        "</td></tr>\n"
        f'<tr><td>VLAN Type</td><td><INPUT name="vlan_type" type="text" '
        f'class="inputDisabled" READONLY '
        f'VALUE="{"Default" if vid == 1 else "Static"}"></td></tr>\n'
        f"</table>\n{grid}"
        f'<INPUT TYPE="hidden" NAME="err_flag" VALUE="{"1" if err_msg else "0"}">\n'
        f'<INPUT TYPE="hidden" NAME="err_msg" VALUE="{err_msg}">\n'
        f'<INPUT TYPE="hidden" NAME="hiddenTagged" id="hiddenTagged" '
        f'VALUE="{tagged}">\n'
        f'<INPUT TYPE="hidden" NAME="hiddenUnTagged" id="hiddenUnTagged" '
        f'VALUE="{untagged}">\n'
        f'<INPUT TYPE="hidden" NAME="hiddenMem" id="hiddenMem" '
        f'VALUE="{hidden_mem}">\n'
        f'<INPUT TYPE="hidden" id="submt" NAME="submt" VALUE="0">\n'
        f'<INPUT TYPE="hidden" id="cncel" NAME="cncel" VALUE="">\n'
        f'<INPUT TYPE="hidden" id="port_id" NAME="port_id" VALUE="0">\n'
        f'<INPUT TYPE="hidden" id="click_id" NAME="click_id" VALUE="0">\n'
        f'<INPUT TYPE="hidden" NAME="selectedPorts" id="selectedPorts" VALUE="">\n'
        f'<INPUT TYPE="hidden" NAME="ignoreMouseUp" id="ignoreMouseUp" VALUE="">\n'
        f'<INPUT TYPE="hidden" NAME="mouseX" id="mouseX" VALUE="">\n'
        f'<INPUT TYPE="hidden" NAME="mouseY" id="mouseY" VALUE="">\n'
        f'<INPUT TYPE="hidden" NAME="processedClick" id="processedClick" VALUE="">\n'
        f"{csrf}</FORM></body></HTML>\n"
    )


def apply_membership(state: VirtualSwitchState, form: dict[str, str]) -> None:
    """Apply a membership POST -- but ONLY when ``submt`` is the apply flag.

    ``submt=0`` is the VLAN ``<select>``'s own re-render POST and must not
    mutate anything: the reader relies on that to page through VLANs, and a mock
    that wrote on every POST would let a reader silently rewrite every VLAN it
    read. Confirmed on hardware, by reading a VLAN twice and diffing the two
    responses (byte-identical) on all four switches.

    A port set Excluded loses its CURRENT membership too; a port set
    tagged/untagged becomes a current member. ``configured_only`` is cleared for
    a port the caller explicitly set, because the caller has now stated that
    port's participation outright.
    """
    from ..registry import get_model

    if form.get("submt") != _APPLY or refusal(state, form) is not None:
        # A refused apply changes NOTHING on real hardware (the page re-renders
        # the unchanged VLAN alongside err_flag=1), so the mock must not mutate
        # either -- otherwise a writer that ignored err_flag would still "pass".
        return
    page = state.vlan_membership_page
    if page is None:  # pragma: no cover - the face 404s such a model first
        return
    vid = _shown_vlan(state, form)
    vsim = state.vlans.get(vid)
    if vsim is None:
        return
    codes = [c for c in form.get("hiddenMem", "").split(",") if c != ""]
    port_count = get_model(state.model_key).port_count
    for port in _physical_ports(state):
        code = codes[port - 1] if port - 1 < len(codes) else None
        mode = _FASTPATH_MEM_TO_MODE.get(code or "")
        if mode is None:
            continue
        vsim.configured_only.discard(port)
        if mode.value == "excluded":
            # Only participation is dropped. The device's UNTAGGED bitmap is a
            # separate axis and keeps its bit for a non-member port: real
            # firmware's ``show vlan`` prints ``Tagging: Untagged`` on every
            # excluded port, and the real GSM7252PS SNMP walk lists untagged
            # ports that are not egress members at all (see _GSM7252PS_VLANS).
            # Clearing it here would make the mock destroy state the web form
            # cannot even express.
            vsim.member.discard(port)
        else:
            vsim.member.add(port)
            if mode.value == "untagged":
                vsim.untagged.add(port)
            else:
                vsim.untagged.discard(port)
    # LAG slots: the mock models LAGs only as ifIndexes above the physical port
    # count, so an apply that clears a LAG slot removes that LAG from the VLAN.
    lags = [p for p in sorted(vsim.configured) if p > port_count]
    base = _lag_base(state)
    for i, lag in enumerate(lags):
        slot = base + i
        code = codes[slot] if slot < len(codes) else None
        mode = _FASTPATH_MEM_TO_MODE.get(code or "")
        if mode is not None and mode.value == "excluded":
            vsim.member.discard(lag)
            vsim.configured_only.discard(lag)
