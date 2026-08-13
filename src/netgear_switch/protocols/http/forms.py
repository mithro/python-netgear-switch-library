"""Pure (I/O-free) web-UI write-form encoders.

Field names/values are GROUNDED against ``py_netgear_plus`` GS30xSeries
``get_switch_poe_port_data``/``get_power_cycle_poe_port_data`` and
``rcfiles/bin/netgear-smp-vlan`` (8021q/PVID forms). Each op requires the
page's CSRF ``hash`` (scraped just before the POST by the writer).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...models import VlanMode

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from .types import FastpathMembership, XuiFormPage, XuiListPage, XuiRow

_WIRE = {VlanMode.UNTAGGED: "1", VlanMode.TAGGED: "2", VlanMode.EXCLUDED: "3"}


def poe_apply_form(
    *, port: int, on: bool, is_epx: bool, csrf_hash: str
) -> dict[str, str]:
    return {
        "ACTION": "Apply",
        "portID": str(port - 1),
        "ADMIN_MODE": "1" if on else "0",
        "PORT_PRIO": "0",
        "POW_MOD": "3",
        "POW_LIMT_TYP": "2" if is_epx else "0",
        "DETEC_TYP": "2",
        "DISCONNECT_TYP": "2",
        "hash": csrf_hash,
    }


def poe_reset_form(*, port: int, csrf_hash: str) -> dict[str, str]:
    return {"ACTION": "Reset", f"port{port - 1}": "checked", "hash": csrf_hash}


def pvid_form(*, port: int, vlan: int, csrf_hash: str) -> dict[str, str]:
    return {f"port{port - 1}": "checked", "pvid": str(vlan), "hash": csrf_hash}


def membership_hidden_mem(states: Mapping[int, VlanMode], port_count: int) -> str:
    return "".join(
        _WIRE[states.get(p, VlanMode.EXCLUDED)] for p in range(1, port_count + 1)
    )


def membership_form(*, vlan: int, hidden_mem: str, csrf_hash: str) -> dict[str, str]:
    return {"VLAN_ID": str(vlan), "hiddenMem": hidden_mem, "hash": csrf_hash}


# FASTPATH VLAN Membership (switching/dot1q/vlan_port_cfg_rw.html) submit flag.
# The firmware's own rollover.js sets it from JavaScript:
#   function submitform() { ... elements['submt'].value = 0x10; ... form.submit() }
# i.e. the DECIMAL string "16" on the wire (JS stringifies the number). Leaving it
# at "0" is what the VLAN <select>'s onChange handler (screen_refresh()) posts, and
# that is a pure re-render -- which is exactly why the same endpoint can be used to
# READ another VLAN's membership without applying anything.
_FASTPATH_MEM_APPLY = "16"
_FASTPATH_MEM_NOOP = "0"


def fastpath_membership_form(
    page: FastpathMembership,
    *,
    vlan: int,
    hidden_mem: str | None = None,
    apply: bool = False,
) -> dict[str, str]:
    """The POST body for the FASTPATH VLAN Membership page.

    Starts from ``page.fields`` -- every field the device itself rendered,
    verbatim -- so nothing the browser sends is dropped (the M4300-16X rejects a
    POST that omits its per-page ``CSRFToken`` with ``403 Forbidden``) and nothing
    is invented. Only the four fields the browser's own handlers touch are
    overridden:

    * ``vlanId``  -- which VLAN to show/apply (the ``<select>``'s value).
    * ``hiddenTagged``/``hiddenUnTagged`` -- CLEARED, exactly as the firmware's
      ``screen_refresh()`` and ``resethidden()`` do before submitting. They are
      OUTPUT fields (the device re-renders them); echoing stale values back is not
      what the browser does.
    * ``submt`` -- ``"16"`` to apply, ``"0"`` for a read-only re-render.

    ``hidden_mem`` overrides the membership codes (use
    ``parse.fastpath_hidden_mem_with``); ``None`` keeps what the page rendered,
    which is required for a read (posting a DIFFERENT VLAN's codes with
    ``submt=0`` is precisely what the browser does when you pick another VLAN,
    and the firmware ignores them).
    """
    body = dict(page.fields)
    body["vlanId"] = str(vlan)
    body["hiddenTagged"] = ""
    body["hiddenUnTagged"] = ""
    body["submt"] = _FASTPATH_MEM_APPLY if apply else _FASTPATH_MEM_NOOP
    if hidden_mem is not None:
        body["hiddenMem"] = hidden_mem
    return body


# FASTPATH XUI apply flag. The firmware publishes it itself, in
# ``/scripts/_xeobj_jsvars.js``:
#     var xui_operation_submit = 8;
#     var xui_operation_reload = 1;
#     var xui_operation_redirect = 2;
# and every page's per-button metadata names it (``xeData.xt_2_1_2 = "8"`` for
# APPLY on portsConfiguration, ``xt_2_1_3 = "8"`` for RESET on
# poeInterfaceConfiguration, ``xt_3_1_1 = "8"`` for APPLY on ipConfiguration and
# mgmtVlanIpv4Configuration). ``onclickSubmit`` writes it into the form's
# ``submit_flag`` before submitting. Fetched live from 10.1.5.22 on 2026-07-30 --
# NOT the same flag as the VLAN-membership page's separate ``submt`` field.
XUI_OPERATION_SUBMIT = "8"
XUI_OPERATION_RELOAD = "1"


def xui_row_apply_form(
    page: XuiListPage,
    row: XuiRow,
    changes: Mapping[str, str],
    *,
    button: str,
    omit: Collection[str] = (),
) -> dict[str, str]:
    """The POST body that applies ``changes`` to exactly ONE row of an XUI list.

    Only that row's fields are sent (plus its ``gecb`` checkbox, the page's
    ``tokens``, its list-navigation block, the form's redirection block and the
    clicked button). That is deliberately NARROWER than a browser, which submits
    every row's hidden inputs and lets the firmware apply only the checked ones
    -- and it is narrower for a safety reason, not a convenience one: a body that
    never mentions the other 51 ports cannot change them even if a firmware
    ignored the checkboxes. LIVE-PROVEN on all four managed switches 2026-07-30:
    after this exact body, re-reading the whole table showed the target row's
    cell changed and EVERY other cell of every other row byte-identical.

    ``page.nav`` IS sent, and that is not decoration -- it is the difference
    between a write that lands and one the firmware refuses. LIVE 2026-07-30/31
    on gsm7252ps 10.1.5.22, port 1/0/35 (link-down, undescribed), the PoE apply
    answered HTTP 200 + ``err_flag=1`` with one
    ``Error! Failed to Set '<column>' with '<value>'`` line per read-write column
    -- even for a body that changed nothing -- until the page's own
    ``urlListUnit`` field rode along. Adding ``v_1_1_1`` alone, or ``v_1_3_1``
    alone (the page aliases them: ``xeData["xalias_urlListUnit"] =
    "1_1_1|1_3_1|3_1_1|3_4_1"``), made the identical write succeed; adding only
    the ``v_1_1_2`` type filter did NOT. See ``XuiListPage.nav``.

    ``changes`` is keyed by bare column (``"v_1_2_6"``); the row's own
    ``<unit>.<row0>.<count>.`` prefix is prepended here so a caller can never
    address the wrong row. A column the row does not render raises rather than
    being silently added -- that would be writing a field the device never
    offered.

    ``omit`` drops the named bare columns from this row's echoed fields, for the
    columns the clicked BUTTON disables. These pages carry per-button shed lists
    in their own metadata -- ``xeData.xa_<button>[14]`` is the "disable" set, and
    ``xuiShed(2, ...)`` sets ``disabled=true`` on each, so a browser never
    submits them for that button. A column the row does not render is ignored
    (models differ in which columns exist), because ``omit`` says "do not send
    this", not "this must be here".
    """
    body = dict(page.tokens)
    body.update(page.nav)
    dropped = {row.prefix + column for column in omit}
    body.update({k: v for k, v in row.fields.items() if k not in dropped})
    for column, value in changes.items():
        name = row.prefix + column
        if name not in row.fields:
            raise KeyError(
                f"row {row.prefix!r} does not render column {column!r} "
                f"(it has {sorted(k[len(row.prefix) :] for k in row.fields)})"
            )
        body[name] = value
    if row.checkbox is not None:
        body[row.checkbox] = "on"
    body.update(page.hidden)
    body["submit_flag"] = XUI_OPERATION_SUBMIT
    body["err_flag"] = "0"
    body["err_msg"] = ""
    body[button] = page.buttons[button]
    return body


def xui_form_apply_form(
    page: XuiFormPage, changes: Mapping[str, str], *, button: str
) -> dict[str, str]:
    """The POST body that applies ``changes`` to an XUI *detail* page.

    Starts from every field the device rendered -- so the M4300-16X's per-page
    ``CSRFToken`` (whose absence it answers with ``403 Forbidden``) rides along
    without this builder having to know about it -- and overrides only the named
    fields. An unknown field raises rather than being invented.
    """
    body = dict(page.fields)
    for name, value in changes.items():
        if name not in page.fields:
            raise KeyError(
                f"page {page.action!r} does not render field {name!r} "
                f"(it has {sorted(page.fields)})"
            )
        body[name] = value
    body.update(page.hidden)
    body["submit_flag"] = XUI_OPERATION_SUBMIT
    body["err_flag"] = "0"
    body["err_msg"] = ""
    body[button] = page.buttons[button]
    return body


# GS110EMX ``port_settings.html`` admin mode. The page has no separate
# enable/disable control: its "Physical Mode" select is
# ``0=(blank) 1=Auto 6=Disable``, and its own ``sendPortStatusForm()`` translates
# that selection into the triple actually POSTed --
#     PHYSICAL_MODE 1 -> PORT_CTRL_MODE=1, PORT_CTRL_DUPLEX=0, PORT_CTRL_SPEED=0
#     PHYSICAL_MODE 6 -> PORT_CTRL_MODE=3, PORT_CTRL_DUPLEX=0, PORT_CTRL_SPEED=0
# -- so "disabled" is PORT_CTRL_MODE 3 and "enabled (auto)" is 1. Harvested from
# the firmware's own /function.js on a live GS110EMX (10.1.5.25, 2026-07-31).
_EMX_CTRL_MODE_AUTO = "1"
_EMX_CTRL_MODE_DISABLE = "3"


def gs110emx_port_admin_form(
    *, port: int, enabled: bool, flow_control_mode: str
) -> dict[str, str]:
    """The GS110EMX port-admin POST body (the ``Gambit`` token is added by the
    transport, exactly as it is for every other request on this model).

    ``flow_control_mode`` is echoed from the port's OWN row rather than defaulted
    -- the page always sends it, so omitting it (or guessing) would rewrite the
    port's flow control as a side effect of an admin-mode change.
    """
    return {
        # SEMICOLON-TERMINATED, not a bare number: the page's own
        # ``saveSelectedPorts()`` builds ``selectedPorts`` as
        # ``"<n>;"`` per checked row and POSTs that string as PORT_NO. A bare
        # "3" is accepted with HTTP 200 and applies NOTHING -- caught live on
        # 10.1.5.25 by the verify-after-write, which is exactly what that check
        # is for.
        "PORT_NO": f"{port};",
        "PORT_CTRL_MODE": _EMX_CTRL_MODE_AUTO if enabled else _EMX_CTRL_MODE_DISABLE,
        "PORT_CTRL_DUPLEX": "0",
        "PORT_CTRL_SPEED": "0",
        "FLOW_CONTROL_MODE": flow_control_mode,
        "ACTION": "apply",
    }


def vlan_add_form(*, vlan: int, csrf_hash: str) -> dict[str, str]:
    return {
        "ACTION": "Add",
        "ADD_VLANID": str(vlan),
        "status": "Enable",
        "hash": csrf_hash,
    }


def vlan_delete_form(
    *, vlan: int, checkbox_index: int, csrf_hash: str
) -> dict[str, str]:
    return {
        "ACTION": "Delete",
        f"vlanck{checkbox_index}": str(vlan),
        "status": "Enable",
        "hash": csrf_hash,
    }


def reboot_form(*, csrf_hash: str) -> dict[str, str]:
    return {"hash": csrf_hash}


#: ``dhcp_mode`` on the GS110EMX sysInfo page: 1 = Enable (DHCP), 2 = Disable
#: (static). Read off the live page's own ``<select name="dhcp_mode">``, whose
#: current value the page carries as ``<tr data-select-value="N">`` -- the
#: options themselves have no ``selected`` attribute, so it is the row
#: attribute that says which one is in force.
EMX_DHCP_ON = "1"
EMX_DHCP_OFF = "2"


def gs110emx_switch_info_form(
    *,
    switch_name: str,
    dhcp_mode: str,
    ip_address: str,
    subnet_mask: str,
    gateway_address: str,
) -> dict[str, str]:
    """The GS110EMX sysInfo POST body -- the WHOLE form, per the page's own JS.

    Transcribed from ``submitSwitchInfoForm()`` in the switch's ``/function.js``
    (read live from 10.1.5.27, 2026-08-05), which validates the name, then::

        form1.elements["ACTION"].value = "Apply";
        form1.submit();

    -- an ordinary whole-form POST, with ``ACTION`` the only field the script
    itself sets. Note the capital "Apply" here versus the lowercase "apply" the
    port-admin page sends; both spellings appear in that file, per page.

    EVERY OTHER FIELD MUST BE ECHOED FROM THE PAGE. This one form carries the
    management addressing as well as the name, so a caller who omits or guesses
    ``dhcp_mode``/``IP_ADDRESS``/``SUBNET_MASK``/``GATEWAY_ADDRESS`` does not
    merely fail to rename the switch -- it reconfigures the address it is
    talking to and strands the device. That is why this builder takes all of
    them and has no defaults.

    The ``Gambit`` session token is added by the transport, as for every other
    request on this model.
    """
    return {
        "switch_name": switch_name,
        "dhcp_mode": dhcp_mode,
        # The page's checkbox, disabled unless DHCP is being turned on; "0"
        # is its value in the served markup and means "do not re-request a
        # lease". Sending "1" would make the switch renew and possibly move.
        "refresh": "0",
        "IP_ADDRESS": ip_address,
        "SUBNET_MASK": subnet_mask,
        "GATEWAY_ADDRESS": gateway_address,
        "refreshFlag": "0",
        "errMsg": "",
        "ACTION": "Apply",
    }


# --- XUI row ADD / DELETE (the syslog collector table) -----------------------
#
# These pages carry a blank TEMPLATE row alongside the data rows -- inputs named
# ``v_g_<table>_<tr>_<col>``, rendered inside ``display:none`` cells with every
# value empty. An ADD fills that row in and clicks APPLY; a DELETE marks an
# existing row and clicks DELETE. The page's own action arrays say so:
#
#     xa_4_2_1 (APPLY)  -> "2_1_5|g_2_1_5" = "Active"
#     xa_4_3_1 (DELETE) -> "2_1_5|g_2_1_5" = "Delete"
#
# so cell 5 is the WRITE-ONLY row-status (``xp_2_1_5 = "write-only"``,
# ``xc = "hidden"``, ``xdt = L7_ROW_STATUS_t``) while cell 2 is the READ-ONLY
# one the table displays. Both read off the served M4300 page, 2026-08-05.
XUI_ROW_STATUS_ACTIVE = "Active"
XUI_ROW_STATUS_DELETE = "Delete"


def xui_row_add_form(
    page: XuiListPage,
    values: Mapping[str, str],
    *,
    status_column: str,
    button: str,
) -> dict[str, str]:
    """The POST body that ADDS a row, by filling the page's template row.

    ``values`` is keyed by BARE column (``"2_1_1"``); the ``v_g_`` prefix is
    added here so a caller cannot address a data row by mistake. A column the
    template does not render raises rather than being invented -- the template
    row is the device's own declaration of which columns a new row has.

    ``status_column`` is the write-only row-status cell (``"2_1_5"`` on the
    syslog page); it is set to ``Active``, which is what the page's Apply action
    array writes. The whole template row is echoed, including the columns the
    caller did not set, because the firmware renders them all and a body that
    dropped them would be submitting a different row than the page describes.
    """
    if not page.template:
        raise KeyError("this page renders no v_g_* template row, so it cannot add")
    body = dict(page.tokens)
    body.update(page.nav)
    body.update(page.template)
    for column, value in values.items():
        name = f"v_g_{column}"
        if name not in page.template:
            raise KeyError(
                f"the template row does not render column {column!r} "
                f"(it has {sorted(k[4:] for k in page.template)})"
            )
        body[name] = value
    body[f"v_g_{status_column}"] = XUI_ROW_STATUS_ACTIVE
    body.update(page.hidden)
    body["submit_flag"] = XUI_OPERATION_SUBMIT
    body["err_flag"] = "0"
    body["err_msg"] = ""
    body[button] = page.buttons[button]
    return body


def xui_row_delete_form(
    page: XuiListPage, row: XuiRow, *, status_column: str, button: str
) -> dict[str, str]:
    """The POST body that DELETES one row, by marking its row-status cell.

    Same envelope as ``xui_row_apply_form`` -- only this row's fields, plus its
    checkbox -- with the write-only row-status set to ``Delete`` and the page's
    Delete button clicked.
    """
    # xui_row_apply_form keys ``changes`` by the FULL cell name ("v_2_1_5"),
    # while ``status_column`` is the bare coordinate the readers use ("2_1_5").
    return xui_row_apply_form(
        page, row, {f"v_{status_column}": XUI_ROW_STATUS_DELETE}, button=button
    )
