"""The FASTPATH "XUI" write-form scaffolding shared by every managed model.

Every managed page (``portsConfiguration.html``,
``poeInterfaceConfiguration.html``, ``ipConfiguration.html``,
``mgmtVlanIpv4Configuration.html``) is wrapped in the SAME structure on real
firmware, and the mock reproduces it exactly because each piece is load-bearing
for the writer:

* TWO ``<FORM>``s. The first, ``<page>.html/a0``, is the applet/redirect form
  and carries no data; the SECOND, ``<page>.html/a1``, is the read+write form.
  A parser that grabbed the first form would find nothing.
* Repeating rows are ``<TR p="<unit>.<row0>.<count>0">`` and their fields are
  named ``<unit>.<row0>.<count>.v_1_2_<column>`` -- the row index is 0-based and
  the count is the RENDERED row count, not the port count (a 52-port switch's
  PoE page has 48 rows). Each row also carries its own ``gecb*`` checkbox, and
  the firmware applies ONLY the rows whose checkbox is submitted.
* A trailing "redirection elements" block -- ``submit_flag``/``submit_target``/
  ``err_flag``/``err_msg``/``clazz_information`` -- and a ``xuiButtonsDiv``
  holding the page's buttons as DISABLED hidden inputs.
* An apply is ``submit_flag=8`` (the firmware's own
  ``xui_operation_submit = 8``, from ``/scripts/_xeobj_jsvars.js``); a refusal
  comes back as HTTP **200** with ``err_flag=1`` and a human ``err_msg``.

All of it live-captured 2026-07-30 from gsm7252ps 10.1.5.22, gsm7228ps
10.1.5.11, m4300-24x 10.1.5.13 and m4300-16x 10.1.5.20:49152.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ..protocols.http.endpoints import HttpModelSpec
    from .state import VirtualSwitchState

# The firmware's own apply flag (see the module docstring).
SUBMIT_APPLY = "8"


def instance(row0: int, count: int, unit: int = 1) -> str:
    """The row field-name prefix, WITHOUT its trailing dot."""
    return f"{unit}.{row0}.{count}"


def row(inst: str, cells: str, *, checkbox: str = "gecb5") -> str:
    """Wrap ``cells`` in the real ``<TR p="...">`` row, with its own checkbox.

    ``checkbox`` differs per firmware on real hardware (``gecb5`` on gsm7252ps's
    ports page, ``gecb10`` on gsm7228ps's, ``gecb_1_2`` on the M4300s), so the
    caller passes the one that model renders -- the writer scrapes it rather
    than constructing it, and a mock that always used one spelling would hide a
    scrape that had hard-coded another.
    """
    return (
        f'<TR p="{inst}0" id=1_2>\n'
        f'<td class="def geRight">'
        f'<INPUT id="1_2_null" type="checkbox" name="{inst}.{checkbox}" xgc ></td>\n'
        f"{cells}</TR>\n"
    )


# The page's list-NAVIGATION block, above and below the table -- the "Go To
# Port" bars real firmware emits as ``<TR ... class=deftestme>``. Its ``v_*``
# fields SCOPE the list: ``v_1_1_1``/``v_1_3_1`` are the two aliases of the
# page's ``urlListUnit`` ("Port Group Index", ``xc="url-list"``,
# ``xeData["xalias_urlListUnit"] = "1_1_1|1_3_1|3_1_1|3_4_1"``) and ``v_1_1_2``
# is the interface-type filter. They are ENABLED hidden inputs, so a browser
# submits them on every apply.
#
# Rendered by the mock because their ABSENCE is what a real switch refuses on
# (see ``unit_required`` in ``apply_poe``): a page that never showed them could
# not reproduce that refusal, and the writer bug that omitted them would keep
# passing here forever.
LIST_UNIT_FIELDS = ("v_1_1_1", "v_1_3_1")
LIST_TYPE_FILTER = "v_1_1_2"


def nav_rows(unit: str = "1", *, type_filter: str = "^Physical$") -> str:
    """The page's two ``class=deftestme`` list-navigation rows."""
    return (
        "<TR id=1_1 class=deftestme>\n"
        "<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden "
        f'NAME=v_1_1_1 VALUE="{unit}"></TD>\n'
        '<TD id=1_1_2 style="display:none"><INPUT xid=1_1_2 TYPE=hidden '
        f'NAME={LIST_TYPE_FILTER} VALUE="{type_filter}"></TD>\n'
        '<td id="1_1_null"><INPUT type="text" '
        'id="inputBox_interface_1_1_null" name="inputBox_interface_1_1_null" '
        'SIZE="10" MAXLENGTH="10" VALUE=""></td>\n'
        "</TR>\n"
        "<TR id=1_3 class=deftestme>\n"
        "<TD class=defright id=1_3_1><INPUT xid=1_3_1 TYPE=hidden "
        f'NAME=v_1_3_1 VALUE="{unit}"></TD>\n'
        '<td id="1_3_null"><INPUT type="text" '
        'id="inputBox_interface_1_3_null" name="inputBox_interface_1_3_null" '
        'SIZE="10" MAXLENGTH="10" VALUE=""></td>\n'
        "</TR>\n"
    )


def has_list_unit(form: Mapping[str, str]) -> bool:
    """Whether this POST carries one of the page's ``urlListUnit`` aliases."""
    return any(form.get(name) for name in LIST_UNIT_FIELDS)


def _hidden(name: str, value: str) -> str:
    return f'<INPUT TYPE="hidden" NAME="{name}" XC=hidden VALUE="{value}">\n'


def _buttons(buttons: Mapping[str, str]) -> str:
    cells = "".join(
        f"<TD id={xid}><INPUT xid={xid} DISABLED TYPE=hidden "
        f'NAME=v_{xid} VALUE="{label}"></TD>\n'
        for xid, label in buttons.items()
    )
    return f'<div id="xuiButtonsDiv"><table><tr>\n{cells}</tr></table></div>\n'


def page(
    path: str,
    body: str,
    *,
    buttons: Mapping[str, str],
    err_msg: str = "",
    title: str = "NETGEAR",
) -> str:
    """One complete XUI page: both forms, the body, the redirection block and
    the buttons. ``err_msg`` non-empty renders the refusal the way the firmware
    does -- HTTP 200 with ``err_flag=1``."""
    name = path.rsplit("/", 1)[-1]
    return (
        f"<HTML>\n<HEAD><TITLE>{title}</TITLE></HEAD>\n<BODY CLASS=page>\n"
        f'<FORM method=post ACTION="{path}/a0">\n'
        '<INPUT TYPE="hidden" NAME="applet_port" XC=hidden VALUE="">\n'
        "</FORM>\n"
        f'<FORM method=post ACTION="{path}/a1">\n'
        "<table>\n"
        f"{body}"
        "</table>\n"
        + _hidden("submit_flag", "0")
        + _hidden("submit_target", name)
        + _hidden("err_flag", "1" if err_msg else "0")
        + _hidden("err_msg", err_msg)
        + _hidden("clazz_information", name)
        + _buttons(buttons)
        + "</FORM>\n</BODY>\n</HTML>\n"
    )


def checked_rows(form: Mapping[str, str], checkbox: str) -> list[str]:
    """The row prefixes whose ``gecb`` checkbox the submitted ``form`` carries.

    This is the whole selection rule on real hardware: fields for an unchecked
    row are ignored even when present. Reproducing it is what makes the mock
    able to FAIL a writer that forgot the checkbox -- which is exactly how a
    write silently does nothing on the real switch.
    """
    suffix = "." + checkbox
    return [name[: -len(suffix) + 1] for name in form if name.endswith(suffix)]


def is_apply(form: Mapping[str, str]) -> bool:
    """Whether this POST is an APPLY (``submit_flag=8``) rather than a reload."""
    return form.get("submit_flag") == SUBMIT_APPLY


def pressed(form: Mapping[str, str], candidates: Iterable[str]) -> str | None:
    """Which of ``candidates`` (button field names) this POST carries."""
    return next((c for c in candidates if c in form), None)


# --- management-IP pages ----------------------------------------------------
#
# Two shapes, one per Cheetah family; see endpoints.XuiMgmtIpFields for the
# measured field maps and for why they cannot share one page constant.


def _labelled(xid: str, label: str, value: str) -> str:
    return (
        f"<TR id={xid} class=deftestme>\n"
        f"<TD class=defleft id={xid}>{label}</TD>\n"
        f"<TD class=defright id={xid}><INPUT xid={xid} TYPE=hidden "
        f'NAME=v_{xid} VALUE="{value}"></TD>\n</TR>\n'
    )


def render_mgmt_ip(
    state: VirtualSwitchState, spec: HttpModelSpec, *, err_msg: str = ""
) -> str:
    """The model's management-IP page, rendered from ``state.mgmt``."""
    fields = spec.mgmt_ip_fields
    path = spec.mgmt_ip_path
    assert fields is not None  # caller checked
    assert path is not None  # caller checked
    mode = fields.dhcp_value if state.mgmt.mode == "dhcp" else fields.static_value
    body = (
        _labelled(fields.mode.removeprefix("v_"), "Configuration Method", mode)
        + _labelled(fields.address.removeprefix("v_"), "IP Address", state.mgmt.address)
        + _labelled(
            fields.netmask.removeprefix("v_"), "Subnet Mask", state.mgmt.netmask
        )
        + _labelled(
            fields.gateway.removeprefix("v_"), "Default Gateway", state.mgmt.gateway
        )
    )
    return page(
        path,
        body,
        buttons={fields.apply_button.removeprefix("v_"): "APPLY"},
        err_msg=err_msg,
        title="NETGEAR - IPv4 Network Interface Configuration",
    )


# --- syslogConfiguration.html ------------------------------------------------
#
def _xui_cell(inst: str, xid: str, value: str, *, text: bool = True) -> str:
    """One data cell of an XUI row grid, shaped as the live pages emit it.

    ``text=False`` renders the value into the hidden input only, not as visible
    cell text -- which is what the real pages do for their action/index columns
    and for the Severity Filter cell.
    """
    shown = value if text else ""
    return (
        f'<TD class="def alt0" p="1.0.10" id={xid}>'
        f"<INPUT xid={xid} TYPE=hidden NAME={inst}.v_{xid} "
        f'VALUE="{value}">{shown}</TD>\n'
    )


# --- management-service pages ------------------------------------------------
#
# Two shapes, MIXED WITHIN A MODEL -- measured 2026-08-03, see
# protocols/http/parse for the full map. gsm7252ps renders all four as XUI;
# m4300 renders http/https as a plain named form and ssh/telnet as XUI. The mock
# reproduces that split rather than picking one, because a fake that served only
# XUI would let a parser that had never learned the plain form pass.
#
# The XUI admin coordinate per service, and the port coordinate where the real
# page prints one (telnet's page prints NO port on either switch -- the CLI
# reports it, the page does not, so the mock must not invent one).
_SERVICE_XUI_COORDS = {
    "http": ("1_1_1", None),
    "https": ("1_1_1", "1_4_1"),
    "ssh": ("1_1_1", "1_10_1"),
    "telnet": ("2_5_1", None),
}
#: The plain-form radio group and port input per service.
_SERVICE_FORM_FIELDS = {
    "http": ("httpAdmin", "httpPort"),
    "https": ("sslAdmin", "httpsPort"),
}


def render_service_xui(state: VirtualSwitchState, path: str, service: str) -> str:
    """One service's config page in the XUI labelled-scalar shape."""
    sim = state.services[service]
    admin_coord, port_coord = _SERVICE_XUI_COORDS[service]
    body = _labelled(
        admin_coord,
        f"{service.upper()} Admin Mode",
        "Enable" if sim.enabled else "Disable",
    )
    if port_coord is not None and sim.port is not None:
        body += _labelled(port_coord, f"{service.upper()} Port", str(sim.port))
    return page(
        path,
        body,
        buttons={"4_5_1": "CANCEL", "4_5_2": "APPLY"},
        title=f"NetGear - {service.upper()} Configuration",
    )


def render_service_form(state: VirtualSwitchState, path: str, service: str) -> str:
    """One service's config page in the PLAIN NAMED FORM shape.

    Reproduces the firmware's double-checked radio group verbatim: BOTH radios
    carry a checked attribute, spelled ``checked="checked"`` on the first and a
    bare uppercase ``CHECKED`` on the second, and a browser takes the LAST. A
    mock that marked only the true one would let a first-match parser pass here
    and then misreport every real switch.
    """
    sim = state.services[service]
    radio, port_field = _SERVICE_FORM_FIELDS[service]
    selected = "Enable" if sim.enabled else "Disable"
    # The NOT-selected value first, then the selected one -- last wins.
    other = "Disable" if sim.enabled else "Enable"
    radios = (
        f'<INPUT type="radio" name="{radio}" id="{radio}{other}" '
        f'value="{other}" checked="checked" disabled="disabled" >\n'
        f'<INPUT type="radio" name="{radio}" id="{radio}{selected}" '
        f'value="{selected}" disabled="disabled" CHECKED>\n'
    )
    port = (
        f'<INPUT TYPE="TEXT" class="input" id="{port_field}" name="{port_field}" '
        f'SIZE="17" MAXLENGTH="5" VALUE="{sim.port}">\n'
        if sim.port is not None
        else ""
    )
    return (
        f"<HTML>\n<HEAD><TITLE>NETGEAR</TITLE></HEAD>\n<BODY CLASS=page>\n"
        f'<FORM method=post ACTION="{path}">\n{radios}{port}'
        '<INPUT TYPE="hidden" id="submt" NAME="submt" VALUE="">\n'
        '<INPUT TYPE="hidden" NAME="err_flag" VALUE="0">\n'
        "</FORM>\n</BODY>\n</HTML>\n"
    )


# --- userManagement.html -----------------------------------------------------
#
# The login-account grid. LIVE-CAPTURED 2026-08-03 from gsm7252ps 10.1.5.22 and
# m4300-24x 10.1.5.13; column labels are those pages' own header cells.
#
# The password columns are rendered because the real pages render them, and
# rendering what the device renders is the point -- but note WHAT they hold:
# gsm7252ps emits a literal "********" and the M4300 emits "", so neither page
# discloses anything, and a reader that tried to report a password would find
# only asterisks. The mock reproduces the gsm7252ps spelling.
_USER_HEADERS = {
    "1_1_2": "User Name",
    "1_1_13": "Edit Password",
    "1_1_3": "Password",
    "1_1_4": "Confirm   Password",
    "1_1_5": "Access   Mode",
    "1_1_6": "Lockout   Status",
    "1_1_7": "Password   Expiration   Date",
}


def render_users(state: VirtualSwitchState, path: str) -> str:
    """``userManagement.html``, rendered from ``state.users``."""
    body = (
        "<TR>\n"
        + "".join(
            f'<TD class="def_TH alt0" id={xid}>{label}</TD>\n'
            for xid, label in _USER_HEADERS.items()
        )
        + "</TR>\n"
    )
    count = len(state.users)
    for row0, user in enumerate(state.users):
        inst = instance(row0, count)
        body += (
            "<TR>\n"
            + _xui_cell(inst, "1_1_1", str(row0), text=False)
            + _xui_cell(inst, "1_1_2", user.name)
            + _xui_cell(inst, "1_1_13", "Disable", text=False)
            + _xui_cell(inst, "1_1_3", "********", text=False)
            + _xui_cell(inst, "1_1_4", "********", text=False)
            # Verbatim from state: this page's wording is NOT the CLI's.
            + _xui_cell(inst, "1_1_5", user.http_access_mode)
            + _xui_cell(inst, "1_1_6", "FALSE", text=False)
            + _xui_cell(inst, "1_1_7", "", text=False)
            + "</TR>\n"
        )
    return page(
        path,
        body,
        buttons={"3_1_1": "CANCEL", "3_2_1": "APPLY"},
        title="NetGear - User Management",
    )


# --- syslogConfiguration.html ------------------------------------------------
#
# One page shape for every managed model. LIVE-CAPTURED 2026-08-03 from all four
# (gsm7252ps 10.1.5.22, gsm7228ps 10.1.5.11, m4300-24x 10.1.5.13, m4300-16x
# 10.1.5.20): the two families differ only in extras -- the M4300s add Cheetah
# ``<!-- baselogCfg_* -->`` comments and two scalars the GSMs lack -- while every
# coordinate the reader uses is identical, which is why one renderer serves all
# four.
#
# The blank ``g_2_1_*`` TEMPLATE row is rendered ON PURPOSE. Real firmware emits
# it above the data rows, its fields named ``v_g_2_1_N`` with NO instance prefix,
# and a parser that mistook it for a collector would report a phantom row with an
# empty host. Leaving it out of the mock would make that bug untestable.
_SYSLOG_HEADERS = {
    "2_1_7": "IP Address Type",
    "2_1_1": "Host Address",
    "2_1_2": "Status",
    "2_1_3": "Port",
    "2_1_4": "Severity Filter",
}

#: The severity WORD the web UI prints for each standard number -- the inverse
#: of ``models.SYSLOG_SEVERITY_NAMES``, capitalised as the pages render it
#: ("Info" on all four switches, where SNMP's column reads 6). Written out
#: rather than derived from that map so the mock is an INDEPENDENT source: a
#: renderer that inverted the reader's own table could only ever agree with it.
_SYSLOG_SEVERITY_WORDS = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notice",
    6: "Info",
    7: "Debug",
}


def render_syslog(state: VirtualSwitchState, path: str, *, err_msg: str = "") -> str:
    """``syslogConfiguration.html``, rendered from ``state.syslog``.

    Counters (Messages Received/Relayed/Ignored) are rendered as the live pages
    do but are NOT part of ``SyslogConfig``; they exist so the page the mock
    serves has the same field set as the real one.
    """
    sim = state.syslog
    body = (
        _labelled(
            "1_1_1", "Admin Status", "Enable" if sim.admin_mode == 1 else "Disable"
        )
        + _labelled("1_2_1", "Local UDP Port", str(sim.local_port))
        + _labelled("1_3_1", "Messages Received", "9583")
        + _labelled("1_5_1", "Messages Relayed", "15")
        + _labelled("1_4_1", "Messages Ignored", "0")
        + "<TR>\n"
        + "".join(
            f'<TD class="def_TH alt0" id={xid}>{label}</TD>\n'
            for xid, label in _SYSLOG_HEADERS.items()
        )
        + "</TR>\n"
        # The template row: instance-less field names, so it is not a data row.
        + "<TR id=g_2_1>\n"
        + "".join(
            f'<TD><INPUT xid=g_{xid} TYPE=hidden NAME=v_g_{xid} VALUE=""></TD>\n'
            for xid in ("2_1_6", *_SYSLOG_HEADERS)
        )
        # VALUE="" -- the real page renders every template cell empty. "Add" is
        # the element LABEL (xeData.xeleValue_2_1_5), not the input's value, and
        # a mock that pre-filled it would let a writer that forgot to set the
        # row-status pass.
        + '<TD style="display:none"><INPUT xid=g_2_1_5 TYPE=hidden '
        + 'NAME=v_g_2_1_5 VALUE=""></TD>\n'
        + "</TR>\n"
    )
    count = len(sim.collectors)
    for row0, collector in enumerate(sim.collectors):
        inst = instance(row0, count)
        # The REAL row shape: <TR p="..."> plus the row's own gecb checkbox.
        # It used to be a bare <TR>, which parse_xui_list_page skips entirely --
        # so the page read fine through parse_xe_rows while offering the WRITER
        # no rows at all to address. The M4300 spells the checkbox "gecb_2_1"
        # on this page (live).
        body += (
            f'<TR p="{inst}0" id=2_1>\n'
            f'<td class="def alt0 geRight">'
            f'<INPUT id="2_1_null" type="checkbox" name="{inst}.gecb_2_1" xgc >'
            f"</td>\n"
            + _xui_cell(inst, "2_1_6", str(collector.index), text=False)
            + _xui_cell(inst, "2_1_7", "IPv4")
            + _xui_cell(inst, "2_1_1", collector.host)
            + _xui_cell(inst, "2_1_2", "Active" if collector.status == 1 else "")
            + _xui_cell(inst, "2_1_3", str(collector.port))
            + _xui_cell(
                inst,
                "2_1_4",
                _SYSLOG_SEVERITY_WORDS[collector.severity],
                text=False,
            )
            # Empty, as the live row is: 2_1_5 is WRITE-only, so the page
            # renders no value in it (2_1_2 is the readable "Active" mirror).
            + _xui_cell(inst, "2_1_5", "", text=False)
            + "</TR>\n"
        )
    return page(
        path,
        body,
        # Title-case, as the live M4300 page renders them (the writer echoes
        # page.buttons[...], so the label must be the device's).
        buttons={
            "4_1_1": "Add",
            "4_3_1": "Delete",
            "4_4_1": "Cancel",
            "4_2_1": "Apply",
        },
        title="NetGear - Syslog Configuration",
        err_msg=err_msg,
    )


def _bad_ipv4(text: str) -> bool:
    parts = text.split(".")
    return len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def apply_mgmt_ip(
    state: VirtualSwitchState, spec: HttpModelSpec, form: Mapping[str, str]
) -> str:
    """Apply a management-IP form, returning the firmware's ``err_msg`` ("" = ok).

    Reproduces the real page's validator rather than accepting anything: the
    firmware answers a malformed address with HTTP 200 +
    ``err_flag=1`` + "Error: Unable to set '<name>' with '<value>'. IP address
    should be in x.x.x.x form ..." (the page publishes that exact string as
    ``xeValData.xv_1_1_1_635``).
    """
    fields = spec.mgmt_ip_fields
    assert fields is not None
    if not is_apply(form):
        return ""
    for field, label in (
        (fields.address, "IP Address"),
        (fields.netmask, "Subnet Mask"),
        (fields.gateway, "Default Gateway"),
    ):
        value = form.get(field)
        if value is not None and _bad_ipv4(value):
            return (
                f"Error: Unable to set '{label}' with '{value}'. IP address "
                "should be in x.x.x.x form with each octet(x) in the range 0-255."
            )
    mode = form.get(fields.mode)
    if mode == fields.dhcp_value:
        state.mgmt.mode = "dhcp"
        return ""
    if mode == fields.static_value:
        state.mgmt.mode = "static"
    state.mgmt.address = form.get(fields.address, state.mgmt.address)
    state.mgmt.netmask = form.get(fields.netmask, state.mgmt.netmask)
    state.mgmt.gateway = form.get(fields.gateway, state.mgmt.gateway)
    return ""


def apply_port_admin(
    state: VirtualSwitchState,
    form: Mapping[str, str],
    *,
    checkbox: str,
    ports: Sequence[int],
    count: int,
    admin_column: str = "v_1_2_6",
) -> str:
    """Apply ``portsConfiguration.html``'s Admin Mode column, honouring the
    per-row checkboxes. Returns the firmware ``err_msg`` ("" = accepted)."""
    if not is_apply(form):
        return ""
    for prefix in checked_rows(form, checkbox):
        value = form.get(prefix + admin_column)
        if value is None:
            continue
        if value not in ("Enable", "Disable"):
            return f"Error! Failed to Set 'Admin <br/> Mode' with '{value}'"
        row0 = int(prefix.split(".")[1])
        if row0 >= len(ports):
            continue
        state.ports[ports[row0]].admin = value == "Enable"
    del count
    return ""


#: The severity WORD the web UI's enum carries -> the standard number. The page
#: spells them Title-case ("Info"); the CLI spells the same value lowercase.
_SYSLOG_SEVERITY_NUMBERS = {w: n for n, w in _SYSLOG_SEVERITY_WORDS.items()}


def apply_syslog_rows(state: VirtualSwitchState, form: Mapping[str, str]) -> str:
    """Apply a syslog-page row ADD or DELETE, returning ``err_msg`` ("" = ok).

    Reproduces what the live M4300 page does, both halves:

    * ADD -- the ``v_g_2_1_*`` template row with its write-only row-status
      (``v_g_2_1_5``) set to "Active". A new row takes the next FREE index and
      leaves existing rows where they are, which is what makes the table sparse.
    * DELETE -- a data row whose own ``v_2_1_5`` is set to "Delete".

    A template row submitted WITHOUT the row-status is ignored, exactly as the
    firmware ignores a blank global row that was never activated -- that is the
    case a writer which forgot to set it would otherwise appear to pass.
    """
    address = (form.get("v_g_2_1_1") or "").strip()
    if address:
        # THE ADD IS REFUSED, and the fake must refuse it too. Driven live
        # against m4300-24x 10.1.5.13 on 2026-08-05: the firmware answers a
        # filled template row with HTTP 200 and
        # ``Error! Failed to Set 'Host Address' with '<addr>'``, leaving the
        # table unchanged (verified through the switch's own CLI). Supplying the
        # IP Address Type and sending the enums as INDICES moves which fields
        # fail, but never gets the address to stick.
        #
        # A fake that accepted the add would make HttpWriter's refusal look
        # like a library limitation rather than the device's answer -- and would
        # green-light an implementation that does not work on hardware.
        return f"Error! Failed to Set 'Host Address' with '{address}'"

    # DELETE: an instance-prefixed row whose row-status cell says so.
    for name, value in form.items():
        if not name.endswith(".v_2_1_5") or value.strip() != "Delete":
            continue
        prefix = name[: -len("v_2_1_5")]
        target = (form.get(prefix + "v_2_1_1") or "").strip()
        row = next((c for c in state.syslog.collectors if c.host == target), None)
        if row is None:
            return f"Error! Logging Host {target} is non-existent."
        # Survivors KEEP their index -- that is what makes the table sparse.
        state.syslog.collectors.remove(row)
        return ""
    return ""
