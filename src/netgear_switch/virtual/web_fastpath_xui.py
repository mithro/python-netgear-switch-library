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
    mode = (
        fields.dhcp_value if state.mgmt.mode == "dhcp" else fields.static_value
    )
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


def _bad_ipv4(text: str) -> bool:
    parts = text.split(".")
    return len(parts) != 4 or not all(
        p.isdigit() and 0 <= int(p) <= 255 for p in parts
    )


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
