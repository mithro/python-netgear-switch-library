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
    from collections.abc import Mapping

    from .types import FastpathMembership

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
