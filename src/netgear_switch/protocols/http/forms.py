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
