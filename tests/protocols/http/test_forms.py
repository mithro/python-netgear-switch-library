from __future__ import annotations

from netgear_switch.models import VlanMode
from netgear_switch.protocols.http import forms


def test_poe_apply_form_grounded_fields() -> None:
    f = forms.poe_apply_form(port=2, on=True, is_epx=True, csrf_hash="h")
    assert f["ACTION"] == "Apply"
    assert f["portID"] == "1"          # 0-indexed
    assert f["ADMIN_MODE"] == "1"
    assert f["PORT_PRIO"] == "0"
    assert f["POW_MOD"] == "3"
    assert f["POW_LIMT_TYP"] == "2"    # EPx variant
    assert f["DETEC_TYP"] == "2"
    assert f["DISCONNECT_TYP"] == "2"
    assert f["hash"] == "h"
    off = forms.poe_apply_form(port=2, on=False, is_epx=False, csrf_hash="h")
    assert off["ADMIN_MODE"] == "0"
    assert off["POW_LIMT_TYP"] == "0"  # non-EPx variant


def test_poe_reset_form() -> None:
    f = forms.poe_reset_form(port=3, csrf_hash="h")
    assert f["ACTION"] == "Reset"
    assert f["port2"] == "checked"
    assert f["hash"] == "h"


def test_pvid_form() -> None:
    f = forms.pvid_form(port=2, vlan=90, csrf_hash="h")
    assert f["port1"] == "checked"
    assert f["pvid"] == "90"


def test_membership_hidden_mem_encodes_wire_codes() -> None:
    states = {1: VlanMode.TAGGED, 2: VlanMode.UNTAGGED, 5: VlanMode.EXCLUDED}
    # ports not listed default to Excluded (3).
    assert forms.membership_hidden_mem(states, port_count=5) == "21333"


def test_membership_form_grounded_fields() -> None:
    f = forms.membership_form(vlan=90, hidden_mem="12333", csrf_hash="h")
    assert f["VLAN_ID"] == "90"
    assert f["hiddenMem"] == "12333"
    assert f["hash"] == "h"


def test_vlan_add_and_delete_and_reboot() -> None:
    assert forms.vlan_add_form(vlan=90, csrf_hash="h")["ADD_VLANID"] == "90"
    d = forms.vlan_delete_form(vlan=90, checkbox_index=1, csrf_hash="h")
    assert d["ACTION"] == "Delete"
    assert d["vlanck1"] == "90"
    assert forms.reboot_form(csrf_hash="h") == {"hash": "h"}
