from __future__ import annotations

import pytest

from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import (
    SET_TYPE_LETTERS,
    SetVarbind,
    encode_port_bitmap,
    membership_bitmaps,
    set_port_bit,
    vlan_bitmap_width,
)
from netgear_switch.registry import Backend, SwitchClass, SwitchModel, get_model


def test_set_varbind_rejects_unknown_type_letter():
    with pytest.raises(ValueError, match="unknown SET type letter"):
        SetVarbind("1.3.6", 1, "z")
    assert SetVarbind("1.3.6", 1, "i").type_letter == "i"
    assert "u" in SET_TYPE_LETTERS


def test_encode_is_inverse_of_decode():
    ports = {1, 8, 9, 52}
    assert decode_port_bitmap(encode_port_bitmap(ports)) == frozenset(ports)


def test_set_port_bit_only_changes_target_bit():
    base = encode_port_bitmap({1, 2, 10, 48})  # a "trunk" set
    added = set_port_bit(base, 25, present=True)
    assert decode_port_bitmap(added) == frozenset({1, 2, 10, 25, 48})
    removed = set_port_bit(base, 10, present=False)
    assert decode_port_bitmap(removed) == frozenset({1, 2, 48})


def test_membership_bitmaps_untagged_tagged_excluded():
    egress = encode_port_bitmap({1, 2})
    untagged = encode_port_bitmap({1})
    # UNTAGGED: port in egress AND untagged.
    e, u = membership_bitmaps(
        mode=VlanMode.UNTAGGED, port=5, egress=egress, untagged=untagged
    )
    assert decode_port_bitmap(e) == frozenset({1, 2, 5})
    assert decode_port_bitmap(u) == frozenset({1, 5})
    # TAGGED: port in egress, NOT untagged.
    e, u = membership_bitmaps(
        mode=VlanMode.TAGGED, port=1, egress=egress, untagged=untagged
    )
    assert decode_port_bitmap(e) == frozenset({1, 2})
    assert decode_port_bitmap(u) == frozenset()
    # EXCLUDED: port in neither; other ports preserved.
    e, u = membership_bitmaps(
        mode=VlanMode.EXCLUDED, port=1, egress=egress, untagged=untagged
    )
    assert decode_port_bitmap(e) == frozenset({2})
    assert decode_port_bitmap(u) == frozenset()


def test_encode_decode_large_port_set():
    """Round-trip test for >64-port switches (requires buffer growth)."""
    ports = {1, 65, 100}
    encoded = encode_port_bitmap(ports)
    assert decode_port_bitmap(encoded) == frozenset(ports)
    # Verify the buffer grew beyond 8 bytes to accommodate port 100
    assert len(encoded) > 8


def test_set_port_bit_preserves_str_input():
    """set_port_bit on str input (latin-1) yields same result as bytes input."""
    # Create a reference bytes bitmap
    bytes_bitmap = encode_port_bitmap({1, 10, 48})
    # Encode it to str (latin-1) to simulate transport normalization
    str_bitmap = bytes_bitmap.decode("latin-1")

    # Modify both with set_port_bit
    bytes_result = set_port_bit(bytes_bitmap, 25, present=True)
    str_result = set_port_bit(str_bitmap, 25, present=True)

    # Both should decode to the same port set
    assert decode_port_bitmap(bytes_result) == decode_port_bitmap(str_result)
    assert decode_port_bitmap(bytes_result) == frozenset({1, 10, 25, 48})


def test_set_port_bit_preserves_width():
    """set_port_bit preserves input bitmap width and rounds up to 8-byte min."""
    # Test 1: 16-byte input stays 16 bytes
    bitmap_16 = encode_port_bitmap({1}, width_bytes=16)
    assert len(bitmap_16) == 16
    result = set_port_bit(bitmap_16, 2, present=True)
    assert len(result) == 16
    assert decode_port_bitmap(result) == frozenset({1, 2})

    # Test 2: 8-byte input stays at least 8 bytes
    bitmap_8 = encode_port_bitmap({1}, width_bytes=8)
    assert len(bitmap_8) == 8
    result = set_port_bit(bitmap_8, 2, present=True)
    assert len(result) >= 8
    assert decode_port_bitmap(result) == frozenset({1, 2})


def test_vlan_bitmap_width_52_port_model_is_8():
    assert vlan_bitmap_width(get_model("gsm7252ps")) == 8


def test_vlan_bitmap_width_synthetic_96_port_model_is_12():
    # A hypothetical >64-port model, WITHOUT touching the production registry
    # (constructed directly here, never added to MODELS).
    synthetic = SwitchModel(
        key="synthetic-96port",
        display_name="Synthetic 96-port test model",
        switch_class=SwitchClass.FULLY_MANAGED,
        port_count=96,
        poe_port_count=0,
        backends=frozenset({Backend.SNMP}),
        snmp_vendor_base=None,
    )
    assert vlan_bitmap_width(synthetic) == 12


def test_set_port_bit_widens_to_requested_width_bytes():
    """width_bytes widens the result even when the input bitmap is narrower."""
    base = encode_port_bitmap({1})  # 8 bytes
    result = set_port_bit(base, 2, present=True, width_bytes=12)
    assert len(result) == 12
    assert decode_port_bitmap(result) == frozenset({1, 2})


def test_set_port_bit_width_bytes_never_narrows_below_input_or_8():
    """The result is max(8, input width, width_bytes) -- never narrower than
    what was read, and never narrower than the requested model width."""
    wide = encode_port_bitmap({1}, width_bytes=16)
    result = set_port_bit(wide, 2, present=True, width_bytes=12)
    assert len(result) == 16  # wider input wins over the smaller requested width

    narrow = encode_port_bitmap({1}, width_bytes=8)
    result = set_port_bit(narrow, 2, present=True, width_bytes=None)
    assert len(result) == 8  # default (no model width given) stays 8


def test_membership_bitmaps_forwards_width_bytes():
    egress = encode_port_bitmap({1})
    untagged = encode_port_bitmap({1})
    e, u = membership_bitmaps(
        mode=VlanMode.UNTAGGED,
        port=5,
        egress=egress,
        untagged=untagged,
        width_bytes=12,
    )
    assert len(e) == 12
    assert len(u) == 12
    assert decode_port_bitmap(e) == frozenset({1, 5})
    assert decode_port_bitmap(u) == frozenset({1, 5})
