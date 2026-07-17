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
)


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
