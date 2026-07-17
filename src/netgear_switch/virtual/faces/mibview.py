# src/netgear_switch/virtual/faces/mibview.py
"""Pure OID responder over VirtualSwitchState.oid_map().

No pysnmp, no network: a sorted (oid_tuple, snmp_type, value) list answering
exact-match GET and lexicographic GETNEXT with bisect. Task 15 wires this into
the real pysnmp command responder.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..state import VirtualSwitchState

_Entry = tuple[tuple[int, ...], str, str]  # (oid_tuple, snmp_type, value)


def _oid_to_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.lstrip(".").split("."))


class StateMibView:
    """Sorted view of a switch's OID map supporting GET and GETNEXT."""

    def __init__(self, state: VirtualSwitchState) -> None:
        entries: list[_Entry] = [
            (_oid_to_tuple(oid), snmp_type, value)
            for oid, (snmp_type, value) in state.oid_map().items()
        ]
        entries.sort(key=lambda e: e[0])
        self._entries = entries
        self._oids = [e[0] for e in entries]  # parallel key list for bisect

    def get(self, oid: tuple[int, ...]) -> _Entry | None:
        i = bisect.bisect_left(self._oids, oid)
        if i < len(self._oids) and self._oids[i] == oid:
            return self._entries[i]
        return None  # caller maps None -> NoSuchInstance

    def get_next(self, oid: tuple[int, ...]) -> _Entry | None:
        # bisect_right -> index of the first OID strictly greater than `oid`.
        i = bisect.bisect_right(self._oids, oid)
        if i < len(self._oids):
            return self._entries[i]
        return None  # caller maps None -> endOfMibView
