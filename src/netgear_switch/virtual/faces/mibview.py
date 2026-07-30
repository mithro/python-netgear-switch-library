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
        self._state = state
        self._load()

    def _load(self) -> None:
        entries: list[_Entry] = [
            (_oid_to_tuple(oid), snmp_type, value)
            for oid, (snmp_type, value) in self._state.oid_map().items()
        ]
        entries.sort(key=lambda e: e[0])
        self._entries = entries
        self._oids = [e[0] for e in entries]  # parallel key list for bisect

    def get(self, oid: tuple[int, ...]) -> _Entry | None:
        # Callers MUST check `is_implemented(oid)` first (see faces/snmp.py):
        # this flat bisect has no notion of "this whole subtree is not
        # registered on this model" -- a None here means only "no instance at
        # this exact OID within an implemented subtree" (-> NoSuchInstance).
        i = bisect.bisect_left(self._oids, oid)
        if i < len(self._oids) and self._oids[i] == oid:
            return self._entries[i]
        return None  # caller maps None -> NoSuchInstance

    def get_next(self, oid: tuple[int, ...]) -> _Entry | None:
        # Same caveat as `get` above: callers check `is_implemented(oid)`
        # first, since a bare bisect_right would otherwise happily jump into
        # a completely unrelated (but implemented) subtree when `oid` itself
        # is under an unregistered one.
        # bisect_right -> index of the first OID strictly greater than `oid`.
        i = bisect.bisect_right(self._oids, oid)
        if i < len(self._oids):
            return self._entries[i]
        return None  # caller maps None -> endOfMibView

    def rebuild(self) -> None:
        """Recompute the sorted view from current state (call after a write)."""
        self._load()

    def apply_write(self, oid: str, value: int | bytes | str) -> None:
        """Mutate the underlying state then rebuild so reads reflect the write."""
        self._state.apply_write(oid, value)
        self.rebuild()

    def apply_write_uncommitted(self, oid: str, value: int | bytes | str) -> None:
        """Mutate the underlying state WITHOUT rebuilding the sorted view.

        For an atomic multi-varbind SET (``faces/snmp.py``'s
        ``write_variables``): the (relatively expensive) ``rebuild()`` is
        deferred until the whole PDU has committed successfully, once, rather
        than once per varbind. Callers MUST call ``rebuild()`` themselves
        once every varbind in the PDU has applied without error.
        """
        self._state.apply_write(oid, value)

    def snapshot_state(self) -> VirtualSwitchState:
        """Snapshot the underlying state, for atomic multi-varbind SET rollback.

        See ``VirtualSwitchState.snapshot``/``restore_state``.
        """
        return self._state.snapshot()

    def restore_state(self, snapshot: VirtualSwitchState) -> None:
        """Restore the underlying state in place from a prior
        ``snapshot_state()`` result, discarding any writes applied since.

        The sorted view itself needs no rebuild after a restore: if the
        caller took the snapshot before making any changes and only ever
        reaches this on a failed atomic SET, the state (and thus the view)
        is back to exactly what it was before that SET began.
        """
        self._state.restore(snapshot)

    def is_writable_oid(self, oid: str) -> bool:
        """Passthrough to ``VirtualSwitchState.is_writable_oid`` (see there)."""
        return self._state.is_writable_oid(oid)

    def is_implemented(self, oid: tuple[int, ...]) -> bool:
        """False if ``oid`` falls under a subtree root this model's SNMP
        agent has no registration for at all (e.g. the RFC3621 PoE MIB on a
        non-PoE model) -- see ``VirtualSwitchState.is_oid_implemented``.

        ``faces/snmp.py`` checks this BEFORE calling ``get``/``get_next``: a
        real agent answers ``noSuchObject`` for such a request rather than
        this view's flat bisect silently finding whatever unrelated OID
        happens to sort next.
        """
        oid_str = ".".join(str(x) for x in oid)
        return self._state.is_oid_implemented(oid_str)
