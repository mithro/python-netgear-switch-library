# tests/virtual/test_mibview.py
from __future__ import annotations

from netgear_switch.virtual.faces.mibview import StateMibView, _oid_to_tuple
from netgear_switch.virtual.seed import seed_gsm7252ps


class _FakeState:
    def __init__(self, mapping: dict[str, tuple[str, str]]) -> None:
        self._mapping = mapping

    def oid_map(self) -> dict[str, tuple[str, str]]:
        return self._mapping


def _view() -> StateMibView:
    # .8.2 must sort BEFORE .8.10 numerically (a string sort would invert them).
    return StateMibView(_FakeState({
        "1.3.6.1.2.1.2.2.1.8.1": ("INTEGER", "1"),
        "1.3.6.1.2.1.2.2.1.8.2": ("INTEGER", "2"),
        "1.3.6.1.2.1.2.2.1.8.10": ("INTEGER", "3"),
    }))


def test_get_exact_match():
    got = _view().get((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2))
    assert got == ((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2), "INTEGER", "2")


def test_get_missing_returns_none():
    assert _view().get((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 99)) is None


def test_get_next_uses_numeric_order():
    nxt = _view().get_next((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 2))
    assert nxt is not None
    assert nxt[0] == (1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 10)  # .8.10, not string order


def test_get_next_from_column_prefix():
    nxt = _view().get_next((1, 3, 6, 1, 2, 1, 2, 2, 1, 8))
    assert nxt is not None
    assert nxt[0][-1] == 1


def test_get_next_past_end_returns_none():
    assert _view().get_next((9, 9, 9)) is None


def test_walk_real_seeded_oid_map_yields_every_entry_once():
    """Built from a real seed's oid_map(), repeated get_next() from (0,) must
    visit every OID exactly once, in strictly increasing tuple order."""
    state = seed_gsm7252ps()
    oid_map = state.oid_map()
    view = StateMibView(state)

    seen: list[tuple[int, ...]] = []
    oid: tuple[int, ...] = (0,)
    while True:
        nxt = view.get_next(oid)
        if nxt is None:
            break
        seen.append(nxt[0])
        oid = nxt[0]

    assert len(seen) == len(oid_map)
    assert len(set(seen)) == len(seen)  # no duplicates
    assert seen == sorted(seen)  # strictly increasing
    assert {_oid_to_tuple(k) for k in oid_map} == set(seen)
