"""Live-mock equivalence: sync/async facades routed through the HTTP backend
against a seeded gs305ep VirtualSwitch (NSDP reads + HTTP PoE reads/writes)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from equivalence import (
    GS305EP_HTTP_PINS,
    assert_http_facades_equivalent,
    assert_http_write_equivalent,
)

if TYPE_CHECKING:
    from netgear_switch.models import PoEStatus
    from netgear_switch.virtual.server import VirtualSwitch


def test_http_read_equivalence(virtual_gs305ep: VirtualSwitch) -> None:
    assert_http_facades_equivalent(virtual_gs305ep, GS305EP_HTTP_PINS)


def test_http_poe_write_equivalence() -> None:
    # backend=HTTP is now REQUIRED, not incidental: gs305ep's default backend is
    # NSDP, which has no PoE write, and the facade no longer re-routes a write to
    # another protocol on its own -- an operator's protocol choice is honoured.
    from netgear_switch.registry import Backend

    def sync_write(sw) -> None:  # type: ignore[no-untyped-def]
        sw.set_poe(2, False, force=True, backend=Backend.HTTP)

    async def async_write(sw) -> None:  # type: ignore[no-untyped-def]
        await sw.set_poe(2, False, force=True, backend=Backend.HTTP)

    def poe2_off(poe: list[PoEStatus]) -> bool:
        return not next(p for p in poe if p.port == 2).admin_enabled

    assert_http_write_equivalent(sync_write, async_write, poe2_off)
