from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.http_write import AsyncHttpWriter, HttpWriter
from netgear_switch.models import VlanMode
from netgear_switch.registry import get_model

_PORT_COUNT = 5  # gs305ep port_count
_WIRE_TO_MODE = {"1": VlanMode.UNTAGGED, "2": VlanMode.TAGGED, "3": VlanMode.EXCLUDED}
_MODE_TO_WIRE = {v: k for k, v in _WIRE_TO_MODE.items()}


def _run(coro):
    """Drive a coroutine to completion (no pytest-asyncio plugin configured)."""
    return asyncio.run(coro)


class _FakeGs305epState:
    """Shared PoE/PVID/VLAN state + page rendering behind the stateful fake
    sessions below (sync and async): records every POSTed field set and
    mutates its returned pages so a verify-after-write read reflects the
    write -- or, when ``honour_writes`` is False, deliberately does NOT
    reflect it, so the writer's verify step must raise.
    """

    def __init__(self, *, honour_writes: bool = True) -> None:
        self.poe_on = {1: True, 2: False, 3: False, 4: False}
        self.pvids = dict.fromkeys(range(1, _PORT_COUNT + 1), 1)
        self.vlan_members: dict[int, dict[int, VlanMode]] = {
            1: dict.fromkeys(range(1, _PORT_COUNT + 1), VlanMode.UNTAGGED)
        }
        self.vlan_ids: set[int] = {1}
        self.honour_writes = honour_writes
        self.posts: list[tuple[str, dict[str, str]]] = []

    def _render_get(self, path: str) -> str:
        if path == "/getPoePortStatus.cgi":
            rows = "".join(
                f'<tr class="portID"><td>{p}</td><td>'
                f'{"Delivering" if on else "Disabled"}</td><td>0</td></tr>'
                for p, on in self.poe_on.items()
            )
            return f"<table>{rows}</table>"
        if path == "/portPVID.cgi":
            rows = "".join(
                f'<tr class="portID"><td>{p}</td>'
                f'<td sel="text">{p}</td><td sel="input">{v}</td></tr>'
                for p, v in self.pvids.items()
            )
            return f'<input name="hash" value="h"><table>{rows}</table>'
        if path == "/8021qCf.cgi":
            checks = "".join(
                f'<input name="vlanck{i}" value="{vid}">'
                for i, vid in enumerate(sorted(self.vlan_ids), start=1)
            )
            return f'<input name="hash" value="h">{checks}'
        return '<input name="hash" value="h">'

    def _render_post(self, path: str, data: dict[str, str]) -> str:
        self.posts.append((path, dict(data)))
        if path == "/PoEPortConfig.cgi":
            if data.get("ACTION") == "Apply" and self.honour_writes:
                port = int(data["portID"]) + 1
                self.poe_on[port] = data["ADMIN_MODE"] == "1"
            return "OK"
        if path == "/portPVID.cgi":
            if self.honour_writes:
                for key, val in data.items():
                    if key.startswith("port") and val == "checked":
                        port = int(key.removeprefix("port")) + 1
                        self.pvids[port] = int(data["pvid"])
            return "OK"
        if path == "/8021qMembe.cgi":
            vlan = int(data["VLAN_ID"])
            if "hiddenMem" in data:
                if self.honour_writes:
                    self.vlan_members[vlan] = {
                        i + 1: _WIRE_TO_MODE[ch]
                        for i, ch in enumerate(data["hiddenMem"][:_PORT_COUNT])
                    }
                return "OK"
            current = self.vlan_members.get(
                vlan, dict.fromkeys(range(1, _PORT_COUNT + 1), VlanMode.EXCLUDED)
            )
            hidden = "".join(
                _MODE_TO_WIRE[current.get(p, VlanMode.EXCLUDED)]
                for p in range(1, _PORT_COUNT + 1)
            )
            return (
                '<input name="hash" value="h">'
                f'<input id="hiddenMem" value="{hidden}">'
            )
        if path == "/8021qCf.cgi":
            if self.honour_writes:
                if data.get("ACTION") == "Add":
                    self.vlan_ids.add(int(data["ADD_VLANID"]))
                elif data.get("ACTION") == "Delete":
                    for key, val in data.items():
                        if key.startswith("vlanck"):
                            self.vlan_ids.discard(int(val))
            return "OK"
        return "OK"


class _StatefulSession(_FakeGs305epState):
    """Minimal stateful gs305ep session: PoE/PVID/VLAN state, drives verify."""

    def login(self) -> None:
        return None

    def get_page(self, path: str) -> str:
        return self._render_get(path)

    def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._render_post(path, data)


class _AsyncStatefulSession(_FakeGs305epState):
    """Async mirror of ``_StatefulSession`` over the identical shared state,
    so sync and async writers are exercised against the same recorded
    behaviour and can never drift apart."""

    async def login(self) -> None:
        return None

    async def get_page(self, path: str) -> str:
        return self._render_get(path)

    async def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._render_post(path, data)


# ---------------------------------------------------------------------------
# Sync PoE / mgmt-IP tests
# ---------------------------------------------------------------------------


def test_set_poe_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_poe(2, True)
    assert sess.poe_on[2] is True


def test_set_poe_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_poe(2, True)


def test_protected_port_blocks_without_force() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"), protected_ports=frozenset({2}))
    with pytest.raises(ProtectedPortError):
        writer.set_poe(2, False)
    # force overrides.
    writer.set_poe(2, False, force=True)
    assert sess.poe_on[2] is False


def test_mgmt_ip_write_unsupported() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_mgmt_ip("10.0.0.2", "255.255.255.0", "10.0.0.1")


# ---------------------------------------------------------------------------
# Sync: PVID / VLAN membership / VLAN create-delete / PoE cycle & fault /
# reboot / port-enable.
# ---------------------------------------------------------------------------


def test_set_pvid_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_pvid(3, 20)
    assert sess.pvids[3] == 20
    assert sess.posts[-1] == (
        "/portPVID.cgi",
        {"port2": "checked", "pvid": "20", "hash": "h"},
    )


def test_set_pvid_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_pvid(3, 20)


def test_set_vlan_membership_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED)
    assert sess.vlan_members[1][3] is VlanMode.EXCLUDED
    apply_posts = [p for p in sess.posts if "hiddenMem" in p[1]]
    assert apply_posts[-1] == (
        "/8021qMembe.cgi",
        {"VLAN_ID": "1", "hiddenMem": "11311", "hash": "h"},
    )


def test_set_vlan_membership_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED)


def test_create_vlan_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.create_vlan(10, "irrelevant")
    assert 10 in sess.vlan_ids
    assert sess.posts[-1] == (
        "/8021qCf.cgi",
        {"ACTION": "Add", "ADD_VLANID": "10", "status": "Enable", "hash": "h"},
    )


def test_create_vlan_not_created_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.create_vlan(10, "irrelevant")


def test_delete_vlan_verifies() -> None:
    sess = _StatefulSession()
    sess.vlan_ids.add(10)
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.delete_vlan(10)
    assert 10 not in sess.vlan_ids
    assert sess.posts[-1] == (
        "/8021qCf.cgi",
        {"ACTION": "Delete", "vlanck2": "10", "status": "Enable", "hash": "h"},
    )


def test_delete_vlan_not_removed_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    sess.vlan_ids.add(10)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.delete_vlan(10)


def test_clear_poe_fault_is_unsupported() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.clear_poe_fault(2)


def test_cycle_poe_posts_reset_form() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.cycle_poe(2)
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )
    # cycle_poe is POST-only/no verify BY DESIGN: admin state must be untouched.
    assert sess.poe_on[2] is False


def test_cycle_poe_respects_protected_port() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"), protected_ports=frozenset({2}))
    with pytest.raises(ProtectedPortError):
        writer.cycle_poe(2)


def test_reboot_requires_force() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(ProtectedPortError):
        writer.reboot()


def test_reboot_posts_form_with_force() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.reboot(force=True)
    assert sess.posts[-1] == ("/device_reboot.cgi", {"hash": "h"})


def test_set_port_enabled_is_unsupported() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_port_enabled(2, True)


# ---------------------------------------------------------------------------
# Async parity: AsyncHttpWriter had ZERO direct tests before this file.
# ---------------------------------------------------------------------------


def test_async_set_poe_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_poe(2, True))
    assert sess.poe_on[2] is True


def test_async_set_poe_write_not_reflected_raises_verification() -> None:
    sess = _AsyncStatefulSession(honour_writes=False)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        _run(writer.set_poe(2, True))


def test_async_protected_port_blocks_without_force() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(
        sess, get_model("gs305ep"), protected_ports=frozenset({2})
    )
    with pytest.raises(ProtectedPortError):
        _run(writer.set_poe(2, False))
    _run(writer.set_poe(2, False, force=True))
    assert sess.poe_on[2] is False


def test_async_set_pvid_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_pvid(3, 20))
    assert sess.pvids[3] == 20
    assert sess.posts[-1] == (
        "/portPVID.cgi",
        {"port2": "checked", "pvid": "20", "hash": "h"},
    )


def test_async_set_pvid_write_not_reflected_raises_verification() -> None:
    sess = _AsyncStatefulSession(honour_writes=False)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        _run(writer.set_pvid(3, 20))


def test_async_set_vlan_membership_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED))
    assert sess.vlan_members[1][3] is VlanMode.EXCLUDED


def test_async_create_vlan_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.create_vlan(10, "irrelevant"))
    assert 10 in sess.vlan_ids


def test_async_delete_vlan_verifies() -> None:
    sess = _AsyncStatefulSession()
    sess.vlan_ids.add(10)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.delete_vlan(10))
    assert 10 not in sess.vlan_ids


def test_async_clear_poe_fault_is_unsupported() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        _run(writer.clear_poe_fault(2))


def test_async_cycle_poe_posts_reset_form() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.cycle_poe(2))
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )


def test_async_reboot_requires_force() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(ProtectedPortError):
        _run(writer.reboot())


def test_async_reboot_posts_form_with_force() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.reboot(force=True))
    assert sess.posts[-1] == ("/device_reboot.cgi", {"hash": "h"})


def test_async_set_port_enabled_is_unsupported() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_port_enabled(2, True)


def test_async_set_mgmt_ip_is_unsupported() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_mgmt_ip("10.0.0.2", "255.255.255.0", "10.0.0.1")
