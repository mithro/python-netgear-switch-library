from __future__ import annotations

import pytest
from netgear_switch.http_write import HttpWriter

from netgear_switch.errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.registry import get_model


class _StatefulSession:
    """Minimal stateful gs305ep session: PoE admin per port, drives verify."""

    def __init__(self, *, honour_writes: bool = True) -> None:
        self.poe_on = {1: True, 2: False, 3: False, 4: False}
        self.honour_writes = honour_writes

    def login(self) -> None:
        return None

    def get_page(self, path: str) -> str:
        if path == "/PoEPortConfig.cgi":
            return '<input name="hash" value="h">'
        if path == "/getPoePortStatus.cgi":
            rows = "".join(
                f'<tr class="portID"><td>{p}</td><td>'
                f'{"Delivering" if on else "Disabled"}</td><td>0</td></tr>'
                for p, on in self.poe_on.items()
            )
            return f"<table>{rows}</table>"
        return '<input name="hash" value="h">'

    def post_form(self, path: str, data: dict[str, str]) -> str:
        if (
            path == "/PoEPortConfig.cgi"
            and data.get("ACTION") == "Apply"
            and self.honour_writes
        ):
            port = int(data["portID"]) + 1
            self.poe_on[port] = data["ADMIN_MODE"] == "1"
        return "OK"


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
