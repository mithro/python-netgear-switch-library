from __future__ import annotations

import io

import pytest

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.models import IpMode, MgmtIpConfig, VlanMode
from netgear_switch.registry import get_model


class RecordingSwitch:
    def __init__(self, host: str = "10.0.0.1") -> None:
        self.model = get_model("gsm7252ps")
        self.host = host
        self.calls: list[tuple[object, ...]] = []

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return MgmtIpConfig(IpMode.STATIC, "10.1.5.20", "255.255.255.0", "10.1.5.1")

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self.calls.append(("set_pvid", port, vlan, force))

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self.calls.append(("set_vlan_membership", vlan, port, mode, force))

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        self.calls.append(("create_vlan", vlan, name, force))

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        self.calls.append(("delete_vlan", vlan, force))

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        self.calls.append(("set_mgmt_ip", address, netmask, gateway, force))


def run(
    argv: list[str], switch: RecordingSwitch, stdin: str = ""
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        argv,
        switch_factory=lambda a, c: switch,
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


def test_pvid_set_with_yes() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["pvid", "4", "90", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_pvid", 4, 90, False)]


def test_vlan_set_maps_mode_to_enum() -> None:
    sw = RecordingSwitch()
    run(["vlan", "set", "90", "10", "untagged", "--yes"], sw)
    assert sw.calls == [("set_vlan_membership", 90, 10, VlanMode.UNTAGGED, False)]


def test_vlan_create_and_delete() -> None:
    sw = RecordingSwitch()
    run(["vlan", "create", "90", "iot", "--yes"], sw)
    run(["vlan", "delete", "90", "--yes"], sw)
    assert ("create_vlan", 90, "iot", False) in sw.calls
    assert ("delete_vlan", 90, False) in sw.calls


def test_vlan_set_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["vlan", "set", "90", "10", "tagged", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_vlan_requires_subcommand() -> None:
    sw = RecordingSwitch()
    with pytest.raises(SystemExit) as exc:
        run(["vlan"], sw)
    assert exc.value.code == 2


def test_ip_no_subcommand_shows_config() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["ip"], sw)
    assert code == context.EXIT_OK
    assert "10.1.5.20" in out
    assert "mode:" in out
    assert sw.calls == []


def test_ip_set_is_confirm_gated_and_warns() -> None:
    sw = RecordingSwitch()
    code, _o, err = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1"], sw, stdin="n\n"
    )
    assert code == context.EXIT_ERROR
    assert "strand" in err.lower()
    assert sw.calls == []


def test_ip_set_with_yes_calls_facade() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1", "--yes"], sw
    )
    assert code == context.EXIT_OK
    assert sw.calls == [
        ("set_mgmt_ip", "10.1.5.30", "255.255.255.0", "10.1.5.1", False)
    ]
