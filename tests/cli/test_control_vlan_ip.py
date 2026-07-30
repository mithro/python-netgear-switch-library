from __future__ import annotations

import io

import pytest

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.errors import ProtectedPortError
from netgear_switch.models import IpMode, MgmtIpConfig, VlanMode
from netgear_switch.registry import get_model


class RecordingSwitch:
    def __init__(
        self,
        host: str = "10.0.0.1",
        protected_ports: set[int] | None = None,
        vlan_members: dict[int, set[int]] | None = None,
        protect_mgmt_ip: bool = False,
    ) -> None:
        self.model = get_model("gsm7252ps")
        self.host = host
        self.calls: list[tuple[object, ...]] = []
        self._protected_ports = protected_ports or set()
        self._vlan_members = vlan_members or {}
        self._protect_mgmt_ip = protect_mgmt_ip

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return MgmtIpConfig(IpMode.STATIC, "10.1.5.20", "255.255.255.0", "10.1.5.1")

    def _check_protected_port(self, port: int, force: bool) -> None:
        """Mirror SnmpWriter.set_pvid/set_vlan_membership's protected-port guard."""
        if port in self._protected_ports and not force:
            raise ProtectedPortError(f"port {port} is protected; pass force=True")

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._check_protected_port(port, force)
        self.calls.append(("set_pvid", port, vlan, force))

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._check_protected_port(port, force)
        self.calls.append(("set_vlan_membership", vlan, port, mode, force))

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        # Mirrors SnmpWriter.create_vlan: creation is non-disruptive, so
        # force is accepted only for signature symmetry and never gates it.
        self.calls.append(("create_vlan", vlan, name, force))

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        # Mirrors SnmpWriter.delete_vlan / sync_api._guard_vlan_delete_members:
        # deleting a VLAN strips membership from every member port, so a
        # clash with a protected port refuses without force.
        if not force:
            clash = self._vlan_members.get(vlan, set()) & self._protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    "pass force=True to delete it anyway"
                )
        self.calls.append(("delete_vlan", vlan, force))

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        # Mirrors SnmpWriter.set_mgmt_ip: it writes UNVERIFIED OIDs that can
        # strand the switch, so on a "protected" fixture it is
        # unconditionally force-gated.
        if self._protect_mgmt_ip and not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
                "pass force=True to proceed"
            )
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


# --- pvid set -----------------------------------------------------------


def test_pvid_set_with_yes() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["pvid", "4", "90", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_pvid", 4, 90, False)]


def test_pvid_set_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["pvid", "4", "90", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_pvid_set_declines_confirmation() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["pvid", "4", "90"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_pvid_set_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["pvid", "4", "90"], sw, stdin="\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_pvid_set_force_forwarded() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["pvid", "4", "90", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_pvid", 4, 90, True)]


def test_pvid_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected_ports={9})
    code, _out, err = run(["pvid", "9", "50", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_pvid_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected_ports={9})
    code, _out, _err = run(["pvid", "9", "50", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_pvid", 9, 50, True)]


# --- vlan set (port membership) ------------------------------------------


def test_vlan_set_maps_mode_to_enum() -> None:
    sw = RecordingSwitch()
    run(["vlan", "set", "90", "10", "untagged", "--yes"], sw)
    assert sw.calls == [("set_vlan_membership", 90, 10, VlanMode.UNTAGGED, False)]


def test_vlan_set_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["vlan", "set", "90", "10", "tagged", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_vlan_set_declines_confirmation() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "set", "90", "10", "tagged"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_set_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "set", "90", "10", "tagged"], sw, stdin="\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_set_force_forwarded() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["vlan", "set", "90", "10", "excluded", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_vlan_membership", 90, 10, VlanMode.EXCLUDED, True)]


def test_vlan_set_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected_ports={9})
    code, _out, err = run(["vlan", "set", "90", "9", "tagged", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_vlan_set_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected_ports={9})
    code, _out, _err = run(["vlan", "set", "90", "9", "tagged", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_vlan_membership", 90, 9, VlanMode.TAGGED, True)]


def test_vlan_set_invalid_mode_exits_usage() -> None:
    sw = RecordingSwitch()
    with pytest.raises(SystemExit) as exc:
        run(["vlan", "set", "90", "10", "bogus", "--yes"], sw)
    assert exc.value.code == 2
    assert sw.calls == []


# --- vlan create ----------------------------------------------------------


def test_vlan_create_with_yes_exact_args() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["vlan", "create", "90", "iot", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("create_vlan", 90, "iot", False)]


def test_vlan_create_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["vlan", "create", "90", "iot", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_vlan_create_declines_confirmation() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "create", "90", "iot"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_create_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "create", "90", "iot"], sw, stdin="\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_create_force_forwarded() -> None:
    # create_vlan has no protected-port guard in the real facade (creation is
    # non-disruptive); --force still must reach the facade call for
    # signature symmetry with delete_vlan.
    sw = RecordingSwitch()
    code, _o, _e = run(["vlan", "create", "90", "iot", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("create_vlan", 90, "iot", True)]


# --- vlan delete ------------------------------------------------------------


def test_vlan_delete_with_yes_exact_args() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["vlan", "delete", "90", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("delete_vlan", 90, False)]


def test_vlan_create_and_delete() -> None:
    sw = RecordingSwitch()
    run(["vlan", "create", "90", "iot", "--yes"], sw)
    run(["vlan", "delete", "90", "--yes"], sw)
    assert ("create_vlan", 90, "iot", False) in sw.calls
    assert ("delete_vlan", 90, False) in sw.calls


def test_vlan_delete_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["vlan", "delete", "90", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_vlan_delete_declines_confirmation() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "delete", "90"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_delete_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["vlan", "delete", "90"], sw, stdin="\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_vlan_delete_force_forwarded() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["vlan", "delete", "90", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("delete_vlan", 90, True)]


def test_vlan_delete_protected_vlan_refused_without_force() -> None:
    sw = RecordingSwitch(protected_ports={9}, vlan_members={90: {9, 10}})
    code, _out, err = run(["vlan", "delete", "90", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_vlan_delete_protected_vlan_allowed_with_force() -> None:
    sw = RecordingSwitch(protected_ports={9}, vlan_members={90: {9, 10}})
    code, _out, _err = run(["vlan", "delete", "90", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("delete_vlan", 90, True)]


def test_vlan_requires_subcommand() -> None:
    sw = RecordingSwitch()
    with pytest.raises(SystemExit) as exc:
        run(["vlan"], sw)
    assert exc.value.code == 2


# --- ip / ip set -----------------------------------------------------------


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


def test_ip_set_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _o, err = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1"], sw, stdin="\n"
    )
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_ip_set_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1", "--dry-run"], sw
    )
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
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


def test_ip_set_force_forwarded() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1", "--yes", "--force"],
        sw,
    )
    assert code == context.EXIT_OK
    assert sw.calls == [("set_mgmt_ip", "10.1.5.30", "255.255.255.0", "10.1.5.1", True)]


def test_ip_set_protected_refused_without_force() -> None:
    sw = RecordingSwitch(protect_mgmt_ip=True)
    code, _out, err = run(
        ["ip", "set", "10.1.5.30", "255.255.255.0", "10.1.5.1", "--yes"], sw
    )
    assert code == context.EXIT_PROTECTED
    assert "force" in err.lower()
    assert "Traceback" not in err
    assert sw.calls == []


def test_ip_set_protected_allowed_with_force() -> None:
    sw = RecordingSwitch(protect_mgmt_ip=True)
    code, _out, _err = run(
        [
            "ip",
            "set",
            "10.1.5.30",
            "255.255.255.0",
            "10.1.5.1",
            "--yes",
            "--force",
        ],
        sw,
    )
    assert code == context.EXIT_OK
    assert sw.calls == [("set_mgmt_ip", "10.1.5.30", "255.255.255.0", "10.1.5.1", True)]
