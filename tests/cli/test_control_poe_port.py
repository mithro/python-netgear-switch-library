from __future__ import annotations

import io

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.errors import ProtectedPortError
from netgear_switch.models import PoEDetect, PoEStatus
from netgear_switch.registry import get_model


class RecordingSwitch:
    def __init__(
        self, host: str = "10.0.0.1", protected: set[int] | None = None
    ) -> None:
        self.model = get_model("gsm7252ps")
        self.host = host
        self.calls: list[tuple[object, ...]] = []
        self._protected = protected or set()

    def _check_protected(self, port: int, force: bool) -> None:
        """Mirror the library's protected-port refusal for any write method."""
        if port in self._protected and not force:
            raise ProtectedPortError(f"port {port} is protected; pass force=True")

    def get_poe(self) -> list[PoEStatus]:
        return [PoEStatus(1, True, PoEDetect.DELIVERING, 12800)]

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        self._check_protected(port, force)
        self.calls.append(("set_poe", port, on, force))

    def cycle_poe(self, port: int, *, force: bool = False) -> None:
        self._check_protected(port, force)
        self.calls.append(("cycle_poe", port, force))

    def clear_poe_fault(self, port: int, *, force: bool = False) -> None:
        self._check_protected(port, force)
        self.calls.append(("clear_poe_fault", port, force))

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        self._check_protected(port, force)
        self.calls.append(("set_port_enabled", port, enabled, force))


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


def test_poe_no_port_shows_status() -> None:
    sw = RecordingSwitch()
    code, out, _ = run(["poe"], sw)
    assert code == context.EXIT_OK
    assert "Detect" in out
    assert "delivering" in out
    assert sw.calls == []


def test_poe_off_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _ = run(["poe", "3", "off", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert "PoE port 3 -> off" in out
    assert sw.calls == []


def test_poe_off_requires_confirmation() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["poe", "3", "off"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_poe_off_with_yes_calls_facade() -> None:
    sw = RecordingSwitch()
    code, _out, _err = run(["poe", "3", "off", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_poe", 3, False, False)]


def test_poe_cycle_and_clear_fault() -> None:
    sw = RecordingSwitch()
    run(["poe", "5", "cycle", "--yes"], sw)
    run(["poe", "5", "clear-fault", "--yes"], sw)
    assert ("cycle_poe", 5, False) in sw.calls
    assert ("clear_poe_fault", 5, False) in sw.calls


def test_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, err = run(["poe", "9", "off", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err


def test_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, _err = run(["poe", "9", "off", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_poe", 9, False, True)]


def test_port_down_with_yes() -> None:
    sw = RecordingSwitch()
    code, _out, _err = run(["port", "2", "down", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_port_enabled", 2, False, False)]


def test_poe_on_with_yes_calls_facade_with_enabled_true() -> None:
    """Pins the on/off boolean mapping; fails if the mapping were inverted."""
    sw = RecordingSwitch()
    code, _out, _err = run(["poe", "3", "on", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_poe", 3, True, False)]


def test_port_up_with_yes_calls_facade_with_enabled_true() -> None:
    """Pins the up/down boolean mapping; fails if the mapping were inverted."""
    sw = RecordingSwitch()
    code, _out, _err = run(["port", "2", "up", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_port_enabled", 2, True, False)]


def test_port_up_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _err = run(["port", "4", "up", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert "port 4 up" in out
    assert sw.calls == []


def test_port_down_declines_confirmation_with_explicit_no() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["port", "4", "down"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_port_down_declines_confirmation_with_blank_reply() -> None:
    sw = RecordingSwitch()
    code, _out, err = run(["port", "4", "down"], sw, stdin="\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_port_force_forwarded_to_facade() -> None:
    sw = RecordingSwitch()
    code, _out, _err = run(["port", "6", "up", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_port_enabled", 6, True, True)]


def test_port_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, err = run(["port", "9", "down", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_port_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, _err = run(["port", "9", "down", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("set_port_enabled", 9, False, True)]


def test_poe_cycle_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, err = run(["poe", "9", "cycle", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "Traceback" not in err
    assert sw.calls == []


def test_poe_cycle_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, _err = run(["poe", "9", "cycle", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("cycle_poe", 9, True)]


def test_poe_clear_fault_protected_port_refused_without_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, err = run(["poe", "9", "clear-fault", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "Traceback" not in err
    assert sw.calls == []


def test_poe_clear_fault_protected_port_allowed_with_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _out, _err = run(["poe", "9", "clear-fault", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("clear_poe_fault", 9, True)]
