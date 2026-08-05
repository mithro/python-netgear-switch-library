# tests/test_port_speed.py
"""``set_port_speed`` over the FASTPATH CLI, and the model that pairs with it.

Everything asserted about the WIRE here was proven by execution on a live
GSM7252PS (10.1.5.22, XE firmware) port 1/0/8 on 2026-08-03 -- a link-down,
undescribed, user-authorised port, restored to a byte-identical running-config
afterwards. The transcript, in order:

    PRIOR                     1/0/8 Enable Auto  Down ...
    speed 100 full-duplex  -> 1/0/8 Enable 100 Full Down ...
    speed 1000 full-duplex -> "% Invalid input detected at '^' marker."
                              Physical Mode UNCHANGED at 100 Full
    speed auto 1000        -> Physical Mode back to Auto
    RESTORE speed auto     -> Auto, and no `speed` line in running-config

Two facts fall out of that and are pinned below: 1000 Mbit/s can only ever be
auto-negotiated, and Physical Mode is reported on a DOWN port while Physical
Status is blank -- which is why the configured speed is its own field.
"""

from __future__ import annotations

import pathlib

import pytest

from netgear_switch.cli_write import CliWriter
from netgear_switch.errors import (
    CliCommandError,
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.models import PortSpeed
from netgear_switch.protocols.cli import parse
from netgear_switch.protocols.cli.commands import cli_spec, fastpath_rate
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "gsm7252ps"
#: The port every live probe used, and one the seed also has link-down.
LIVE_PORT = 8


# --- the model ---------------------------------------------------------------


def test_auto_carries_no_rate_or_duplex() -> None:
    speed = PortSpeed.auto()
    assert speed.autonegotiate is True
    assert speed.speed_mbps is None
    assert speed.full_duplex is None
    assert str(speed) == "auto"


def test_forced_carries_both() -> None:
    speed = PortSpeed.forced(100, full_duplex=True)
    assert (speed.autonegotiate, speed.speed_mbps, speed.full_duplex) == (
        False,
        100,
        True,
    )
    assert str(speed) == "100M full-duplex"


def test_auto_with_a_rate_is_unrepresentable() -> None:
    """``speed auto 1000`` is a real command this library will not model.

    The grammar accepts it, but the live switch reported Physical Mode as a
    bare "Auto" afterwards -- identical to plain ``speed auto``. A write whose
    effect cannot be told apart from another write's is one this library cannot
    verify it made, so the state is made unrepresentable rather than offered
    with a caveat.
    """
    with pytest.raises(ValueError, match="no configured rate or duplex"):
        PortSpeed(autonegotiate=True, speed_mbps=1000)


def test_a_forced_speed_needs_a_duplex() -> None:
    """The firmware's grammar requires them together: `speed <rate> <duplex>`."""
    with pytest.raises(ValueError, match="BOTH a rate and a duplex"):
        PortSpeed(autonegotiate=False, speed_mbps=100)


# --- the command builder -----------------------------------------------------


@pytest.mark.parametrize(
    ("mbps", "text"),
    [
        # The three forced rates gsm7252ps 1/0/8 enumerated for itself.
        (10, "10"),
        (100, "100"),
        (10000, "10G"),
    ],
)
def test_fastpath_spells_rates_as_the_switch_does(mbps: int, text: str) -> None:
    assert fastpath_rate(mbps) == text


@pytest.mark.parametrize(
    ("speed", "cmd"),
    [
        (PortSpeed.auto(), "speed auto"),
        (PortSpeed.forced(100, full_duplex=True), "speed 100 full-duplex"),
        (PortSpeed.forced(10, full_duplex=False), "speed 10 half-duplex"),
        (PortSpeed.forced(10000, full_duplex=True), "speed 10G full-duplex"),
    ],
)
def test_builds_the_command_the_switch_accepted(speed: PortSpeed, cmd: str) -> None:
    assert cli_spec(get_model(_MODEL)).port_speed(speed) == cmd


# --- the Physical Mode parser ------------------------------------------------


@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ("Auto", PortSpeed.auto()),
        ("100 Full", PortSpeed.forced(100, full_duplex=True)),
        ("10G Full", PortSpeed.forced(10000, full_duplex=True)),
        ("10 Half", PortSpeed.forced(10, full_duplex=False)),
        # Honest absence, never a fabricated default.
        ("", None),
        ("Something Else", None),
    ],
)
def test_parses_physical_mode(cell: str, expected: PortSpeed | None) -> None:
    assert parse.parse_physical_mode(cell) == expected


def test_physical_mode_is_read_on_a_down_port() -> None:
    """The whole reason ``speed_config`` is a separate field from ``speed_mbps``.

    Verbatim from the committed gsm7252ps capture: port 1/0/6 is Down with a
    BLANK Physical Status and an "Auto" Physical Mode. The operational fields
    must be None while the configured one still answers.
    """
    text = (
        pathlib.Path(__file__).parent
        / "fixtures"
        / "cli"
        / "gsm7252ps_show_port_all.txt"
    ).read_text()
    ports = {p.port: p for p in parse.parse_port_status(text)}

    down = ports[6]
    assert down.link_up is False
    assert down.speed_mbps is None  # negotiated nothing
    assert down.full_duplex is None
    assert down.speed_config == PortSpeed.auto()  # but configured Auto

    up = ports[1]
    assert up.speed_mbps == 1000  # negotiated 1000 Full
    assert up.speed_config == PortSpeed.auto()  # while still configured Auto


# --- the writer, against the fake --------------------------------------------


class _RecordingSession:
    """Wraps the mock CLI face and records every command (see test_cli_vlan_write)."""

    def __init__(self, inner: object) -> None:
        self.inner = inner
        self.commands: list[str] = []

    def run(self, command: str) -> str:
        self.commands.append(command)
        return self.inner.run(command)  # type: ignore[attr-defined]

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        raise AssertionError("a speed write never uses run_scp_copy")

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        raise AssertionError("a speed write must NOT save the config")

    def close(self) -> None:
        pass

    def config_commands(self) -> list[str]:
        return [c for c in self.commands if not c.startswith("show ")]


def _writer(
    *, protected_ports: frozenset[int] = frozenset()
) -> tuple[CliWriter, VirtualSwitch, _RecordingSession]:
    sw = VirtualSwitch(_MODEL)
    session = _RecordingSession(sw.cli_session())
    writer = CliWriter(
        session,  # type: ignore[arg-type]
        get_model(_MODEL),
        protected_ports=protected_ports,
    )
    return writer, sw, session


def _config(writer: CliWriter, port: int) -> PortSpeed | None:
    return next(p.speed_config for p in writer._reader.get_ports() if p.port == port)


def test_forcing_a_speed_sends_the_proven_sequence() -> None:
    writer, _sw, session = _writer()
    writer.set_port_speed(LIVE_PORT, PortSpeed.forced(100, full_duplex=True))

    assert session.config_commands() == [
        "configure",
        f"interface 1/0/{LIVE_PORT}",
        "speed 100 full-duplex",
        "exit",
        "exit",
    ]
    assert _config(writer, LIVE_PORT) == PortSpeed.forced(100, full_duplex=True)


def test_restoring_auto_round_trips() -> None:
    """The exact live sequence: force 100, then put it back to auto."""
    writer, _sw, _session = _writer()
    before = _config(writer, LIVE_PORT)
    assert before == PortSpeed.auto()

    writer.set_port_speed(LIVE_PORT, PortSpeed.forced(100, full_duplex=True))
    writer.set_port_speed(LIVE_PORT, PortSpeed.auto())

    assert _config(writer, LIVE_PORT) == before


def test_forcing_a_speed_does_not_invent_a_negotiated_rate() -> None:
    """Physical MODE moves; Physical STATUS does not.

    A down port forced to 100 has negotiated nothing, and the mock must keep
    saying so -- a mock that moved both columns together would hide the very
    distinction ``speed_config`` exists to express.
    """
    writer, _sw, _session = _writer()
    writer.set_port_speed(LIVE_PORT, PortSpeed.forced(100, full_duplex=True))

    status = next(p for p in writer._reader.get_ports() if p.port == LIVE_PORT)
    assert status.link_up is False
    assert status.speed_mbps is None
    assert status.speed_config == PortSpeed.forced(100, full_duplex=True)


def test_a_forced_1000_is_refused_before_anything_is_sent() -> None:
    """Measured: this firmware has no forced 1000, because 1000BASE-T cannot.

    Refused by name so the caller learns WHY rather than getting the device's
    bare "% Invalid input" -- and refused BEFORE the command goes out, which
    the recorded command list proves.
    """
    writer, _sw, session = _writer()
    before = _config(writer, LIVE_PORT)

    with pytest.raises(CliCommandError, match="cannot be FORCED"):
        writer.set_port_speed(LIVE_PORT, PortSpeed.forced(1000, full_duplex=True))

    # Not one configuration command reached the switch (the only traffic is the
    # `show port all` this test itself issued to read `before`).
    assert session.config_commands() == []
    assert _config(writer, LIVE_PORT) == before


def test_the_fake_refuses_a_forced_1000_too() -> None:
    """The mock reproduces the REFUSAL, not just the successes.

    Driven at the session, below the writer's own guard, so this asserts the
    device model rather than the library's precondition. Without it the mock
    would be lenient exactly where the hardware is strict, and the library's
    guard would have nothing to be right about.
    """
    session = VirtualSwitch(_MODEL).cli_session()
    session.run("configure")
    session.run(f"interface 1/0/{LIVE_PORT}")

    assert session.run("speed 100 full-duplex") == ""  # accepted: empty output
    assert "Invalid input" in session.run("speed 1000 full-duplex")
    session.run("exit")
    session.run("exit")
    # ... and the refusal left the earlier configuration untouched.
    assert "100 Full" in session.run("show port all")


def test_a_protected_port_is_refused() -> None:
    """Disruptive -- applying a speed bounces the link -- so it is force-gated."""
    writer, _sw, _session = _writer(protected_ports=frozenset({LIVE_PORT}))
    with pytest.raises(ProtectedPortError):
        writer.set_port_speed(LIVE_PORT, PortSpeed.auto())

    writer.set_port_speed(
        LIVE_PORT, PortSpeed.forced(100, full_duplex=True), force=True
    )
    assert _config(writer, LIVE_PORT) == PortSpeed.forced(100, full_duplex=True)


def test_an_unknown_port_is_refused() -> None:
    writer, _sw, _session = _writer()
    with pytest.raises(CliCommandError, match="no port 999"):
        writer.set_port_speed(999, PortSpeed.auto())


def test_a_switch_that_accepts_and_ignores_is_caught() -> None:
    """Verify-after-write is what makes this safe to offer at all.

    A switch that answers the command with silence (= accepted) and changes
    nothing is the failure mode an "did it error?" check cannot see.
    """
    sw = VirtualSwitch(_MODEL)
    session = _RecordingSession(sw.cli_session())
    original = session.inner.run  # type: ignore[attr-defined]

    def deaf(command: str) -> str:
        return "" if command.startswith("speed ") else original(command)

    session.inner.run = deaf  # type: ignore[attr-defined]
    writer = CliWriter(session, get_model(_MODEL))  # type: ignore[arg-type]

    with pytest.raises(WriteVerificationError, match="did not read back"):
        writer.set_port_speed(LIVE_PORT, PortSpeed.forced(100, full_duplex=True))


# --- the other three backends refuse BY NAME ---------------------------------


@pytest.mark.parametrize(
    ("module", "cls", "match"),
    [
        ("netgear_switch.snmp_write", "SnmpWriter", "NEGOTIATED"),
        ("netgear_switch.nsdp_write", "NsdpWriter", "negotiated link"),
        ("netgear_switch.http_write", "HttpWriter", "no web-UI speed/duplex"),
    ],
)
def test_every_other_backend_refuses_by_name(module: str, cls: str, match: str) -> None:
    """Principle 2's mechanism: a backend that cannot serve an op SAYS SO.

    Not absent from the class -- absent would surface as an AttributeError out
    of the facade's lambda, naming neither the backend nor the reason.
    """
    import importlib

    writer_cls = getattr(importlib.import_module(module), cls)
    assert hasattr(writer_cls, "set_port_speed")

    writer = writer_cls.__new__(writer_cls)
    writer.model = get_model(_MODEL)
    with pytest.raises(UnsupportedCapabilityError, match=match):
        writer.set_port_speed(1, PortSpeed.auto())
