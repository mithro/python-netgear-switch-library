# tests/test_flow_control.py
"""``set_flow_control`` over the FASTPATH CLI, and the column it verifies against.

The command form is a round trip PROVEN on gsm7252ps 10.1.5.22 port 1/0/8
(link-down, undescribed, 2026-08-03) -- though not deliberately. A context-help
probe (``flowcontrol ?``) executed the bare command, which added a
``flowcontrol`` line to that port's running-config and moved its Flow Mode
column from Disable to Enable; ``no flowcontrol`` removed the line and returned
the column, leaving the interface byte-identical to its captured prior state.
An accident, but a complete and verified round trip of both directions.

Two things follow, and both are pinned here:

* ``show port``'s Flow Mode is the CONFIGURED setting, not a negotiated one --
  it moved on a port whose link was DOWN the whole time.
* the column must be found by NAME. It used to be read as ``cells[-1]``, which
  is the "Stack Capable" column on the M4300 images, so every M4300 port
  reported flow control off regardless of its actual Flow Mode.
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
from netgear_switch.protocols.cli import parse
from netgear_switch.protocols.cli.commands import cli_spec
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "cli"
_MODEL = "gsm7252ps"
LIVE_PORT = 8


# --- the column ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "trailing_column"),
    [
        # The gsm7252ps/S3300 tables END at Flow Mode...
        ("gsm7252ps_show_port_all.txt", None),
        ("gsm7228ps_port_all.txt", None),
        # ...while both M4300 images append "Stack Capable" after it. Reading
        # the last cell there yields "Yes", not a flow-control state.
        ("m4300_24x_show_port_all.txt", "Yes"),
        ("m4300_16x_show_port_all.txt", "Yes"),
    ],
)
def test_flow_mode_is_found_by_name_not_position(
    fixture: str, trailing_column: str | None
) -> None:
    text = (FIXTURES / fixture).read_text()
    cells = next(parse.iter_table_rows(text))

    if trailing_column is not None:
        # The exact trap: the last cell is NOT the flow-control column here.
        assert cells[-1].strip() == trailing_column

    # Every one of these captures reads Disable in its real Flow Mode column,
    # so the parser must report False -- and on the M4300 it must do so from
    # the right cell rather than because "Yes" happens not to be "Enable".
    ports = parse.parse_port_status(text)
    assert ports
    assert all(p.flow_control is False for p in ports)

    columns = parse.header_columns(text)
    flow = next(i for i, c in enumerate(columns) if "flow" in c.lower())
    assert cells[flow].strip() == "Disable"


def test_an_enabled_port_reads_back_as_enabled() -> None:
    """The M4300 shape with flow control actually ON.

    Built from the real m4300-24x header and one real row with only the Flow
    Mode cell changed, because no capture of an enabled port exists. Under the
    old cells[-1] rule this reads False -- the bug in one assertion.
    """
    text = (
        "                 Admin     Physical   Physical   Link   Link    "
        "LACP   Flow    Stack\n"
        "Intf      Type   Mode      Mode       Status     Status Trap    "
        "Mode   Mode    Capable\n"
        "--------- ------ --------- ---------- ---------- ------ ------- "
        "------ ------- --------\n"
        "1/0/1            Enable    Auto       10G Full   Up     Enable  "
        "Enable Enable  Yes\n"
    )
    (port,) = parse.parse_port_status(text)
    assert port.flow_control is True


# --- the command --------------------------------------------------------------


@pytest.mark.parametrize(
    ("enabled", "command"), [(True, "flowcontrol"), (False, "no flowcontrol")]
)
def test_builds_the_bare_toggle(enabled: bool, command: str) -> None:
    spec = cli_spec(get_model(_MODEL))
    assert spec.port_flow_control(enabled=enabled) == command


# --- the writer ---------------------------------------------------------------


class _RecordingSession:
    def __init__(self, inner: object) -> None:
        self.inner = inner
        self.commands: list[str] = []

    def run(self, command: str) -> str:
        self.commands.append(command)
        return self.inner.run(command)  # type: ignore[attr-defined]

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        raise AssertionError("a flow-control write never uses run_scp_copy")

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        raise AssertionError("a flow-control write must NOT save the config")

    def close(self) -> None:
        pass

    def config_commands(self) -> list[str]:
        return [c for c in self.commands if not c.startswith("show ")]


def _writer(
    key: str = _MODEL, *, protected_ports: frozenset[int] = frozenset()
) -> tuple[CliWriter, _RecordingSession]:
    session = _RecordingSession(VirtualSwitch(key).cli_session())
    writer = CliWriter(
        session,  # type: ignore[arg-type]
        get_model(key),
        protected_ports=protected_ports,
    )
    return writer, session


def _flow(writer: CliWriter, port: int) -> bool | None:
    return next(p.flow_control for p in writer._reader.get_ports() if p.port == port)


def test_the_seeds_start_where_their_captures_say() -> None:
    """Flow control is OFF on every FASTPATH seed, because it is off on every
    captured switch. The seeds used to carry the True default while the CLI face
    printed a hardcoded "Disable" -- agreeing with the device by accident and
    disagreeing with themselves."""
    for key in ("gsm7252ps", "gsm7228ps", "m4300-24x", "m4300-16x"):
        writer, _session = _writer(key)
        assert all(p.flow_control is False for p in writer._reader.get_ports()), key


def test_enabling_and_disabling_round_trips() -> None:
    """The live sequence, both directions."""
    writer, session = _writer()
    assert _flow(writer, LIVE_PORT) is False

    writer.set_flow_control(LIVE_PORT, True)
    assert _flow(writer, LIVE_PORT) is True
    assert session.config_commands() == [
        "configure",
        f"interface 1/0/{LIVE_PORT}",
        "flowcontrol",
        "exit",
        "exit",
    ]

    writer.set_flow_control(LIVE_PORT, False)
    assert _flow(writer, LIVE_PORT) is False


def test_it_does_not_touch_the_link() -> None:
    """Configured state only -- the live port was DOWN throughout and stayed so."""
    writer, _session = _writer()
    was = next(p for p in writer._reader.get_ports() if p.port == LIVE_PORT)
    assert was.link_up is False

    writer.set_flow_control(LIVE_PORT, True)

    now = next(p for p in writer._reader.get_ports() if p.port == LIVE_PORT)
    assert (now.link_up, now.speed_mbps) == (was.link_up, was.speed_mbps)
    assert now.flow_control is True


def test_a_protected_port_is_refused() -> None:
    writer, _session = _writer(protected_ports=frozenset({LIVE_PORT}))
    with pytest.raises(ProtectedPortError):
        writer.set_flow_control(LIVE_PORT, True)

    writer.set_flow_control(LIVE_PORT, True, force=True)
    assert _flow(writer, LIVE_PORT) is True


def test_an_unknown_port_is_refused() -> None:
    writer, _session = _writer()
    with pytest.raises(CliCommandError, match="no port 999"):
        writer.set_flow_control(999, True)


def test_a_switch_that_accepts_and_ignores_is_caught() -> None:
    session = _RecordingSession(VirtualSwitch(_MODEL).cli_session())
    original = session.inner.run  # type: ignore[attr-defined]

    def deaf(command: str) -> str:
        return "" if command.endswith("flowcontrol") else original(command)

    session.inner.run = deaf  # type: ignore[attr-defined]
    writer = CliWriter(session, get_model(_MODEL))  # type: ignore[arg-type]

    with pytest.raises(WriteVerificationError, match="did not read back"):
        writer.set_flow_control(LIVE_PORT, True)


# --- the other backends refuse BY NAME ---------------------------------------


@pytest.mark.parametrize(
    ("module", "cls", "match"),
    [
        ("netgear_switch.snmp_write", "SnmpWriter", "dot3PauseAdminMode"),
        ("netgear_switch.nsdp_write", "NsdpWriter", "no write tag"),
        ("netgear_switch.http_write", "HttpWriter", "no control to change it"),
    ],
)
def test_every_other_backend_refuses_by_name(module: str, cls: str, match: str) -> None:
    """Each for its own reason, and the HTTP one is a MEASURED absence: the
    GoAhead ports page reports flowControlAdminType but has no control for it,
    and its submit builder emits no flow-control field at all."""
    import importlib

    writer_cls = getattr(importlib.import_module(module), cls)
    assert hasattr(writer_cls, "set_flow_control")

    writer = writer_cls.__new__(writer_cls)
    writer.model = get_model(_MODEL)
    with pytest.raises(UnsupportedCapabilityError, match=match):
        writer.set_flow_control(1, True)


def test_the_goahead_page_really_has_no_flow_control_control() -> None:
    """Pins the claim the HTTP refusal rests on, against the captured page."""
    page = (
        pathlib.Path(__file__).parent / "fixtures" / "http" / "gs728tpp_ports.xml"
    ).read_text()

    # The fields ARE published...
    assert "<flowControlAdminType>" in page
    assert "<flowControlOperType>" in page
    # ...but nothing on the page can change them: the only selects are Admin
    # Mode and Port Speed, and the submit builder names neither field.
    assert 'ID="slctAdminMode"' in page
    assert 'ID="slctPortSpeed"' in page
    assert "flowControlAdminType:" not in page  # no post-object entry
