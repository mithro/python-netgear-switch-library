# tests/test_syslog_collectors.py
"""Syslog collector add/remove over the FASTPATH CLI, and the read they verify against.

The command forms were learned READ-ONLY on 2026-08-05 by asking each switch to
print its OWN configuration back -- no writes, and no `?` context-help (which
EXECUTES commands accepting <cr>; see the hazard in task #72). All four
FASTPATH models -- gsm7252ps 10.1.5.22, m4300-24x 10.1.5.13, m4300-16x
10.1.5.20, gsm7228ps 10.1.5.11 -- print these two lines in `show
running-config`, character for character:

    logging host "10.1.5.1" ipv4 514 info
    logging syslog

and this table for `show logging hosts`:

    Index   IP Address/Hostname     Severity    Port   Status  Mode   Auth  Cert#
    ----- ------------------------ ---------- ------ --------- ----- ------ -----
    1     10.1.5.1                 info       514    Active    udp

So the address is QUOTED, the address-kind is an explicit token, the severity
travels as a WORD, and a removal addresses the 1-based INDEX rather than the
address. The two `no` forms are the standard FASTPATH negation and are the one
INFERRED part -- running-config never prints a negation. They are safe because
CliWriter treats any output as failure, so a wrong form is raised, not ignored.
"""

from __future__ import annotations

import pytest

from netgear_switch.cli_read import CliReader
from netgear_switch.cli_write import CliWriter
from netgear_switch.errors import (
    CliCommandError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.protocols.cli import parse
from netgear_switch.protocols.cli.commands import address_kind, cli_spec
from netgear_switch.registry import get_model
from netgear_switch.virtual.server import VirtualSwitch

_MODEL = "m4300-24x"
#: TEST-NET-1 (RFC 5737): documentation-only, routes nowhere.
THROWAWAY = "192.0.2.1"
#: The collector every live switch actually has, and every seed carries.
LIVE_COLLECTOR = "10.1.5.1"


# --- the command builder ------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "kind"),
    [
        ("10.1.5.1", "ipv4"),
        ("192.0.2.1", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("logs.example.com", "dns"),
    ],
)
def test_address_kind(address: str, kind: str) -> None:
    assert address_kind(address) == kind


def test_add_command_matches_the_live_running_config_line() -> None:
    """Byte-for-byte the line all four switches print for their own collector."""
    spec = cli_spec(get_model(_MODEL))
    assert (
        spec.logging_host_add("10.1.5.1", 514, 6)
        == 'logging host "10.1.5.1" ipv4 514 info'
    )


def test_severity_travels_as_a_word() -> None:
    spec = cli_spec(get_model(_MODEL))
    assert spec.logging_host_add("10.1.5.1", 514, 4).endswith(" warning")
    assert spec.logging_host_add("10.1.5.1", 514, 0).endswith(" emergency")
    with pytest.raises(ValueError, match="outside the standard range"):
        spec.logging_host_add("10.1.5.1", 514, 9)


def test_removal_is_a_subcommand_not_a_negation() -> None:
    """The inference that cost a live switch its clean state.

    ``no logging host <index>`` is the obvious FASTPATH negation and it is
    WRONG: a live gsm7252ps rejected it, and every address spelling too, leaving
    a throwaway collector stranded until ``logging host ?`` revealed that
    removal is a SUBCOMMAND.
    """
    spec = cli_spec(get_model(_MODEL))
    assert spec.logging_host_remove(1) == "logging host remove 1"


def test_the_fake_rejects_the_negation_the_real_switch_rejects() -> None:
    """Principle 5: the mock ACCEPTED `no logging host 2` while the device
    refused it, which is precisely why the bug reached hardware."""
    with VirtualSwitch(_MODEL) as mock:
        session = mock.cli_session()
        session.run("configure")
        assert "Invalid input" in session.run("no logging host 1")
        session.run("exit")
        # ... and the collector is still there, exactly as on the live switch.
        assert LIVE_COLLECTOR in session.run("show logging hosts")


def test_enable_command_is_the_bare_running_config_line() -> None:
    spec = cli_spec(get_model(_MODEL))
    assert spec.logging_syslog(enabled=True) == "logging syslog"
    assert spec.logging_syslog(enabled=False) == "no logging syslog"


# --- the read that verification depends on ------------------------------------


def test_an_unanswerable_read_raises_rather_than_reporting_it_off() -> None:
    """The defect this file's fix removes.

    `parse_syslog` used to return SyslogConfig(enabled=False, local_port=0,
    servers=()) for ANY unparseable input. A switch that answered "Command not
    found" was therefore reported as "remote logging is off, no collectors,
    source port 0" -- a confident wrong answer to a question that was never
    answered, with a fabricated 0 in it. That is precisely what the mock used
    to do, so nothing caught it.
    """
    with pytest.raises(CliCommandError, match="did not return a logging block"):
        parse.parse_syslog(
            "Command not found / Incomplete command. Use ? to list commands.", ""
        )


def test_the_fake_now_answers_the_logging_commands() -> None:
    """It did not: both returned "Command not found", so the CLI syslog READ was
    never exercised against the mock at all."""
    with VirtualSwitch(_MODEL) as mock:
        session = mock.cli_session()
        assert "Syslog Logging" in session.run("show logging")
        assert "IP Address/Hostname" in session.run("show logging hosts")


@pytest.mark.parametrize(
    ("key", "enabled", "hosts"),
    [
        ("m4300-24x", True, (LIVE_COLLECTOR,)),
        ("gsm7252ps", True, (LIVE_COLLECTOR,)),
        # Seeded with no collectors on purpose -- the case that proves an empty
        # table reads as empty rather than as "could not ask".
        ("gsm7228ps", False, ()),
    ],
)
def test_cli_read_matches_the_seed(
    key: str, enabled: bool, hosts: tuple[str, ...]
) -> None:
    with VirtualSwitch(key) as mock:
        got = CliReader(mock.cli_session(), get_model(key)).get_syslog()
    assert got.enabled is enabled
    assert got.local_port == 514
    assert tuple(s.host for s in got.servers) == hosts


# --- the writer ---------------------------------------------------------------


def _writer(key: str = _MODEL) -> CliWriter:
    return CliWriter(VirtualSwitch(key).cli_session(), get_model(key))


def _hosts(writer: CliWriter) -> tuple[str, ...]:
    return tuple(s.host for s in writer._reader.get_syslog().servers)


def test_add_then_remove_round_trips_and_leaves_the_original_alone() -> None:
    """Exactly the live procedure this would be verified with on hardware."""
    writer = _writer()
    assert _hosts(writer) == (LIVE_COLLECTOR,)

    writer.add_syslog_collector(THROWAWAY, port=1514, severity=4)
    added = next(s for s in writer._reader.get_syslog().servers if s.host == THROWAWAY)
    assert (added.port, added.severity) == (1514, 4)

    writer.remove_syslog_collector(THROWAWAY)
    assert _hosts(writer) == (LIVE_COLLECTOR,)


def test_a_duplicate_add_is_refused_before_anything_is_sent() -> None:
    """FASTPATH would append a SECOND row for the same address, silently
    duplicating delivery -- so the writer refuses instead."""
    writer = _writer()
    with pytest.raises(CliCommandError, match="already exists"):
        writer.add_syslog_collector(LIVE_COLLECTOR)
    assert _hosts(writer) == (LIVE_COLLECTOR,)


def test_the_fake_really_would_duplicate() -> None:
    """The mock reproduces the behaviour the guard exists to prevent.

    Driven at the session, below the writer, so the append is the DEVICE model
    rather than the library's precondition. Without this the guard would be
    guarding nothing.
    """
    with VirtualSwitch(_MODEL) as mock:
        session = mock.cli_session()
        session.run("configure")
        assert session.run(f'logging host "{LIVE_COLLECTOR}" ipv4 514 info') == ""
        session.run("exit")
        table = session.run("show logging hosts")
    assert table.count(LIVE_COLLECTOR) == 2


def test_removing_an_absent_collector_is_refused() -> None:
    writer = _writer()
    with pytest.raises(CliCommandError, match="no syslog collector"):
        writer.remove_syslog_collector(THROWAWAY)


def test_the_table_index_is_sparse_and_is_not_the_row_position() -> None:
    """The bug that shipped, and the measurement that caught it.

    On m4300-24x 10.1.5.13 (2026-08-05) the table held Index 1 and Index 3 with
    nothing at 2 -- FASTPATH hands out the next free slot and leaves survivors
    where they are. ``remove_syslog_collector`` counted rows instead of reading
    the Index column, so it addressed Index 2: a row that did not exist. The
    switch ACCEPTED that removal as a no-op and the collector survived, which
    is why nothing failed loudly.
    """
    writer = _writer()
    writer.add_syslog_collector("192.0.2.2")  # index 2
    writer.add_syslog_collector("192.0.2.3")  # index 3
    writer.remove_syslog_collector("192.0.2.2")  # leaves a HOLE at 2

    servers = writer._reader.get_syslog().servers
    assert [s.host for s in servers] == [LIVE_COLLECTOR, "192.0.2.3"]
    # The survivor kept index 3 while being the SECOND row.
    assert [s.index for s in servers] == [1, 3]

    # A position-based remover would send `logging host remove 2` here and the
    # collector would survive. This must actually remove it.
    writer.remove_syslog_collector("192.0.2.3")
    assert _hosts(writer) == (LIVE_COLLECTOR,)


def test_the_fake_refuses_a_nonexistent_index_the_way_the_switch_does() -> None:
    """Measured wording from 10.1.5.13. A mock that silently accepted it would
    reproduce the exact silence that hid the position-for-index bug."""
    with VirtualSwitch(_MODEL) as mock:
        session = mock.cli_session()
        session.run("configure")
        out = session.run("logging host remove 2")  # nothing at index 2
        session.run("exit")
    assert "non-existent" in out


def test_a_collector_without_an_index_cannot_be_removed() -> None:
    """A SyslogConfig from a backend that does not publish the index must not
    have one invented for it."""
    from netgear_switch.models import SyslogConfig, SyslogServer

    writer = _writer()
    writer._reader.get_syslog = lambda: SyslogConfig(  # type: ignore[method-assign]
        enabled=True,
        local_port=514,
        servers=(SyslogServer(host=THROWAWAY, port=514, severity=6, active=True),),
    )
    with pytest.raises(CliCommandError, match="no table index"):
        writer.remove_syslog_collector(THROWAWAY)


def test_enable_round_trips() -> None:
    writer = _writer()
    assert writer._reader.get_syslog().enabled is True
    writer.set_syslog_enabled(False)
    assert writer._reader.get_syslog().enabled is False
    writer.set_syslog_enabled(True)
    assert writer._reader.get_syslog().enabled is True


def test_a_switch_that_accepts_and_ignores_is_caught() -> None:
    session = VirtualSwitch(_MODEL).cli_session()
    original = session.run

    def deaf(command: str) -> str:
        return "" if command.startswith("logging host ") else original(command)

    session.run = deaf  # type: ignore[method-assign]
    writer = CliWriter(session, get_model(_MODEL))

    with pytest.raises(WriteVerificationError, match="did not read back"):
        writer.add_syslog_collector(THROWAWAY)


# --- the other backends refuse BY NAME ----------------------------------------


@pytest.mark.parametrize("op", ["add_syslog_collector", "remove_syslog_collector"])
@pytest.mark.parametrize(
    ("module", "cls"),
    [
        ("netgear_switch.snmp_write", "SnmpWriter"),
        ("netgear_switch.nsdp_write", "NsdpWriter"),
        ("netgear_switch.http_write", "HttpWriter"),
    ],
)
def test_every_other_backend_refuses_by_name(module: str, cls: str, op: str) -> None:
    """Each for its own measured reason -- see the docstrings. Present on the
    class rather than absent, so the refusal names the backend instead of
    surfacing as an AttributeError from the facade's lambda."""
    import importlib

    writer_cls = getattr(importlib.import_module(module), cls)
    writer = writer_cls.__new__(writer_cls)
    writer.model = get_model(_MODEL)
    with pytest.raises(UnsupportedCapabilityError, match="syslog-collector row"):
        getattr(writer, op)(THROWAWAY)
