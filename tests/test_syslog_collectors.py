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
        # Only NSDP refuses BOTH ops outright, and it is the one that can be
        # driven off a bare class. SNMP serves remove (destroy(6)) and HTTP
        # serves remove too, each refusing add for its own measured reason --
        # all four cases are covered by the dedicated tests below.
        ("netgear_switch.nsdp_write", "NsdpWriter"),
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


# --- SNMP: destroy works, create does not ------------------------------------


def _snmp(mock: VirtualSwitch):
    from netgear_switch.snmp_read import SnmpReader
    from netgear_switch.snmp_write import SnmpWriter
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    model = get_model(_MODEL)
    client = NetsnmpCliClient(f"{mock.host}:{mock.port}", mock.community)
    return SnmpReader(client, model), SnmpWriter(client, model)


def test_snmp_destroys_a_row_but_will_not_create_one() -> None:
    """The agent's asymmetry, measured on m4300-24x 10.1.5.13 (2026-08-05).

    Five creation mechanisms all refused -- createAndGo(4) and createAndWait(5)
    with inconsistentValue, the value columns alone and active(1) with
    commitFailed -- while a single SET of RowStatus destroy(6) on an EXISTING
    row removed it, confirmed through the switch's own `show logging hosts`.

    So the library serves remove over SNMP and refuses add, and the fake
    reproduces both halves rather than being uniformly permissive.
    """
    with VirtualSwitch(model=_MODEL) as mock:
        reader, writer = _snmp(mock)
        assert [s.host for s in reader.get_syslog().servers] == [LIVE_COLLECTOR]

        with pytest.raises(UnsupportedCapabilityError, match="refuses to create"):
            writer.add_syslog_collector(THROWAWAY)

        writer.remove_syslog_collector(LIVE_COLLECTOR)
        assert reader.get_syslog().servers == ()


def test_snmp_surfaces_the_row_index_it_destroys_by() -> None:
    """The OID instance IS the row index, and the reader must expose it --
    a destroy addressed by list position would hit the wrong row on the sparse
    tables real switches carry."""
    with VirtualSwitch(model=_MODEL) as mock:
        reader, _ = _snmp(mock)
        assert [s.index for s in reader.get_syslog().servers] == [1]


def test_snmp_removing_an_absent_collector_is_refused() -> None:
    """A PRECONDITION failure -- see the dedicated test below for why the type
    matters."""
    from netgear_switch.protocols.snmp.client import SnmpError

    with VirtualSwitch(model=_MODEL) as mock:
        _, writer = _snmp(mock)
        with pytest.raises(SnmpError, match="no syslog collector"):
            writer.remove_syslog_collector(THROWAWAY)


# --- HTTP: the M4300 page deletes, but will not add --------------------------


def _http(mock: VirtualSwitch):
    from netgear_switch._dispatch import build_sync_http_client
    from netgear_switch.http_read import HttpReader
    from netgear_switch.http_write import HttpWriter

    model = get_model(_MODEL)
    client = build_sync_http_client(
        f"{mock.host}:{mock.http_port}", mock.http_password, model
    )
    return HttpReader(client, model), HttpWriter(client, model)


def test_the_syslog_page_renders_a_template_row() -> None:
    """The row an ADD would fill, and the reason this was called impossible.

    It is in the SERVED page all along, named ``v_g_2_1_N``. Two rounds of
    "this needs a browser capture" came from searching for ``g_2_1_N``.
    """
    import pathlib

    from netgear_switch.protocols.http.parse import parse_xui_list_page

    html = (
        pathlib.Path(__file__).parent
        / "fixtures"
        / "http"
        / "m4300_24x_syslog_configuration.html"
    ).read_text()
    page = parse_xui_list_page(html, page="syslog")
    assert sorted(page.template) == [f"v_g_2_1_{n}" for n in range(1, 8)]
    assert set(page.template.values()) == {""}  # every cell blank
    # ... and the data row parses too, which it did NOT until the fake grew the
    # real <TR p="..."> shape.
    assert page.row_for("v_2_1_1", "10.1.5.1") is not None


def test_http_deletes_but_refuses_to_add() -> None:
    """Both halves measured on m4300-24x 10.1.5.13 (2026-08-05).

    DELETE works -- it marks an existing row's write-only row-status and clicks
    Delete, live-verified. ADD does not: the firmware answers HTTP 200 with
    ``Error! Failed to Set 'Host Address'`` and leaves the table alone, through
    every variation tried (address type supplied, enums as indices, row-status
    "Add" instead of "Active").
    """
    with VirtualSwitch(model=_MODEL) as mock:
        reader, writer = _http(mock)
        assert [s.host for s in reader.get_syslog().servers] == [LIVE_COLLECTOR]

        with pytest.raises(UnsupportedCapabilityError, match="refuses a collector add"):
            writer.add_syslog_collector(THROWAWAY)

        writer.remove_syslog_collector(LIVE_COLLECTOR)
        assert reader.get_syslog().servers == ()


def test_the_fake_refuses_the_add_the_firmware_refuses() -> None:
    """Driven at the page, below the writer's own guard.

    A fake that accepted the add would make the writer's refusal look like a
    library limitation rather than the device's answer -- and would green-light
    an implementation that does not work on hardware.
    """
    from netgear_switch.virtual import web_fastpath_xui

    with VirtualSwitch(model=_MODEL) as mock:
        err = web_fastpath_xui.apply_syslog_rows(
            mock.state,
            {"v_g_2_1_1": THROWAWAY, "v_g_2_1_3": "514", "v_g_2_1_5": "Active"},
        )
    assert "Failed to Set 'Host Address'" in err


def test_a_missing_collector_is_a_precondition_not_a_capability_limit() -> None:
    """The distinction the capability guard caught me conflating.

    ``remove_syslog_collector`` on a switch that has no such collector must NOT
    raise ``UnsupportedCapabilityError`` -- that type means "this backend cannot
    do this on this model", and the published support matrix is generated from
    it. Raising it here made the table claim SNMP could not remove collectors on
    gsm7228ps and m4300-16x, whose seeds simply carry none.
    """
    from netgear_switch.protocols.snmp.client import SnmpError

    with VirtualSwitch(model=_MODEL) as mock:
        _, writer = _snmp(mock)
        with pytest.raises(SnmpError, match="no syslog collector"):
            writer.remove_syslog_collector(THROWAWAY)
        # ... and specifically NOT the capability error.
        try:
            writer.remove_syslog_collector(THROWAWAY)
        except UnsupportedCapabilityError:  # pragma: no cover
            pytest.fail("a missing row must not read as an unsupported capability")
        except SnmpError:
            pass


def test_a_model_with_no_vendor_subtree_cannot_destroy_a_row() -> None:
    """gs728tpp's agent publishes no 4526 subtree at all, so the RowStatus
    column does not exist there -- refused by name, not attempted."""
    from netgear_switch.snmp_write import SnmpWriter

    writer = SnmpWriter.__new__(SnmpWriter)
    writer.model = get_model("gs728tpp")
    with pytest.raises(UnsupportedCapabilityError, match="vendor OID"):
        writer.remove_syslog_collector(LIVE_COLLECTOR)
