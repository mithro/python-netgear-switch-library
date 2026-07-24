# tests/transport/test_cli_telnet.py
"""End-to-end integration test for the telnet CLI transport.

Drives the REAL ``TelnetCliTransport`` (stdlib ``telnetlib`` over a genuine
loopback TCP socket) against a local fake FASTPATH shell that replays the real
captured gsm7252ps ``show`` output. This exercises the transport's actual
socket-open -> User/Password login -> ``ShellDriver`` (enable + paging-off +
per-command read-until-prompt) byte path -- the strongest verification of the
telnet access method achievable without live telnet hardware (the gsm7252ps has
telnet disabled).

``telnetlib`` was removed from the stdlib in Python 3.13; on such an interpreter
this whole module skips cleanly with a clear reason instead of erroring.
"""
from __future__ import annotations

import importlib.util

import pytest
from _fastpath_fake import (
    FAKE_PASSWORD,
    FAKE_USERNAME,
    TelnetFakeServer,
    assert_reader_reads_real_gsm7252ps,
)

from netgear_switch.cli_read import CliReader
from netgear_switch.protocols.cli.commands import cli_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.cli.telnet import TelnetCliTransport

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("telnetlib") is None,
    reason="stdlib telnetlib was removed in Python 3.13; telnet transport "
    "unavailable -- use the SSH or console transport instead",
)


def test_telnet_transport_reads_real_gsm7252ps_output() -> None:
    server = TelnetFakeServer()
    server.start()
    model = get_model("gsm7252ps")
    transport = TelnetCliTransport(
        server.host,
        FAKE_USERNAME,
        FAKE_PASSWORD,
        cli_spec(model),
        port=server.port,
        timeout=10.0,
    )
    try:
        transport.connect()  # real socket open + telnet login + shell setup
        reader = CliReader(transport, model)
        assert_reader_reads_real_gsm7252ps(reader)
    finally:
        transport.close()
        server.close()


def test_telnet_unknown_command_reports_not_found() -> None:
    """A command with no captured fixture round-trips a real "not found" reply
    over the wire -- proving the driver frames arbitrary commands, not just the
    ones the reader happens to issue."""
    server = TelnetFakeServer()
    server.start()
    model = get_model("gsm7252ps")
    transport = TelnetCliTransport(
        server.host,
        FAKE_USERNAME,
        FAKE_PASSWORD,
        cli_spec(model),
        port=server.port,
        timeout=10.0,
    )
    try:
        transport.connect()
        assert "Command not found" in transport.run("show nonsense")
    finally:
        transport.close()
        server.close()
