# tests/transport/test_cli_console.py
"""End-to-end integration test for the serial-console CLI transport.

Drives the REAL ``ConsoleCliTransport`` (pyserial) against a local fake FASTPATH
shell running on a pty master; the transport opens the pty's slave path as its
serial device, exactly as it would open ``/dev/ttyS0`` on a real console cable.
The fake replays the real captured gsm7252ps ``show`` output, so this exercises
the transport's actual serial-open -> login -> ``ShellDriver`` byte path -- the
strongest verification of the console access method achievable without physical
serial hardware.

Skips cleanly if pyserial (the ``[ssh]`` extra) is not installed, or on a
platform without ``os.openpty`` (e.g. Windows).
"""

from __future__ import annotations

import importlib.util
import os

import pytest
from _fastpath_fake import (
    FAKE_PASSWORD,
    FAKE_USERNAME,
    ConsolePtyFakeServer,
    assert_reader_reads_real_gsm7252ps,
)

from netgear_switch.cli_read import CliReader
from netgear_switch.protocols.cli.commands import cli_spec
from netgear_switch.registry import get_model

pytestmark = [
    pytest.mark.skipif(
        importlib.util.find_spec("serial") is None,
        reason="pyserial not installed (install the '[ssh]' extra)",
    ),
    pytest.mark.skipif(
        not hasattr(os, "openpty"),
        reason="platform has no os.openpty (pty-based console fake unavailable)",
    ),
]

# pyserial's blocking read() waits the full per-read timeout, so keep it short to
# bound total runtime; the local fake always answers well within the window, so
# no read ever returns empty (which the driver would treat as a closed channel).
_CONSOLE_TIMEOUT = 0.3


def _console_transport(device: str, model: object) -> object:
    from netgear_switch.transport.cli.console import ConsoleCliTransport

    return ConsoleCliTransport(
        device,
        FAKE_USERNAME,
        FAKE_PASSWORD,
        cli_spec(model),  # type: ignore[arg-type]
        timeout=_CONSOLE_TIMEOUT,
    )


def test_console_transport_reads_real_gsm7252ps_output() -> None:
    server = ConsolePtyFakeServer()
    server.start()
    model = get_model("gsm7252ps")
    transport = _console_transport(server.device, model)
    try:
        transport.connect()  # real serial open + login + shell setup
        reader = CliReader(transport, model)  # type: ignore[arg-type]
        assert_reader_reads_real_gsm7252ps(reader)
    finally:
        transport.close()  # type: ignore[attr-defined]
        server.close()


def test_console_unknown_command_reports_not_found() -> None:
    server = ConsolePtyFakeServer()
    server.start()
    model = get_model("gsm7252ps")
    transport = _console_transport(server.device, model)
    try:
        transport.connect()
        assert "Command not found" in transport.run("show nonsense")  # type: ignore[attr-defined]
    finally:
        transport.close()  # type: ignore[attr-defined]
        server.close()
