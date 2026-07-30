# tests/virtual/test_serve_daemon.py
"""``serve_forever`` (the ``ngsw serve`` mock-daemon core) + pinned ports.

Covers the daemon primitive the CLI hands off to: that a served switch is
reachable on its bound port by a real SNMP client, that bound endpoints are
printed, that one unbindable model doesn't sink the rest of the fleet, and
that a pinned port is honoured. Everything runs on short-lived threads with a
controllable ``stop`` Event so no daemon is ever left running.
"""
from __future__ import annotations

import asyncio
import io
import socket
import threading

from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import SwitchClass, SwitchModel
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.virtual.server import VirtualSwitch, serve_forever

_PORT_1_OPER_STATUS = f"{oids.IF_OPER_STATUS}.1"


def _free_udp_port() -> int:
    """Grab (and immediately release) an ephemeral UDP port number."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _run_daemon_in_thread(
    switches: list[VirtualSwitch],
) -> tuple[threading.Thread, threading.Event, threading.Event, io.StringIO, list[int]]:
    out = io.StringIO()
    stop = threading.Event()
    ready = threading.Event()
    served: list[int] = []

    def _target() -> None:
        served.append(serve_forever(switches, out=out, stop=stop, ready=ready))

    thread = threading.Thread(target=_target, name="test-daemon", daemon=True)
    thread.start()
    assert ready.wait(timeout=10), "serve_forever never signalled ready"
    return thread, stop, ready, out, served


def test_serve_forever_snmp_read_and_clean_shutdown() -> None:
    sw = VirtualSwitch(model="gsm7252ps")
    thread, stop, _ready, out, served = _run_daemon_in_thread([sw])
    try:
        port = sw.port  # capture before stop() resets it to 0
        assert port != 0
        client = PysnmpClient(sw.host, "public", port=port)
        rows = asyncio.run(client.get([_PORT_1_OPER_STATUS]))
        assert rows == [SnmpRow(_PORT_1_OPER_STATUS, 1, "INTEGER")]
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert served == [1]
    # After a clean shutdown the face is torn down.
    assert sw._snmp_face is None
    printed = out.getvalue()
    assert "[gsm7252ps]" in printed
    assert f"SNMP udp/{port}" in printed
    assert "community='public'" in printed


def test_serve_forever_prints_http_endpoint_for_plus_model() -> None:
    # gs305ep binds NSDP (udp) + HTTP (tcp): both faces must be advertised.
    sw = VirtualSwitch(model="gs305ep")
    thread, stop, _ready, out, _served = _run_daemon_in_thread([sw])
    try:
        udp_port, http_port = sw.port, sw.http_port
        assert http_port != 0
        assert ("NSDP", "udp", udp_port) in sw.bound_endpoints
        assert ("HTTP", "tcp", http_port) in sw.bound_endpoints
    finally:
        stop.set()
        thread.join(timeout=10)
    printed = out.getvalue()
    assert f"NSDP udp/{udp_port}" in printed
    assert f"HTTP tcp/{http_port}" in printed


def test_serve_forever_skips_unbindable_and_serves_rest() -> None:
    good = VirtualSwitch(model="gsm7252ps")
    bad = VirtualSwitch(model="gsm7252ps")
    # Force `bad` to have no bindable face so its start() raises, exercising the
    # "one bad model must not sink the fleet" path (same stub trick the SNMP
    # face tests use). Rename it too so its failure line is distinguishable from
    # the good gsm7252ps in the printed output.
    bad.model = "stub-no-backend"
    bad._model_info = SwitchModel(
        key="stub-no-backend",
        display_name="stub",
        switch_class=SwitchClass.FULLY_MANAGED,
        port_count=1,
        poe_port_count=0,
        backends=frozenset(),
        snmp_vendor_base=None,
    )
    thread, stop, _ready, out, served = _run_daemon_in_thread([bad, good])
    try:
        assert good.port != 0
    finally:
        stop.set()
        thread.join(timeout=10)
    assert served == [1]  # only the good one
    printed = out.getvalue()
    assert "cannot serve 'stub-no-backend'" in printed
    assert "[gsm7252ps]" in printed


def test_serve_forever_returns_zero_when_nothing_binds_without_blocking() -> None:
    bad = VirtualSwitch(model="gsm7252ps")
    bad._model_info = SwitchModel(
        key="stub-no-backend",
        display_name="stub",
        switch_class=SwitchClass.FULLY_MANAGED,
        port_count=1,
        poe_port_count=0,
        backends=frozenset(),
        snmp_vendor_base=None,
    )
    out = io.StringIO()
    stop = threading.Event()  # never set: proves it returns without blocking
    served = serve_forever([bad], out=out, stop=stop)
    assert served == 0
    assert "no switches could be served" in out.getvalue()


def test_pinned_port_is_honoured() -> None:
    port = _free_udp_port()
    sw = VirtualSwitch(model="gsm7252ps", port=port)
    sw.start()
    try:
        assert sw.port == port
    finally:
        sw.stop()
