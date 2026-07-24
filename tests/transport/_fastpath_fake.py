"""A local, byte-level fake of a FASTPATH interactive CLI shell.

Both the telnet integration test (`test_cli_telnet.py`) and the serial-console
integration test (`test_cli_console.py`) drive the REAL library transports
(`TelnetCliTransport` / `ConsoleCliTransport`) against this one emulator. It
speaks the exact shell flow those transports' shared `ShellDriver` expects:

    login (User:/Password:) -> initial prompt -> `enable` -> `terminal length 0`
    -> `show ...` commands, each echoed and answered with a trailing prompt.

Every `show` reply is the REAL captured gsm7252ps output from
`tests/fixtures/cli/gsm7252ps_show_*.txt` -- the same fixtures the parser unit
tests use -- so a transport that genuinely drives the shell end to end produces
byte-for-byte the parsed results the SSH/fixture path yields.

The emulator core (`FastpathShell`) is transport-free: it turns one input line
into response bytes. `serve()` frames it over any read/write byte callables, and
the two `start_*` helpers wire it onto a real loopback TCP socket (telnet) and a
real pty master (console) so the transports open genuine sockets / serial ports.
"""
from __future__ import annotations

import contextlib
import os
import socket
import threading
import tty
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from netgear_switch.cli_read import CliReader

_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cli"

# Each FASTPATH `show` command -> the real captured transcript that answers it.
# Only commands with a genuine capture are served; anything else gets a
# "Command not found" reply, exactly like the switch (never fabricated output).
_COMMAND_FIXTURES: dict[str, str] = {
    "show version": "gsm7252ps_show_version.txt",
    "show port all": "gsm7252ps_show_port_all.txt",
    "show network": "gsm7252ps_show_network.txt",
    "show vlan brief": "gsm7252ps_show_vlan_brief.txt",
    "show vlan 90": "gsm7252ps_show_vlan_90.txt",
    "show vlan port all": "gsm7252ps_show_vlan_port_all.txt",
    "show mac-addr-table": "gsm7252ps_show_mac_addr_table.txt",
    "show lldp remote-device all": "gsm7252ps_show_lldp_remote_device_all.txt",
    "show poe port info all": "gsm7252ps_show_poe_port_info_all.txt",
    "show environment": "gsm7252ps_show_environment.txt",
    "show interface ethernet 1/0/1": "gsm7252ps_show_interface_ethernet_1_0_1.txt",
}

_PROMPT_UNPRIV = b"\r\n(GSM7252PS) >"
_PROMPT_PRIV = b"\r\n(GSM7252PS) #"
_NEWLINE = b"\r\n"

# The credentials the login step consumes. Any values work (the fake never
# authenticates -- like a console you already have physical access to); the
# tests pass these so the exchange is realistic.
FAKE_USERNAME = "admin"
FAKE_PASSWORD = "password"


def _load_fixture(name: str) -> bytes:
    # Real captures are stored with Unix newlines; a real shell emits CRLF, so
    # normalise to CRLF to faithfully mimic the wire bytes the driver strips.
    text = (_FIXTURES_DIR / name).read_text()
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1")


class FastpathShell:
    """Transport-free FASTPATH shell core: one input line -> response bytes."""

    def __init__(self) -> None:
        self._privileged = False

    def _prompt(self) -> bytes:
        return _PROMPT_PRIV if self._privileged else _PROMPT_UNPRIV

    def handle_line(self, line: str) -> bytes:
        """Return the bytes the shell emits in reply to one typed command line.

        Every reply echoes the command (a real pty echoes what you type) and
        ends with the prompt, matching what `ShellDriver` reads-until then
        strips.
        """
        command = line.strip()
        echo = command.encode("latin-1") + _NEWLINE
        if command == "enable":
            # An admin login goes straight to the privileged prompt with no
            # further password challenge (what the real gsm7252ps does).
            self._privileged = True
            return echo + self._prompt()
        if command == "terminal length 0":
            return echo + self._prompt()
        fixture = _COMMAND_FIXTURES.get(command)
        if fixture is not None:
            return echo + _load_fixture(fixture) + _NEWLINE + self._prompt()
        return echo + b"% Invalid input: Command not found" + _NEWLINE + self._prompt()


class _IacStripper:
    """Filter telnet IAC control sequences out of a client byte stream.

    telnetlib will not initiate option negotiation against a server that sends
    none (this fake sends none), but a stray IAC would corrupt line framing, so
    strip them defensively across chunk boundaries.
    """

    _IAC = 0xFF

    def __init__(self) -> None:
        self._pending = 0  # option-bytes still to swallow after an IAC command

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            if self._pending:
                self._pending -= 1
                continue
            if byte == self._IAC:
                # WILL/WONT/DO/DONT (251-254) carry one option byte; other
                # commands carry none. Swallow the command byte next, and for
                # negotiation verbs one more option byte after it.
                self._pending = 2
                continue
            out.append(byte)
        return bytes(out)


class _LineReader:
    """Buffer bytes from a `read()` callable and hand back whole lines."""

    def __init__(self, read: Callable[[], bytes], *, strip_iac: bool) -> None:
        self._read = read
        self._stripper = _IacStripper() if strip_iac else None
        self._buf = b""

    def read_line(self) -> str | None:
        while b"\n" not in self._buf:
            chunk = self._read()
            if not chunk:
                return None
            if self._stripper is not None:
                chunk = self._stripper.feed(chunk)
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("latin-1").rstrip("\r")


def serve(
    read: Callable[[], bytes],
    write: Callable[[bytes], None],
    *,
    telnet_login: bool,
) -> None:
    """Run the fake shell over one connection until the client disconnects.

    `telnet_login` selects the login handshake:

    * telnet: the transport reads-until "User:"/"Password:" prompts, so the
      server must emit them and consume exactly the two credential lines.
    * console: the transport blindly writes a "\\r\\n" prod then the username
      and password without reading, so the server consumes those three line
      chunks and emits no login prompts.

    Afterwards the server sends the initial (unprivileged) prompt that
    `ShellDriver.setup()` reads, then loops answering commands.
    """
    reader = _LineReader(read, strip_iac=telnet_login)
    shell = FastpathShell()

    if telnet_login:
        write(b"\r\nUser:")
        reader.read_line()  # username
        write(b"\r\nPassword:")
        reader.read_line()  # password
    else:
        reader.read_line()  # leading "\r\n" prod
        reader.read_line()  # username
        reader.read_line()  # password

    write(_PROMPT_UNPRIV)  # initial prompt for ShellDriver.setup()

    while True:
        line = reader.read_line()
        if line is None:
            return
        write(shell.handle_line(line))


class TelnetFakeServer:
    """A loopback TCP server that serves one FASTPATH telnet shell connection."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._conn: socket.socket | None = None

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        self._conn = conn
        conn.settimeout(10.0)
        with contextlib.suppress(OSError):
            # client hung up mid-session -- expected on close()
            serve(lambda: conn.recv(4096), conn.sendall, telnet_login=True)

    def close(self) -> None:
        for closable in (self._conn, self._sock):
            if closable is not None:
                with contextlib.suppress(OSError):
                    closable.close()
        self._thread.join(timeout=5.0)


class ConsolePtyFakeServer:
    """A pty whose master runs the FASTPATH shell; the slave path is the device
    a serial transport (pyserial) opens."""

    def __init__(self) -> None:
        self._master, self._slave = os.openpty()
        # Put the pty into raw mode: a cooked tty would echo the master's writes
        # back and translate CR<->NL, corrupting the byte stream the transport
        # sees. pyserial reconfigures to raw when it opens the slave too, but do
        # it up front so the pipe is clean regardless of open ordering.
        tty.setraw(self._slave)
        self.device = os.ttyname(self._slave)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _read(self) -> bytes:
        try:
            return os.read(self._master, 4096)
        except OSError:
            return b""  # slave closed -> EIO; treat as disconnect

    def _write(self, data: bytes) -> None:
        while data:
            written = os.write(self._master, data)
            data = data[written:]

    def _run(self) -> None:
        serve(self._read, self._write, telnet_login=False)

    def close(self) -> None:
        for fd in (self._master, self._slave):
            with contextlib.suppress(OSError):
                os.close(fd)
        self._thread.join(timeout=5.0)


def assert_reader_reads_real_gsm7252ps(reader: CliReader) -> None:
    """Drive a CliReader over the transport-under-test and assert it recovers
    the SAME values as the SSH/fixture parser path -- proving the transport
    carried the real captured bytes end to end.

    Every ``show`` here maps 1:1 to a captured fixture; multi-round-trip ops
    (``get_vlans`` walks every VLAN id, ``get_stats`` every port) are exercised
    at the single-fixture granularity we actually captured, via the reader's
    session directly, rather than fabricating the un-captured commands.
    """
    # get_ports -> `show port all`: 52 physical ports, port 1 up at 1G.
    ports = {p.port: p for p in reader.get_ports()}
    assert len(ports) == 52
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 1000

    # get_mgmt_ip -> `show network`: the switch's real base MAC + address.
    mgmt = reader.get_mgmt_ip()
    assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
    assert mgmt.address == "10.1.5.22"

    # identify -> `show version`.
    assert reader.identify().key == "gsm7252ps"

    # VLANs: brief lists 90 -> "iot", and the VLAN 90 detail confirms name +
    # members (a full get_vlans() would need every VLAN's detail, only 90 was
    # captured, so drive the two captured commands directly).
    from netgear_switch.protocols.cli import parse

    brief = parse.parse_vlan_brief(reader.session.run("show vlan brief"))
    assert (90, "iot") in brief
    vlan90 = parse.parse_vlan_detail(reader.session.run("show vlan 90"), name="iot")
    assert vlan90.name == "iot"
    assert 1 in vlan90.member_ports

    # get_pvids -> `show vlan port all`.
    assert dict(reader.get_pvids())[1] == 90

    # get_macs -> `show mac-addr-table`.
    assert any(m.mac == "02:00:0A:01:01:01" for m in reader.get_macs())

    # get_lldp -> `show lldp remote-device all`.
    lldp = reader.get_lldp()
    assert lldp[0].local_port == 1
    assert lldp[0].remote_sys_name == "rpi5-pmod"

    # get_poe -> `show poe port info all`.
    from netgear_switch.models import PoEDetect

    poe = {p.port: p for p in reader.get_poe()}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 3600

    # get_sensors -> `show environment`.
    sensors = reader.get_sensors()
    assert sensors
    assert {s.kind for s in sensors} <= {"temperature", "fan", "power"}
