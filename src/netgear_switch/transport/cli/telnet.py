"""Thin telnet CLI transport (implements ``CliSession``), transport-only.

Reuses the SAME ``ShellDriver`` (and therefore the same parsers) as the SSH
transport -- it differs only in carrying bytes over ``telnetlib`` instead of a
paramiko channel. It CANNOT be live-tested from CI (no network) and shares no
parser code that isn't already covered by the SSH/mock paths.

CAVEAT: the stdlib ``telnetlib`` module was DEPRECATED in Python 3.11 and
REMOVED in Python 3.13. It is imported lazily so ``import netgear_switch`` never
depends on it; on 3.13+ constructing this transport raises a clear
``CliTransportError`` telling the caller to use SSH or the console transport
instead. Telnet on a management switch is plaintext and best avoided anyway.
"""
from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from .session import CliSession, CliTransportError, ShellDriver

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec

_DEFAULT_TIMEOUT = 20.0


class TelnetCliTransport(CliSession):
    """A telnet interactive-shell CLI session over ``telnetlib``."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        spec: CliModelSpec,
        *,
        port: int = 23,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._spec = spec
        self._port = port
        self._timeout = timeout
        self._conn: Any = None
        self._driver: ShellDriver | None = None

    def _login(self, conn: Any) -> None:
        # FASTPATH telnet prompts "User:" then "Password:" before the shell.
        conn.read_until(b"User:", timeout=self._timeout)
        conn.write(self._username.encode("latin-1") + b"\r\n")
        conn.read_until(b"Password:", timeout=self._timeout)
        conn.write(self._password.encode("latin-1") + b"\r\n")

    def connect(self) -> None:
        try:
            import telnetlib
        except ImportError as exc:  # pragma: no cover - py3.13+ / optional
            raise CliTransportError(
                "telnet CLI transport requires the stdlib 'telnetlib', removed "
                "in Python 3.13 -- use the SSH or console transport instead"
            ) from exc
        try:
            conn = telnetlib.Telnet(self._host, self._port, timeout=self._timeout)
            self._login(conn)
        except Exception as exc:
            self.close()
            raise CliTransportError(f"telnet connect/login failed: {exc}") from exc
        self._conn = conn
        self._driver = ShellDriver(
            lambda data: conn.write(data),
            lambda n: conn.read_eager() or conn.read_some(),
            enable_cmd=self._spec.enable_cmd,
            paging_off_cmd=self._spec.paging_off_cmd,
            enable_password=self._password,
        )
        self._driver.setup()

    def run(self, command: str) -> str:
        if self._driver is None:
            self.connect()
        assert self._driver is not None
        return self._driver.run(command)

    def close(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):  # teardown must not raise
                self._conn.close()
            self._conn = None
        self._driver = None
