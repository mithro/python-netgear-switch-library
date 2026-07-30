"""Thin serial-console CLI transport (implements ``CliSession``), transport-only.

Reuses the SAME ``ShellDriver``/parsers as the SSH transport, carrying bytes over
a local serial line (``pyserial``, the ``[ssh]`` extra) instead of a network
socket. Used to reach a switch's physical console port. Cannot be exercised from
CI (no serial hardware); transport-only, parser-shared.

pyserial is imported lazily so ``import netgear_switch`` never depends on it.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from .session import CliSession, CliTransportError, ShellDriver

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec

# NETGEAR console ports default to 115200 8N1.
_DEFAULT_BAUD = 115200
_DEFAULT_TIMEOUT = 20.0


class ConsoleCliTransport(CliSession):
    """A serial-console interactive-shell CLI session over ``pyserial``."""

    def __init__(
        self,
        device: str,
        username: str,
        password: str,
        spec: CliModelSpec,
        *,
        baudrate: int = _DEFAULT_BAUD,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._device = device
        self._username = username
        self._password = password
        self._spec = spec
        self._baudrate = baudrate
        self._timeout = timeout
        self._serial: Any = None
        self._driver: ShellDriver | None = None

    def _login(self, ser: Any) -> None:
        # Prod the console (it may already be at a prompt) then answer the
        # User:/Password: login the shared driver's setup() does not cover.
        ser.write(b"\r\n")
        ser.write(self._username.encode("latin-1") + b"\r\n")
        ser.write(self._password.encode("latin-1") + b"\r\n")

    def connect(self) -> None:
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise CliTransportError(
                "console CLI transport requires pyserial (install the '[ssh]' extra)"
            ) from exc
        try:
            ser = serial.Serial(
                self._device, baudrate=self._baudrate, timeout=self._timeout
            )
            self._login(ser)
        except Exception as exc:
            self.close()
            raise CliTransportError(f"console open/login failed: {exc}") from exc
        self._serial = ser
        self._driver = ShellDriver(
            ser.write,
            ser.read,
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

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        if self._driver is None:
            self.connect()
        assert self._driver is not None
        return self._driver.run_scp_copy(command, scp_password)

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        if self._driver is None:
            self.connect()
        assert self._driver is not None
        return self._driver.run_write_memory(command, prestuff=prestuff)

    def close(self) -> None:
        if self._serial is not None:
            with contextlib.suppress(Exception):  # teardown must not raise
                self._serial.close()
            self._serial = None
        self._driver = None
