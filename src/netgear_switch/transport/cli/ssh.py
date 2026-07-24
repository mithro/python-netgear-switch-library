"""Paramiko-backed SSH CLI transport (implements ``CliSession``).

paramiko is an OPTIONAL dependency (the ``[ssh]`` extra) and is imported LAZILY
inside ``connect`` -- ``import netgear_switch`` never reaches paramiko, exactly
like the httpx transport under ``transport/http``.

PARAMIKO VERSION DECISION (documented as the reviewer asked)
------------------------------------------------------------
Old FASTPATH firmware (the GSM7252PS/M4300 generation) only offers the legacy
key exchange ``diffie-hellman-group14-sha1`` and the ``ssh-rsa`` (SHA-1) host-key
algorithm. paramiko 3.0 dropped both from its DEFAULT preferred lists (and later
releases removed some legacy SHA-1 primitives outright), so a stock modern
paramiko negotiates NOTHING with these switches and the handshake fails.

Two mitigations, applied together:

1. Pin the dependency to a release that still ships and prefers the legacy
   algorithms -- ``paramiko>=2.12,<3`` (2.12 is CONFIRMED working against a real
   GSM7252PS). This is the ``[ssh]`` extra's constraint in ``pyproject.toml``.
2. Belt-and-suspenders, ALSO re-insert the legacy algorithms into the
   ``Transport``'s preferred KEX / host-key lists explicitly here via
   ``get_security_options()`` when the running paramiko still defines them, so
   the transport keeps working even if a newer paramiko is installed that
   retains the primitives but merely de-prioritised them.

This transport CANNOT be live-tested from CI (no network); it is transport-only,
and the shared ``ShellDriver`` it builds on is unit-tested with a fake channel.
"""
from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from .session import CliSession, CliTransportError, ShellDriver

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec

# Legacy algorithms these old FASTPATH switches require (see module docstring).
_LEGACY_KEX = "diffie-hellman-group14-sha1"
_LEGACY_HOSTKEYS = ("ssh-rsa",)

_DEFAULT_TIMEOUT = 20.0


class SshCliTransport(CliSession):
    """An SSH interactive-shell CLI session over paramiko."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        spec: CliModelSpec,
        *,
        port: int = 22,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._spec = spec
        self._port = port
        self._timeout = timeout
        self._transport: Any = None
        self._channel: Any = None
        self._driver: ShellDriver | None = None

    @staticmethod
    def _prefer_legacy_algorithms(transport: Any) -> None:
        """Re-insert the legacy KEX/host-key algorithms this firmware needs.

        Only touches algorithms the running paramiko still defines, so it is a
        no-op (never an error) on a build that removed them entirely -- there the
        version pin is what keeps things working.
        """
        opts = transport.get_security_options()
        available_kex = set(opts.kex)
        if _LEGACY_KEX in available_kex:
            opts.kex = (_LEGACY_KEX, *(k for k in opts.kex if k != _LEGACY_KEX))
        available_keys = set(opts.key_types)
        wanted_keys = tuple(k for k in _LEGACY_HOSTKEYS if k in available_keys)
        if wanted_keys:
            opts.key_types = (
                *wanted_keys,
                *(k for k in opts.key_types if k not in wanted_keys),
            )

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise CliTransportError(
                "SSH CLI transport requires paramiko (install the '[ssh]' extra)"
            ) from exc
        try:
            transport = paramiko.Transport((self._host, self._port))
            self._prefer_legacy_algorithms(transport)
            transport.start_client(timeout=self._timeout)
            transport.auth_password(self._username, self._password)
            channel = transport.open_session(timeout=self._timeout)
            channel.get_pty()
            channel.invoke_shell()
            channel.settimeout(self._timeout)
        except Exception as exc:
            self.close()
            raise CliTransportError(f"SSH connect/auth failed: {exc}") from exc
        self._transport = transport
        self._channel = channel
        self._driver = ShellDriver(
            channel.sendall,
            channel.recv,
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
        if self._channel is not None:
            with contextlib.suppress(Exception):  # teardown must not raise
                self._channel.close()
            self._channel = None
        if self._transport is not None:
            with contextlib.suppress(Exception):  # teardown must not raise
                self._transport.close()
            self._transport = None
        self._driver = None
