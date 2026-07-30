"""Exception hierarchy for netgear_switch."""

from __future__ import annotations


class NetgearSwitchError(Exception):
    """Base class for every error raised by this library."""


class ConfigError(NetgearSwitchError):
    """The inventory/config file is malformed or invalid."""


class CredentialError(NetgearSwitchError):
    """A required secret could not be resolved from any source."""


class UnknownModelError(NetgearSwitchError):
    """A switch references a model key that is not in the registry."""


class UnsupportedCapabilityError(NetgearSwitchError):
    """The requested operation is not available on this model/backend."""


class ProtectedPortError(NetgearSwitchError):
    """A disruptive write targeted a protected port without force=True."""


class WriteVerificationError(NetgearSwitchError):
    """A write did not read back as expected.

    Carries the observed state before and after the write attempt so callers
    can report exactly what diverged.
    """

    def __init__(self, message: str, *, before: object, after: object) -> None:
        super().__init__(message)
        self.before = before
        self.after = after


class CliCommandError(NetgearSwitchError):
    """A FASTPATH CLI command was REJECTED by the device, or a write
    precondition failed before any command was sent.

    The CLI analogue of ``protocols.snmp.client.SnmpError`` for the write path:
    FASTPATH answers an accepted configuration command with EMPTY output, so any
    text back (``% Invalid input``, ``ERROR: ...``) means the command did not
    apply. Distinct from ``WriteVerificationError``, which means the commands
    WERE accepted but the switch did not read back the intended state, and from
    ``transport.cli.session.CliTransportError``, which means the connection /
    prompt framing itself failed.
    """


class HttpError(NetgearSwitchError):
    """An HTTP web-UI transport operation failed (connect, HTTP status, page shape)."""


class HttpAuthError(HttpError):
    """Web-UI login was rejected, or an authenticated session was lost."""


class HttpUnexpectedPageError(HttpError):
    """A web-UI page or token could not be parsed into the expected shape."""
