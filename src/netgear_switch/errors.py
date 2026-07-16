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


class UnsupportedCapability(NetgearSwitchError):
    """The requested operation is not available on this model/backend."""


class WriteVerificationError(NetgearSwitchError):
    """A write did not read back as expected.

    Carries the observed state before and after the write attempt so callers
    can report exactly what diverged.
    """

    def __init__(self, message: str, *, before: object, after: object) -> None:
        super().__init__(message)
        self.before = before
        self.after = after
