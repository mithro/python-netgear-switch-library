"""Shared CLI context and exit-code policy (leaf module, no cli/ imports)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from netgear_switch.errors import ProtectedPortError, WriteVerificationError

if TYPE_CHECKING:
    from typing import TextIO

    from netgear_switch.errors import NetgearSwitchError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_VERIFY = 3
EXIT_PROTECTED = 4


@dataclass
class CliContext:
    """Streams and global flags threaded through every command handler."""

    out: TextIO
    err: TextIO
    inp: TextIO
    as_json: bool
    verbose: bool


def exit_code_for(exc: NetgearSwitchError) -> int:
    """Map a library error to a distinct process exit code."""
    if isinstance(exc, WriteVerificationError):
        return EXIT_VERIFY
    if isinstance(exc, ProtectedPortError):
        return EXIT_PROTECTED
    return EXIT_ERROR
