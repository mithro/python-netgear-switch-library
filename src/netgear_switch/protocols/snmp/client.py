"""Shared SNMP transport seam: row type, error, and client protocols.

Pure and I/O-free, and transport-agnostic. The net-snmp CLI (sync) and pysnmp
(async) transports both implement these protocols and return SnmpRow instances
the parsers consume. No transport-specific types appear here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ...errors import NetgearSwitchError

if TYPE_CHECKING:
    from .write import SetVarbind

# snmp_type tokens meaning "no value present here".
ABSENT_TYPES: frozenset[str] = frozenset(
    {"NOSUCHOBJECT", "NOSUCHINSTANCE", "ENDOFMIBVIEW"}
)


@dataclass(frozen=True)
class SnmpRow:
    """One SNMP varbind: full numeric OID, normalized value, type token.

    ``value`` is a normalized Python value so the sync (net-snmp CLI) and async
    (pysnmp) clients are interchangeable: ``int`` for integer-family types
    (INTEGER/Gauge32/Counter32/Counter64/Timeticks-numeric), ``str`` for text,
    OID and IP-address values, ``bytes`` for raw octet strings (Hex-STRING).
    Both clients MUST yield equal values for the same OID (Task 16 enforces it).
    """

    oid: str
    value: int | str | bytes
    snmp_type: str


class SnmpError(NetgearSwitchError):
    """An SNMP transport operation failed (timeout, connection, agent error)."""


def full_oid(oid: str, oid_index: str) -> str:
    """Join an optional instance index onto a base OID as a full numeric OID.

    A transport may hand back the whole numeric OID in ``oid`` with an empty
    ``oid_index``, or split the instance into ``oid_index``. Joining both and
    stripping any leading dot is correct either way.
    """
    oid = oid.lstrip(".")
    return f"{oid}.{oid_index}" if oid_index else oid


class SnmpClient(Protocol):
    """Synchronous SNMP v2c read client for a single switch."""

    def get(self, oids: list[str]) -> list[SnmpRow]: ...

    def walk(self, base_oid: str) -> list[SnmpRow]: ...


class AsyncSnmpClient(Protocol):
    """Asynchronous SNMP v2c read client for a single switch."""

    async def get(self, oids: list[str]) -> list[SnmpRow]: ...

    async def walk(self, base_oid: str) -> list[SnmpRow]: ...


class SnmpWriteClient(SnmpClient, Protocol):
    """Synchronous SNMP v2c read+write client for a single switch.

    Extends the read client with SET. ``set_many`` is one PDU (atomic). A write
    RW community can also read, so a single write client verifies its own
    writes via the inherited ``get``/``walk``.
    """

    def set(self, varbind: SetVarbind) -> None: ...

    def set_many(self, varbinds: list[SetVarbind]) -> None: ...


class AsyncSnmpWriteClient(AsyncSnmpClient, Protocol):
    """Asynchronous SNMP v2c read+write client for a single switch."""

    async def set(self, varbind: SetVarbind) -> None: ...

    async def set_many(self, varbinds: list[SetVarbind]) -> None: ...
