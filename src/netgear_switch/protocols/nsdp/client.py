"""Shared NSDP transport seam: error, result check, and client Protocols.

Pure and transport-agnostic (mirrors ``protocols/snmp/client.py``). ``NsdpError``
lives here beside the protocol rather than in ``errors.py``, matching the
``SnmpError`` precedent; both subclass the shared ``NetgearSwitchError`` base so
callers can still catch the library-wide root.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ...errors import NetgearSwitchError
from .auth import AUTH_V2_UNSUPPORTED
from .write import RESULT_BAD_PASSWORD, RESULT_SUCCESS

if TYPE_CHECKING:
    from .protocol import NSDPPacket, Tag, TLVEntry


class NsdpError(NetgearSwitchError):
    """An NSDP transport operation failed (timeout, malformed, bad password)."""


def read_interface_mac(interface: str) -> bytes:
    """Read a network interface's 6-byte MAC from sysfs (Linux)."""
    text = Path(f"/sys/class/net/{interface}/address").read_text().strip()
    raw = bytes.fromhex(text.replace(":", ""))
    if len(raw) != 6:
        raise NsdpError(f"interface {interface!r} MAC is not 6 bytes: {text!r}")
    return raw


def check_result(packet: NSDPPacket) -> None:
    """Raise ``NsdpError`` unless the response reports success (result 0x0000)."""
    if packet.result == RESULT_SUCCESS:
        return
    if packet.result == RESULT_BAD_PASSWORD:
        raise NsdpError(
            "NSDP write rejected: bad password (result 0x0700). "
            f"{AUTH_V2_UNSUPPORTED}"
        )
    raise NsdpError(f"NSDP request failed with result 0x{packet.result:04x}")


class NsdpClient(Protocol):
    """Synchronous NSDP read client for a single switch."""

    def read(self, tags: list[Tag]) -> NSDPPacket: ...


class NsdpWriteClient(NsdpClient, Protocol):
    """Synchronous NSDP read+write client for a single switch."""

    def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket: ...


class AsyncNsdpClient(Protocol):
    """Asynchronous NSDP read client for a single switch."""

    async def read(self, tags: list[Tag]) -> NSDPPacket: ...


class AsyncNsdpWriteClient(AsyncNsdpClient, Protocol):
    """Asynchronous NSDP read+write client for a single switch."""

    async def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket: ...
