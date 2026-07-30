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
from .write import RESULT_SUCCESS

if TYPE_CHECKING:
    from .protocol import NSDPPacket, Tag, TLVEntry


class NsdpError(NetgearSwitchError):
    """An NSDP transport operation failed (timeout, malformed, bad password)."""


def first_tlv_value(packet: NSDPPacket, tag: Tag) -> bytes | None:
    """Return the value of the first TLV with ``tag``, or ``None`` if absent."""
    for entry in packet.tlvs:
        if entry.tag == tag:
            return entry.value
    return None


def read_interface_mac(interface: str) -> bytes:
    """Read a network interface's 6-byte MAC from sysfs (Linux)."""
    text = Path(f"/sys/class/net/{interface}/address").read_text().strip()
    raw = bytes.fromhex(text.replace(":", ""))
    if len(raw) != 6:
        raise NsdpError(f"interface {interface!r} MAC is not 6 bytes: {text!r}")
    return raw


def check_result(packet: NSDPPacket) -> None:
    """Raise ``NsdpError`` unless the response reports success (result 0x0000).

    The 2-byte ``result`` is (error-byte << 8 | unk1); the error CODE is
    ``result >> 8``. Codes seen on rejections: 7 = v1 denial, 13 = v2 bad
    password, 14 = v2 write lockout, 3 = read-only, 4 = write-only. The
    offending tag is echoed in ``errattr``.
    """
    if packet.result == RESULT_SUCCESS:
        return
    code = (packet.result >> 8) & 0xFF
    attr = packet.errattr
    if code in (0x07, 0x0D):
        raise NsdpError(
            f"NSDP write rejected: bad password (error 0x{code:02x}, "
            f"attr 0x{attr:04x})"
        )
    if code == 0x0E:
        raise NsdpError(
            "NSDP write locked out after repeated auth failures "
            f"(error 0x0e, attr 0x{attr:04x}); the switch goes silent for a "
            "cooldown -- pace writes and retry"
        )
    raise NsdpError(
        f"NSDP request failed (error 0x{code:02x}, attr 0x{attr:04x}, "
        f"result 0x{packet.result:04x})"
    )


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
