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


def _attr_name(tag: int) -> str:
    """Name the TLV tag the switch blamed, for the error message."""
    from .protocol import Tag as _Tag

    try:
        return f"{_Tag(tag).name} (0x{tag:04x})"
    except ValueError:
        return f"tag 0x{tag:04x}"


def check_result(packet: NSDPPacket) -> None:
    """Raise ``NsdpError`` unless the response reports success (result 0x0000).

    The message names the offending TLV tag (header bytes 4-5), because the
    switch tells us and a caller cannot debug "the request failed" otherwise
    (principle 1). The auth-version codes are called out by name: they are what
    a real GS110EMX answers when it wants the v2 salted auth this library does
    not implement, and they are NOT the classic 0x0700 bad-password result -- an
    operator otherwise reads them as "wrong password" and rotates a credential
    that was never wrong.
    """
    if packet.result == RESULT_SUCCESS:
        return
    from .protocol import (
        ERROR_AUTH_VERSION,
        ERROR_AUTH_VERSION_ALT,
        ERROR_NAMES,
        Tag,
    )

    code = packet.error_code
    blamed = _attr_name(packet.error_attr) if packet.error_attr else "no attribute"
    detail = ERROR_NAMES.get(code, f"unknown error code {code}")
    if code in (ERROR_AUTH_VERSION, ERROR_AUTH_VERSION_ALT):
        raise NsdpError(
            f"NSDP write rejected by {blamed}: error {code} ({detail}). "
            f"{AUTH_V2_UNSUPPORTED}"
        )
    if packet.result == RESULT_BAD_PASSWORD and packet.error_attr in (0, Tag.PASSWORD):
        raise NsdpError(
            f"NSDP write rejected: bad password (result 0x0700). {AUTH_V2_UNSUPPORTED}"
        )
    raise NsdpError(
        f"NSDP request failed with result 0x{packet.result:04x} "
        f"(error {code}: {detail}) on {blamed}"
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
