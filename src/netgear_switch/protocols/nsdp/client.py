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


def _attr_name(tag: int) -> str:
    """Name the TLV tag the switch blamed, for the error message."""
    from .protocol import Tag as _Tag

    try:
        return f"{_Tag(tag).name} (0x{tag:04x})"
    except ValueError:
        return f"tag 0x{tag:04x}"


def check_result(packet: NSDPPacket) -> None:
    """Raise ``NsdpError`` unless the response reports success (result 0x0000).

    The 2-byte ``result`` is (error-byte << 8 | unk1); the error CODE alone is
    ``result >> 8`` (``NSDPPacket.error_code``). Codes seen on real rejections:
    3 = read-only, 4 = write-only, 7 = v1 denial, 13 = write auth refused,
    14 = write lockout.

    Every message NAMES the TLV tag the switch blamed (header bytes 4-5),
    because the switch tells us and a caller cannot debug "the request failed"
    otherwise (principle 1). That blamed tag is also what separates the two
    causes of error 13: attr 0x000A (ATTR_PASSWORD) means a v1 XOR password was
    offered to a firmware that only accepts the v2 salted challenge-response --
    a WIRING problem, not a credential one, and an operator told "bad password"
    there rotates a credential that was never wrong. Error 13 on any other attr
    really is a bad password: this library IMPLEMENTS v2 auth
    (``auth.auth_v2_password``, live-verified on a GS110EMX), so a rejected
    token means the password is wrong or the salt it was folded against
    went stale.
    """
    if packet.result == RESULT_SUCCESS:
        return
    from .protocol import (
        ERROR_AUTH_REJECTED,
        ERROR_DENIED,
        ERROR_LOCKED,
        ERROR_NAMES,
        Tag,
    )

    code = packet.error_code
    attr = packet.error_attr
    blamed = _attr_name(attr) if attr else "no attribute"
    detail = ERROR_NAMES.get(code, f"unknown error code {code}")
    if code == ERROR_AUTH_REJECTED and attr == Tag.PASSWORD:
        raise NsdpError(
            f"NSDP write rejected at {blamed}: error {code} ({detail}) -- this "
            "firmware refuses the v1 XOR password and requires the v2 salted "
            "challenge-response, which this library implements; let the client "
            "auto-detect the scheme (auth_scheme='auto') or force 'v2' rather "
            "than 'v1'"
        )
    if code in (ERROR_DENIED, ERROR_AUTH_REJECTED):
        raise NsdpError(
            f"NSDP write rejected: bad password (error 0x{code:02x}) at {blamed}"
        )
    if code == ERROR_LOCKED:
        raise NsdpError(
            f"NSDP write locked out after repeated auth failures (error "
            f"0x{code:02x}) at {blamed}; the switch goes silent for a cooldown "
            "-- pace writes and retry"
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
