"""Shared NSDP transport seam: error, result check, and client Protocols.

Pure and transport-agnostic (mirrors ``protocols/snmp/client.py``). ``NsdpError``
lives here beside the protocol rather than in ``errors.py``, matching the
``SnmpError`` precedent; both subclass the shared ``NetgearSwitchError`` base so
callers can still catch the library-wide root.
"""
from __future__ import annotations

import fcntl
import socket
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ...errors import NetgearSwitchError
from .auth import AUTH_V2_UNSUPPORTED
from .write import RESULT_BAD_PASSWORD, RESULT_SUCCESS

_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B

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


def interface_broadcast(interface: str) -> str | None:
    """Return the directed IPv4 broadcast address of ``interface``, or None.

    Real Netgear switches answer NSDP only over broadcast, and a non-root
    process cannot force a global 255.255.255.255 datagram out a specific
    interface (that needs SO_BINDTODEVICE / CAP_NET_RAW). The DIRECTED subnet
    broadcast (e.g. 10.1.5.255) is instead delivered by the ordinary connected
    route for the switch's subnet, so it works unprivileged. Derived from the
    interface's own address + netmask via ioctl (Linux). Returns None if the
    interface has no IPv4 address (caller falls back to unicast to the host).
    Shared by the sync and async NSDP transports so both broadcast identically.
    """
    ifname = struct.pack("256s", interface.encode()[:15])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, ifname)[20:24]
        mask = fcntl.ioctl(sock.fileno(), _SIOCGIFNETMASK, ifname)[20:24]
    except (OSError, ValueError):
        # OSError: interface has no IPv4 address; ValueError: invalid fd.
        return None
    finally:
        sock.close()
    ip = int.from_bytes(addr, "big")
    netmask = int.from_bytes(mask, "big")
    broadcast = ip | (~netmask & 0xFFFFFFFF)
    return socket.inet_ntoa(broadcast.to_bytes(4, "big"))


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
