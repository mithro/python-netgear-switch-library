"""Asynchronous NSDP UDP transport (stdlib asyncio datagram endpoint).

Mirrors the sync ``UdpNsdpClient`` but over ``loop.create_datagram_endpoint``.
The datagram exchange is factored into an injectable ``transceive`` coroutine so
read/write are unit-testable with a fake exchange (no real UDP), the async
analogue of the sync client's ``sock_factory`` seam. As with the sync client,
``client_port=0`` binds an unprivileged ephemeral port for the virtual face.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from ...protocols.nsdp.auth import auth_v2_password, encpass_is_v2
from ...protocols.nsdp.client import (
    NsdpError,
    check_result,
    first_tlv_value,
    read_interface_mac,
)
from ...protocols.nsdp.protocol import NSDPPacket, Op, Tag
from ...protocols.nsdp.write import (
    build_read_request,
    build_write_request,
    build_write_request_v2,
)

if TYPE_CHECKING:
    from ...protocols.nsdp.protocol import TLVEntry

Transceive = Callable[..., Awaitable[bytes]]

_DUMMY_MAC = b"\x00\x00\x00\x00\x00\x01"
_BROADCAST_MAC = b"\x00" * 6


class _OneShotProtocol(asyncio.DatagramProtocol):
    """Resolves a future with the first datagram (or an error) received."""

    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, _addr: object) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def _udp_transceive(
    payload: bytes,
    addr: tuple[str, int],
    *,
    client_port: int,
    interface: str | None,
    timeout: float,
) -> bytes:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if interface is not None:
            # Bind the query to the switch's interface so it egresses that
            # segment and its unicast reply is captured here (multi-homed host).
            # This is what makes a unicast NSDP query reliable. SO_BINDTODEVICE
            # needs CAP_NET_RAW/root, so it is BEST-EFFORT -- an unprivileged
            # caller still attempts the query rather than crashing. Mirrors the
            # sync UdpNsdpClient._exchange.
            with contextlib.suppress(OSError):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    interface.encode() + b"\0",
                )
        sock.bind(("", client_port))
        future: asyncio.Future[bytes] = loop.create_future()
        transport, _proto = await loop.create_datagram_endpoint(
            lambda: _OneShotProtocol(future), sock=sock
        )
    except BaseException:
        # setsockopt/bind (or the endpoint handoff itself) failed before
        # create_datagram_endpoint took ownership of the socket on success —
        # nothing else will ever close it, so close it here to avoid an fd
        # leak. Once the try above succeeds, only the transport (below) owns
        # the socket and closes it.
        sock.close()
        raise
    try:
        transport.sendto(payload, addr)
        return await asyncio.wait_for(future, timeout)
    finally:
        transport.close()


class AsyncUdpNsdpClient:
    """Async NSDP read+write client over UDP for a single switch."""

    def __init__(
        self,
        host: str,
        *,
        interface: str | None = None,
        client_mac: bytes | None = None,
        client_port: int = 63321,
        server_port: int = 63322,
        timeout: float = 2.0,
        auth_scheme: str = "auto",
        transceive: Transceive = _udp_transceive,
    ) -> None:
        self.host = host
        self._interface = interface
        self._client_port = client_port
        self._server_port = server_port
        self._timeout = timeout
        # "auto" (detect via AUTH_V2_ENCPASS on first write), "v1", or "v2".
        self._auth_scheme = auth_scheme
        self._transceive = transceive
        self._sequence = 0
        if client_mac is not None:
            self._client_mac = client_mac
        elif interface is not None:
            self._client_mac = read_interface_mac(interface)
        else:
            self._client_mac = _DUMMY_MAC

    def _next_seq(self) -> int:
        self._sequence = (self._sequence + 1) & 0xFFFF
        return self._sequence

    async def _exchange(self, request: NSDPPacket) -> NSDPPacket:
        try:
            data = await self._transceive(
                request.encode(),
                (self.host, self._server_port),
                client_port=self._client_port,
                interface=self._interface,
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            raise NsdpError(f"NSDP request to {self.host} timed out") from exc
        try:
            return NSDPPacket.decode(data)
        except ValueError as exc:
            raise NsdpError(f"malformed NSDP response from {self.host}: {exc}") from exc

    async def read(self, tags: list[Tag]) -> NSDPPacket:
        req = build_read_request(
            self._client_mac, _BROADCAST_MAC, self._next_seq(), tags
        )
        resp = await self._exchange(req)
        if resp.op != Op.READ_RESPONSE:
            raise NsdpError(f"expected READ_RESPONSE from {self.host}, got {resp.op}")
        return resp

    async def _resolve_scheme(self) -> str:
        """Determine (and cache) the write-auth scheme via AUTH_V2_ENCPASS."""
        if self._auth_scheme in ("v1", "v2"):
            return self._auth_scheme
        resp = await self.read([Tag.AUTH_V2_ENCPASS])
        enc = first_tlv_value(resp, Tag.AUTH_V2_ENCPASS)
        self._auth_scheme = "v2" if encpass_is_v2(enc or b"") else "v1"
        return self._auth_scheme

    async def _build_write(
        self, tlvs: list[TLVEntry], password: str
    ) -> NSDPPacket:
        if await self._resolve_scheme() == "v2":
            # Fresh challenge: read the rotating salt (its response header also
            # carries the switch MAC the token folds in), then LEAD the packet
            # with the 8-byte AUTH_V2_PASSWORD token, config TLVs after it.
            salt_resp = await self.read([Tag.AUTH_V2_SALT])
            salt = first_tlv_value(salt_resp, Tag.AUTH_V2_SALT)
            if salt is None:
                raise NsdpError(
                    f"{self.host} advertised v2 auth but returned no "
                    "AUTH_V2_SALT (0x0017)"
                )
            token = auth_v2_password(password, salt_resp.server_mac, salt)
            return build_write_request_v2(
                self._client_mac, _BROADCAST_MAC, self._next_seq(), tlvs, token
            )
        return build_write_request(
            self._client_mac, _BROADCAST_MAC, self._next_seq(), password, tlvs
        )

    async def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket:
        resp = await self._exchange(await self._build_write(tlvs, password))
        # Guard the op-code before trusting result (symmetric with read()): a
        # misrouted/duplicate UDP datagram (e.g. a stray READ_RESPONSE with
        # result=0) must not silently pass check_result as a successful write.
        if resp.op != Op.WRITE_RESPONSE:
            raise NsdpError(f"expected WRITE_RESPONSE from {self.host}, got {resp.op}")
        check_result(resp)
        return resp
