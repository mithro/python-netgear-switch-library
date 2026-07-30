"""Synchronous NSDP UDP transport (stdlib sockets only).

Binds a UDP client port and exchanges one request/response datagram with the
switch over unicast (the ``query_ip`` pattern — preferred over broadcast
discovery for a known host). ``client_port`` defaults to the real NSDP client
port 63321, but the virtual face lets tests pass ``client_port=0`` to bind an
unprivileged ephemeral port on loopback (so no root/CAP_NET_BIND_SERVICE and no
SO_BINDTODEVICE are needed under test). Errors (timeout / malformed / bad
password) surface as ``NsdpError``, never silently.
"""

from __future__ import annotations

import contextlib
import socket
from typing import TYPE_CHECKING, Any

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
    from collections.abc import Callable

    from ...protocols.nsdp.protocol import TLVEntry

_DUMMY_MAC = b"\x00\x00\x00\x00\x00\x01"
_BROADCAST_MAC = b"\x00" * 6


class UdpNsdpClient:
    """Sync NSDP read+write client over UDP for a single switch."""

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
        sock_factory: Callable[..., Any] = socket.socket,
    ) -> None:
        self.host = host
        self._interface = interface
        self._client_port = client_port
        self._server_port = server_port
        self._timeout = timeout
        # "auto" (detect via AUTH_V2_ENCPASS on first write), "v1", or "v2".
        self._auth_scheme = auth_scheme
        self._sock_factory = sock_factory
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

    def _exchange(self, request: NSDPPacket) -> NSDPPacket:
        sock = self._sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self._interface is not None:
                # Bind the query to the switch's interface so it egresses that
                # segment (and its unicast reply is captured here) even on a
                # multi-homed host. This is what makes a UNICAST NSDP query to a
                # known switch reliable -- verified against real hardware and
                # matching the reference implementation. SO_BINDTODEVICE needs
                # CAP_NET_RAW/root, so it is BEST-EFFORT: an unprivileged caller
                # still attempts the query (and succeeds on a directly-attached
                # segment), never crashing on the missing privilege.
                with contextlib.suppress(OSError):
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_BINDTODEVICE,
                        self._interface.encode() + b"\0",
                    )
            sock.bind(("", self._client_port))
            sock.settimeout(self._timeout)
            sock.sendto(request.encode(), (self.host, self._server_port))
            try:
                data, _addr = sock.recvfrom(4096)
            except TimeoutError as exc:
                raise NsdpError(f"NSDP request to {self.host} timed out") from exc
            try:
                return NSDPPacket.decode(data)
            except ValueError as exc:
                raise NsdpError(
                    f"malformed NSDP response from {self.host}: {exc}"
                ) from exc
        finally:
            sock.close()

    def read(self, tags: list[Tag]) -> NSDPPacket:
        req = build_read_request(
            self._client_mac, _BROADCAST_MAC, self._next_seq(), tags
        )
        resp = self._exchange(req)
        if resp.op != Op.READ_RESPONSE:
            raise NsdpError(f"expected READ_RESPONSE from {self.host}, got {resp.op}")
        return resp

    def _resolve_scheme(self) -> str:
        """Determine (and cache) the write-auth scheme via AUTH_V2_ENCPASS."""
        if self._auth_scheme in ("v1", "v2"):
            return self._auth_scheme
        enc = first_tlv_value(self.read([Tag.AUTH_V2_ENCPASS]), Tag.AUTH_V2_ENCPASS)
        self._auth_scheme = "v2" if encpass_is_v2(enc or b"") else "v1"
        return self._auth_scheme

    def _build_write(
        self, tlvs: list[TLVEntry], password: str
    ) -> NSDPPacket:
        if self._resolve_scheme() == "v2":
            # Fresh challenge: read the rotating salt (its response header also
            # carries the switch MAC the token folds in), then trail the config
            # TLVs with the 8-byte AUTH_V2_PASSWORD token.
            salt_resp = self.read([Tag.AUTH_V2_SALT])
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

    def write(self, tlvs: list[TLVEntry], *, password: str) -> NSDPPacket:
        resp = self._exchange(self._build_write(tlvs, password))
        # Guard the op-code before trusting result (symmetric with read()): a
        # misrouted/duplicate UDP datagram (e.g. a stray READ_RESPONSE with
        # result=0) must not silently pass check_result as a successful write.
        if resp.op != Op.WRITE_RESPONSE:
            raise NsdpError(f"expected WRITE_RESPONSE from {self.host}, got {resp.op}")
        check_result(resp)
        return resp
