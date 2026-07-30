"""A real UDP NSDP responder serving a VirtualSwitchState.

Mirrors the pysnmp face pattern (Task 15's ``VirtualSnmpFace``) but for the far
simpler NSDP wire protocol: a single background thread with one UDP socket bound
to an ephemeral port on loopback (so no root, no privileged 63321/63322 bind,
no SO_BINDTODEVICE). It answers READ_REQUEST from ``state.nsdp_tlvs`` and applies
WRITE_REQUEST after validating auth.

Two write-auth schemes are modelled, selected by ``state.nsdp_auth_version``
(advertised to clients via the AUTH_V2_ENCPASS read):

* **v1** — validate the XOR ``PASSWORD`` (0x000A) TLV; a mismatch returns error
  byte 7 (result 0x0700).
* **v2** — validate the 8-byte ``AUTH_V2_PASSWORD`` (0x001A) token against
  ``auth_v2_password(password, mac, last-issued salt)``. This reproduces the
  GS110EMX (fw 1.0.2.8) behaviour LIVE-VERIFIED here: config-first + trailing
  0x001A with the right token applies the write (error 0); a wrong token returns
  error 13 and, after a few rapid failures, escalates to error 14 and then goes
  SILENT (no reply) for a cooldown; leading with 0x001A returns error 4; and a
  READ naming write-only 0x001A returns error 3.

``stop()`` closes the socket deterministically so no ResourceWarning is emitted
under ``-W error::ResourceWarning``.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from typing import TYPE_CHECKING

from ...protocols.nsdp.auth import ENCPASS_V2, auth_v2_password, encode_password_v1
from ...protocols.nsdp.protocol import NSDPPacket, Op, Tag
from ...protocols.nsdp.write import (
    RESULT_BAD_PASSWORD,
    RESULT_BAD_PASSWORD_V2,
    RESULT_LOCKED_V2,
    RESULT_READONLY,
    RESULT_SUCCESS,
    RESULT_WRITEONLY,
)

if TYPE_CHECKING:
    from ..state import VirtualSwitchState

# v2 lockout shape (approximate -- the real thresholds are firmware rate-based;
# see the GS110EMX findings). Consecutive wrong tokens return error 13 up to
# _V2_ESCALATE_AT, then error 14, then no reply at all once past _V2_SILENCE_AT.
# A successful write resets the counter.
_V2_ESCALATE_AT = 3
_V2_SILENCE_AT = 5

# Write-only auth tags a READ must not name (real hardware answers error 3).
_WRITE_ONLY_TAGS = frozenset({Tag.AUTH_V2_PASSWORD})


class VirtualNsdpFace:
    """A UDP NSDP command responder serving a ``VirtualSwitchState``."""

    def __init__(
        self, state: VirtualSwitchState, *, host: str = "127.0.0.1", port: int = 0
    ) -> None:
        self._state = state
        self._host = host
        # Requested bind port (0 = ephemeral); the bound port lands in
        # ``self._port`` in ``start()``.
        self._port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._port))
        sock.settimeout(0.2)  # so the serve loop can observe _stop promptly
        self._port = sock.getsockname()[1]
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve, name="virtual-nsdp-face", daemon=True
        )
        self._thread.start()
        return self._port

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                response = self._handle(data)
            except ValueError:
                continue  # malformed request datagram: ignore, as hardware does
            if response is not None:
                with contextlib.suppress(OSError):
                    self._sock.sendto(response.encode(), addr)

    def _handle(self, data: bytes) -> NSDPPacket | None:
        req = NSDPPacket.decode(data)
        if req.op == Op.READ_REQUEST:
            return self._read_response(req)
        if req.op == Op.WRITE_REQUEST:
            return self._write_response(req)
        return None

    def _read_response(self, req: NSDPPacket) -> NSDPPacket:
        # Only catalogued ``Tag`` values are meaningful read requests; a raw
        # uncatalogued int tag (``TLVEntry.decode``'s fallback) can't match
        # anything ``nsdp_tlvs`` knows to serve, so it's dropped here rather
        # than widening ``nsdp_tlvs``'s ``set[Tag]`` contract to ``int`` too.
        tags = {t.tag for t in req.tlvs if isinstance(t.tag, Tag)}
        resp = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=req.client_mac,
            server_mac=self._state.nsdp_mac,
            sequence=req.sequence,
        )
        # A read naming a write-only tag (e.g. AUTH_V2_PASSWORD) is refused with
        # error 3 (read-only), exactly as a real GS110EMX does -- verified live.
        write_only = _WRITE_ONLY_TAGS & tags
        if write_only:
            resp.result = RESULT_READONLY
            resp.errattr = int(next(iter(write_only)))
            return resp
        resp.tlvs = self._state.nsdp_tlvs(tags)
        return resp

    def _write_response(self, req: NSDPPacket) -> NSDPPacket | None:
        if self._state.nsdp_auth_version == ENCPASS_V2:
            return self._write_response_v2(req)
        return self._write_response_v1(req)

    def _write_response_v1(self, req: NSDPPacket) -> NSDPPacket:
        expected = encode_password_v1(self._state.nsdp_password)
        # Plain ``==`` compare is intentionally NOT constant-time: this is a
        # local, loopback-only test mock, not a security boundary.
        password_ok = any(
            t.tag == Tag.PASSWORD and t.value == expected for t in req.tlvs
        )
        resp = NSDPPacket(
            op=Op.WRITE_RESPONSE,
            client_mac=req.client_mac,
            server_mac=self._state.nsdp_mac,
            sequence=req.sequence,
        )
        if not password_ok:
            resp.result = RESULT_BAD_PASSWORD
            return resp
        for tlv in req.tlvs:
            if tlv.tag != Tag.PASSWORD:
                self._state.apply_nsdp_write(tlv.tag, tlv.value)
        resp.result = RESULT_SUCCESS
        return resp

    def _write_response_v2(self, req: NSDPPacket) -> NSDPPacket | None:
        """v2 salted challenge-response. Returns ``None`` (no reply) while the
        lockout is engaged, exactly as the real switch goes silent."""
        resp = NSDPPacket(
            op=Op.WRITE_RESPONSE,
            client_mac=req.client_mac,
            server_mac=self._state.nsdp_mac,
            sequence=req.sequence,
        )
        # Leading with the write-only auth tag is rejected structurally (error
        # 4), before auth is even weighed -- observed live on the GS110EMX.
        if req.tlvs and req.tlvs[0].tag == Tag.AUTH_V2_PASSWORD:
            resp.result = RESULT_WRITEONLY
            resp.errattr = int(Tag.AUTH_V2_PASSWORD)
            return resp
        # Past the silence threshold the switch stops answering writes entirely.
        if self._state.nsdp_auth_failures > _V2_SILENCE_AT:
            return None
        token = next(
            (t.value for t in req.tlvs if t.tag == Tag.AUTH_V2_PASSWORD), None
        )
        salt = self._state.nsdp_last_salt
        expected = (
            auth_v2_password(self._state.nsdp_password, self._state.nsdp_mac, salt)
            if salt is not None
            else None
        )
        if token is None or expected is None or token != expected:
            self._state.nsdp_auth_failures += 1
            resp.result = (
                RESULT_LOCKED_V2
                if self._state.nsdp_auth_failures > _V2_ESCALATE_AT
                else RESULT_BAD_PASSWORD_V2
            )
            # errattr echoes the first TLV of the request (observed: the leading
            # config tag, or the salt echo when one is present).
            resp.errattr = int(req.tlvs[0].tag) if req.tlvs else 0
            return resp
        # Authenticated: apply every config TLV (all but the auth token) and
        # reset the lockout counter.
        for tlv in req.tlvs:
            if tlv.tag != Tag.AUTH_V2_PASSWORD:
                self._state.apply_nsdp_write(tlv.tag, tlv.value)
        self._state.nsdp_auth_failures = 0
        resp.result = RESULT_SUCCESS
        return resp

    def stop(self) -> None:
        """Stop the serve thread and close the socket deterministically."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
        self._port = 0
