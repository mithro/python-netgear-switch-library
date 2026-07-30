"""A real UDP NSDP responder serving a VirtualSwitchState.

Mirrors the pysnmp face pattern (Task 15's ``VirtualSnmpFace``) but for the far
simpler NSDP wire protocol: a single background thread with one UDP socket bound
to an ephemeral port on loopback (so no root, no privileged 63321/63322 bind,
no SO_BINDTODEVICE). It answers READ_REQUEST from ``state.nsdp_tlvs`` and applies
WRITE_REQUEST after validating the v1 ``PASSWORD`` TLV (a mismatch returns result
0x0700, exactly as real hardware does — the transport turns that into an
``NsdpError``). ``stop()`` closes the socket deterministically so no
ResourceWarning is emitted under ``-W error::ResourceWarning``.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from typing import TYPE_CHECKING

from ...protocols.nsdp.auth import encode_password_v1
from ...protocols.nsdp.protocol import (
    ERROR_AUTH_VERSION,
    ERROR_READONLY,
    NSDPPacket,
    Op,
    Tag,
)
from ...protocols.nsdp.write import RESULT_BAD_PASSWORD, RESULT_SUCCESS

if TYPE_CHECKING:
    from ..state import VirtualSwitchState


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
        resp.tlvs = self._state.nsdp_tlvs(tags)
        # A SOLE unanswerable tag is an ERROR, not an empty success. MEASURED on
        # a real GS110EMX (10.1.5.25, fw 1.0.2.8, 2026-07-30): reading one tag
        # this firmware does not serve comes back with header error code 3 and
        # the error-attribute field naming that tag, whereas the same tag mixed
        # into a multi-tag read is simply OMITTED and the reply is error 0
        # (checked directly: [MODEL, LOOP_DETECTION] -> error 0, one MODEL TLV).
        # The mock used to answer an empty success in BOTH cases, so nothing in
        # CI could tell a tag this model lacks from a tag it merely has no value
        # for -- which is exactly how "NSDP has no PoE/FDB/LLDP tag" stayed an
        # unfalsifiable claim.
        if not resp.tlvs and len(req.tlvs) == 1 and req.tlvs[0].tag != Tag.END_OF_MARK:
            resp.result = ERROR_READONLY << 8
            resp.error_attr = int(req.tlvs[0].tag)
        return resp

    def _write_response(self, req: NSDPPacket) -> NSDPPacket:
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
        if self._state.nsdp_auth_v2_only:
            # This firmware refuses v1/plaintext auth outright -- error 13 with
            # the PASSWORD attribute blamed, BEFORE it even looks at the value.
            # See VirtualSwitchState.nsdp_auth_v2_only for the capture.
            resp.result = ERROR_AUTH_VERSION << 8
            resp.error_attr = int(Tag.PASSWORD)
            return resp
        if not password_ok:
            resp.result = RESULT_BAD_PASSWORD
            resp.error_attr = int(Tag.PASSWORD)
            return resp
        for tlv in req.tlvs:
            if tlv.tag != Tag.PASSWORD:
                self._state.apply_nsdp_write(tlv.tag, tlv.value)
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
