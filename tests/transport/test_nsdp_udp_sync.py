from __future__ import annotations

import asyncio
import socket

import pytest

from netgear_switch.protocols.nsdp import write
from netgear_switch.protocols.nsdp.client import NsdpError, check_result
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.transport.aio.nsdp_udp import AsyncUdpNsdpClient, _udp_transceive
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient

_MAC = b"\x00\x00\x00\x00\x00\x01"


class _FakeSocket:
    """Records sendto and returns a scripted recvfrom response (or raises).

    ``fail_on_opt`` (e.g. ``socket.SO_BINDTODEVICE``) makes ``setsockopt``
    raise ``OSError`` for that specific option only -- mirrors the async
    ``_FakeAioSocket``'s same-named parameter, for proving the sync
    ``UdpNsdpClient._exchange``'s SO_BINDTODEVICE ``contextlib.suppress``
    actually suppresses a real failure (not just never hitting one).
    """

    def __init__(self, response: bytes | None, *, fail_on_opt: int | None = None):
        self._response = response
        self._fail_on_opt = fail_on_opt
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.opts: list[tuple[int, int]] = []
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def setsockopt(self, level, opt, val):
        self.opts.append((level, opt))
        if opt == self._fail_on_opt:
            raise OSError("Operation not permitted")

    def bind(self, addr):
        self.bound = addr

    def settimeout(self, t):
        self._timeout = t

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, bufsize):
        if self._response is None:
            raise TimeoutError("timed out")
        return self._response, ("127.0.0.1", 63322)

    def close(self):
        self.closed = True


def _response_packet(result: int = 0, op: Op = Op.READ_RESPONSE) -> bytes:
    pkt = NSDPPacket(op=op, client_mac=_MAC, server_mac=b"\xaa" * 6, result=result)
    pkt.add_tlv(Tag.MODEL, b"GS110EMX")
    return pkt.encode()


def _client(
    response: bytes | None, auth_scheme: str = "auto"
) -> tuple[UdpNsdpClient, list[_FakeSocket]]:
    made: list[_FakeSocket] = []

    def factory(*_a, **_k):
        s = _FakeSocket(response)
        made.append(s)
        return s

    return UdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        server_port=63322,
        client_mac=_MAC,
        auth_scheme=auth_scheme,
        sock_factory=factory,
    ), made


def test_read_sends_read_request_and_decodes_response():
    client, made = _client(_response_packet())
    pkt = client.read([Tag.MODEL, Tag.PORT_STATUS])
    assert pkt.op == Op.READ_RESPONSE
    assert pkt.tlvs[0].value == b"GS110EMX"
    # A READ_REQUEST datagram went to the server port; socket was closed.
    sent_data, addr = made[0].sent[0]
    assert addr == ("127.0.0.1", 63322)
    assert NSDPPacket.decode(sent_data).op == Op.READ_REQUEST
    assert made[0].closed is True


def test_timeout_raises_nsdperror():
    client, _ = _client(None)
    with pytest.raises(NsdpError, match="timed out"):
        client.read([Tag.MODEL])


def test_interface_binds_to_device_and_unicasts_to_host(monkeypatch):
    # A real switch (interface set) is queried by UNICAST to the host, with the
    # socket bound to the switch's interface (SO_BINDTODEVICE) so the query
    # egresses that segment on a multi-homed host. This is the reliable path
    # verified against real hardware.
    monkeypatch.setattr(
        "netgear_switch.transport.sync.nsdp_udp.read_interface_mac", lambda _i: _MAC
    )
    fake = _FakeSocket(_response_packet())
    client = UdpNsdpClient(
        "10.1.5.25",
        interface="br-net",
        client_port=63321,
        server_port=63322,
        sock_factory=lambda *a, **k: fake,
    )
    pkt = client.read([Tag.MODEL])
    assert pkt.op == Op.READ_RESPONSE
    assert fake.sent[0][1] == ("10.1.5.25", 63322)  # unicast to the switch
    assert socket.SO_BINDTODEVICE in [o for _lvl, o in fake.opts]
    assert fake.closed is True


def test_async_interface_binds_to_device_and_unicasts_to_host(monkeypatch):
    """Async twin of ``test_interface_binds_to_device_and_unicasts_to_host``:
    a real switch (interface set) is queried by UNICAST to the host, with
    SO_BINDTODEVICE attempted (best-effort). Exercised against a REAL
    ``VirtualNsdpFace`` over loopback with the real (non-fake) ``_udp_transceive``
    -- unlike the sync test's fully-faked socket, the async transport's real
    work happens inside asyncio's datagram-endpoint machinery, so this
    subclasses the real ``socket.socket`` (rather than replacing it with a
    bare fake) to both record the SO_BINDTODEVICE attempt AND stay a fully
    working socket for asyncio to bind/send/receive on.
    """
    from netgear_switch.virtual.faces.nsdp import VirtualNsdpFace
    from netgear_switch.virtual.seed import seed_gs110emx

    recorded_opts: list[tuple[int, int]] = []
    real_socket_cls = socket.socket

    class _RecordingSocket(real_socket_cls):
        def setsockopt(self, level, optname, *a, **kw):
            recorded_opts.append((level, optname))
            return super().setsockopt(level, optname, *a, **kw)

    monkeypatch.setattr(
        "netgear_switch.transport.aio.nsdp_udp.socket.socket",
        lambda *a, **k: _RecordingSocket(*a, **k),
    )

    state = seed_gs110emx()
    face = VirtualNsdpFace(state, host="127.0.0.1")
    port = face.start()
    try:
        client = AsyncUdpNsdpClient(
            "127.0.0.1",
            interface="lo",
            client_mac=_MAC,
            client_port=0,
            server_port=port,
        )
        pkt = asyncio.run(client.read([Tag.MODEL]))
    finally:
        face.stop()

    assert pkt.op == Op.READ_RESPONSE  # the unicast query really reached the switch
    assert socket.SO_BINDTODEVICE in [opt for _lvl, opt in recorded_opts]


def test_sync_bindtodevice_is_best_effort(monkeypatch):
    # SO_BINDTODEVICE requires CAP_NET_RAW/root; an unprivileged caller must
    # NOT be broken by its failure. Sync twin of the async
    # test_udp_transceive_bindtodevice_is_best_effort: a SO_BINDTODEVICE-only
    # OSError from setsockopt must be suppressed by UdpNsdpClient._exchange's
    # contextlib.suppress, so execution still reaches bind/sendto/recvfrom
    # and completes the read successfully.
    monkeypatch.setattr(
        "netgear_switch.transport.sync.nsdp_udp.read_interface_mac", lambda _i: _MAC
    )
    fake = _FakeSocket(_response_packet(), fail_on_opt=socket.SO_BINDTODEVICE)
    client = UdpNsdpClient(
        "10.1.5.25",
        interface="br-net",
        client_port=63321,
        server_port=63322,
        sock_factory=lambda *a, **k: fake,
    )
    pkt = client.read([Tag.MODEL])
    assert pkt.op == Op.READ_RESPONSE  # the read still completed
    assert socket.SO_BINDTODEVICE in [o for _lvl, o in fake.opts]  # attempted
    assert fake.closed is True


def test_malformed_response_raises_nsdperror():
    client, _ = _client(b"not-nsdp-bytes")
    with pytest.raises(NsdpError, match="malformed"):
        client.read([Tag.MODEL])


def test_write_sends_write_request_with_password_and_checks_result():
    # auth_scheme="v1" pins the legacy path (no AUTH_V2_ENCPASS probe) so this
    # single-canned-response fake exercises exactly the v1 write.
    client, made = _client(
        _response_packet(op=Op.WRITE_RESPONSE, result=0), auth_scheme="v1"
    )
    client.write([write.pvid_tlv(1, 90)], password="admin")
    sent_data, _ = made[0].sent[0]
    req = NSDPPacket.decode(sent_data)
    assert req.op == Op.WRITE_REQUEST
    assert req.tlvs[0].tag == Tag.PASSWORD  # v1 auth TLV present


def test_write_bad_password_raises_nsdperror():
    client, _ = _client(
        _response_packet(op=Op.WRITE_RESPONSE, result=0x0700), auth_scheme="v1"
    )
    with pytest.raises(NsdpError, match="bad password"):
        client.write([write.pvid_tlv(1, 90)], password="wrong")


def test_write_wrong_op_response_raises_nsdperror():
    # A stray READ_RESPONSE (result=0) must NOT pass as a successful write.
    client, _ = _client(
        _response_packet(op=Op.READ_RESPONSE, result=0), auth_scheme="v1"
    )
    with pytest.raises(NsdpError, match="expected WRITE_RESPONSE"):
        client.write([write.pvid_tlv(1, 90)], password="admin")


def test_check_result_success_is_silent():
    check_result(NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=_MAC, result=0))


def _fake_transceive(response: bytes | None):
    async def transceive(payload, addr, *, client_port, interface, timeout):
        if response is None:
            raise TimeoutError("timed out")
        return response

    return transceive


def test_async_read_decodes_response():
    client = AsyncUdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        client_mac=_MAC,
        transceive=_fake_transceive(_response_packet()),
    )
    pkt = asyncio.run(client.read([Tag.MODEL]))
    assert pkt.op == Op.READ_RESPONSE
    assert pkt.tlvs[0].value == b"GS110EMX"


def test_async_read_timeout_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        client_mac=_MAC,
        transceive=_fake_transceive(None),
    )
    with pytest.raises(NsdpError, match="timed out"):
        asyncio.run(client.read([Tag.MODEL]))


def test_async_write_bad_password_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        client_mac=_MAC,
        auth_scheme="v1",
        transceive=_fake_transceive(
            _response_packet(op=Op.WRITE_RESPONSE, result=0x0700)
        ),
    )
    with pytest.raises(NsdpError, match="bad password"):
        asyncio.run(client.write([write.pvid_tlv(1, 90)], password="wrong"))


def test_async_write_wrong_op_response_raises_nsdperror():
    # A stray READ_RESPONSE (result=0) must NOT pass as a successful write.
    client = AsyncUdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        client_mac=_MAC,
        auth_scheme="v1",
        transceive=_fake_transceive(_response_packet(op=Op.READ_RESPONSE, result=0)),
    )
    with pytest.raises(NsdpError, match="expected WRITE_RESPONSE"):
        asyncio.run(client.write([write.pvid_tlv(1, 90)], password="admin"))


def test_async_read_malformed_response_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1",
        client_port=0,
        client_mac=_MAC,
        transceive=_fake_transceive(b"not-nsdp-bytes"),
    )
    with pytest.raises(NsdpError, match="malformed"):
        asyncio.run(client.read([Tag.MODEL]))


class _FakeAioSocket:
    """Fake raw socket for ``_udp_transceive``: records setsockopt/close, and
    can be told to raise OSError from every setsockopt (``fail_on='setsockopt'``),
    from a SPECIFIC option only (``fail_on_opt=<opt>``, e.g. SO_BINDTODEVICE), or
    from bind (``fail_on='bind'``) to simulate real-world failures."""

    def __init__(
        self, fail_on: str | None = None, fail_on_opt: int | None = None
    ) -> None:
        self._fail_on = fail_on
        self._fail_on_opt = fail_on_opt
        self.opts: list[int] = []
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def setsockopt(self, level, opt, val):
        self.opts.append(opt)
        if self._fail_on == "setsockopt" or opt == self._fail_on_opt:
            raise OSError("Operation not permitted")

    def bind(self, addr):
        if self._fail_on == "bind":
            raise OSError("Address already in use")
        self.bound = addr

    def close(self):
        self.closed = True


def _run_transceive_with_fake_socket(fake: _FakeAioSocket, monkeypatch, **kwargs):
    # asyncio's own event-loop machinery (e.g. the self-pipe socketpair used
    # by the selector loop) calls socket.socket() internally too, so the loop
    # must exist *before* socket.socket is monkeypatched — otherwise loop
    # creation itself breaks. Create the loop first, patch only around the
    # call under test, then run the coroutine on that already-built loop.
    loop = asyncio.new_event_loop()
    try:
        monkeypatch.setattr(
            "netgear_switch.transport.aio.nsdp_udp.socket.socket",
            lambda *a, **k: fake,
        )
        return loop.run_until_complete(
            _udp_transceive(
                b"payload",
                ("127.0.0.1", 63322),
                client_port=kwargs.get("client_port", 0),
                interface=kwargs.get("interface"),
                timeout=1.0,
            )
        )
    finally:
        loop.close()


def test_udp_transceive_closes_socket_when_bind_fails(monkeypatch):
    fake = _FakeAioSocket(fail_on="bind")
    with pytest.raises(OSError, match="Address already in use"):
        _run_transceive_with_fake_socket(fake, monkeypatch)
    assert fake.closed is True


def test_udp_transceive_bindtodevice_is_best_effort(monkeypatch):
    # SO_BINDTODEVICE requires CAP_NET_RAW/root; an unprivileged caller must
    # NOT be broken by its failure. With an interface set, a SO_BINDTODEVICE-only
    # failure is suppressed, so execution reaches bind() -- here bind is what
    # raises, proving the SO_BINDTODEVICE failure did not short-circuit setup.
    fake = _FakeAioSocket(fail_on="bind", fail_on_opt=socket.SO_BINDTODEVICE)
    with pytest.raises(OSError, match="Address already in use"):
        _run_transceive_with_fake_socket(fake, monkeypatch, interface="eth0")
    assert socket.SO_BINDTODEVICE in fake.opts  # attempted (then suppressed)
    assert fake.closed is True
