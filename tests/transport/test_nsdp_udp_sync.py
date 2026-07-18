from __future__ import annotations

import asyncio

import pytest

from netgear_switch.protocols.nsdp import write
from netgear_switch.protocols.nsdp.client import NsdpError, check_result
from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
from netgear_switch.transport.aio.nsdp_udp import AsyncUdpNsdpClient, _udp_transceive
from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient

_MAC = b"\x00\x00\x00\x00\x00\x01"


class _FakeSocket:
    """Records sendto and returns a scripted recvfrom response (or raises)."""

    def __init__(self, response: bytes | None):
        self._response = response
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.opts: list[tuple[int, int]] = []
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def setsockopt(self, level, opt, val):
        self.opts.append((level, opt))

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


def _client(response: bytes | None) -> tuple[UdpNsdpClient, list[_FakeSocket]]:
    made: list[_FakeSocket] = []

    def factory(*_a, **_k):
        s = _FakeSocket(response)
        made.append(s)
        return s

    return UdpNsdpClient("127.0.0.1", client_port=0, server_port=63322,
                         client_mac=_MAC, sock_factory=factory), made


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


def test_malformed_response_raises_nsdperror():
    client, _ = _client(b"not-nsdp-bytes")
    with pytest.raises(NsdpError, match="malformed"):
        client.read([Tag.MODEL])


def test_write_sends_write_request_with_password_and_checks_result():
    client, made = _client(_response_packet(op=Op.WRITE_RESPONSE, result=0))
    client.write([write.pvid_tlv(1, 90)], password="admin")
    sent_data, _ = made[0].sent[0]
    req = NSDPPacket.decode(sent_data)
    assert req.op == Op.WRITE_REQUEST
    assert req.tlvs[0].tag == Tag.PASSWORD  # v1 auth TLV present


def test_write_bad_password_raises_nsdperror():
    client, _ = _client(_response_packet(op=Op.WRITE_RESPONSE, result=0x0700))
    with pytest.raises(NsdpError, match="bad password"):
        client.write([write.pvid_tlv(1, 90)], password="wrong")


def test_write_wrong_op_response_raises_nsdperror():
    # A stray READ_RESPONSE (result=0) must NOT pass as a successful write.
    client, _ = _client(_response_packet(op=Op.READ_RESPONSE, result=0))
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
        "127.0.0.1", client_port=0, client_mac=_MAC,
        transceive=_fake_transceive(_response_packet()),
    )
    pkt = asyncio.run(client.read([Tag.MODEL]))
    assert pkt.op == Op.READ_RESPONSE
    assert pkt.tlvs[0].value == b"GS110EMX"


def test_async_read_timeout_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1", client_port=0, client_mac=_MAC,
        transceive=_fake_transceive(None),
    )
    with pytest.raises(NsdpError, match="timed out"):
        asyncio.run(client.read([Tag.MODEL]))


def test_async_write_bad_password_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1", client_port=0, client_mac=_MAC,
        transceive=_fake_transceive(
            _response_packet(op=Op.WRITE_RESPONSE, result=0x0700)
        ),
    )
    with pytest.raises(NsdpError, match="bad password"):
        asyncio.run(client.write([write.pvid_tlv(1, 90)], password="wrong"))


def test_async_write_wrong_op_response_raises_nsdperror():
    # A stray READ_RESPONSE (result=0) must NOT pass as a successful write.
    client = AsyncUdpNsdpClient(
        "127.0.0.1", client_port=0, client_mac=_MAC,
        transceive=_fake_transceive(_response_packet(op=Op.READ_RESPONSE, result=0)),
    )
    with pytest.raises(NsdpError, match="expected WRITE_RESPONSE"):
        asyncio.run(client.write([write.pvid_tlv(1, 90)], password="admin"))


def test_async_read_malformed_response_raises_nsdperror():
    client = AsyncUdpNsdpClient(
        "127.0.0.1", client_port=0, client_mac=_MAC,
        transceive=_fake_transceive(b"not-nsdp-bytes"),
    )
    with pytest.raises(NsdpError, match="malformed"):
        asyncio.run(client.read([Tag.MODEL]))


class _FakeAioSocket:
    """Fake raw socket for ``_udp_transceive``: records setsockopt/close,
    and can be told to raise OSError from setsockopt or bind to simulate a
    real-world failure (port conflict, or permission denied on
    SO_BINDTODEVICE without CAP_NET_RAW/root)."""

    def __init__(self, fail_on: str) -> None:
        self._fail_on = fail_on
        self.opts: list[tuple[int, int]] = []
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def setsockopt(self, level, opt, val):
        self.opts.append((level, opt))
        if self._fail_on == "setsockopt":
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
                b"payload", ("127.0.0.1", 63322),
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


def test_udp_transceive_closes_socket_when_bindtodevice_fails(monkeypatch):
    # SO_BINDTODEVICE requires CAP_NET_RAW/root; a caller-supplied interface
    # without privilege is a realistic way for this to raise.
    fake = _FakeAioSocket(fail_on="setsockopt")
    with pytest.raises(OSError, match="Operation not permitted"):
        _run_transceive_with_fake_socket(fake, monkeypatch, interface="eth0")
    assert fake.closed is True
