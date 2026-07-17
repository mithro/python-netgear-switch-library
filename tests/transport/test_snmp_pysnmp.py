# tests/transport/test_snmp_pysnmp.py
from __future__ import annotations

import asyncio
import re
import sys
import types

import pytest

from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.transport.aio.snmp_pysnmp import (
    PysnmpClient,
    _normalize_varbind,
    _octet_value,
)

_MODNAME = "pysnmp.hlapi.v3arch.asyncio"


class Integer32:
    """Stands in for pysnmp's Integer32/Gauge32/etc: int()-convertible.

    Named to match the real pysnmp class, since ``_normalize_varbind``
    dispatches on ``value.__class__.__name__``.
    """

    def __init__(self, value: int) -> None:
        self._value = value

    def __int__(self) -> int:
        return self._value


class OctetString:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def asOctets(self):  # noqa: N802 - mirrors pysnmp's camelCase method name
        return self._data


class IpAddress:
    def __init__(self, text: str) -> None:
        self._text = text

    def prettyPrint(self):  # noqa: N802
        return self._text


class ObjectIdentifier:
    def __init__(self, text: str) -> None:
        self._text = text

    def prettyPrint(self):  # noqa: N802
        return self._text


class _FakeTextual:
    def prettyPrint(self):  # noqa: N802
        return "textual-value"


class NoSuchInstance:
    pass


class NoSuchObject:
    pass


class EndOfMibView:
    pass


def _install_fake_pysnmp(monkeypatch, *, get_cmd=None, bulk_walk_cmd=None):
    """Inject a fake pysnmp.hlapi.v3arch.asyncio module (no network, no import
    of the real async engine) so _do_get/_do_walk can be exercised directly.
    """
    calls: dict[str, object] = {"closed": False}

    class FakeEngine:
        def close_dispatcher(self) -> None:
            calls["closed"] = True

    class FakeUdpTransportTarget:
        @classmethod
        async def create(cls, addr, *, timeout, retries):
            return (addr, timeout, retries)

    fake = types.ModuleType(_MODNAME)
    fake.CommunityData = lambda community: community
    fake.ContextData = lambda: None
    fake.ObjectIdentity = lambda oid: oid
    fake.ObjectType = lambda oid: oid
    fake.SnmpEngine = FakeEngine
    fake.UdpTransportTarget = FakeUdpTransportTarget
    if get_cmd is not None:
        fake.get_cmd = get_cmd
    if bulk_walk_cmd is not None:
        fake.bulk_walk_cmd = bulk_walk_cmd
    monkeypatch.setitem(sys.modules, _MODNAME, fake)
    return calls


def test_get_wraps_normalized_tuples_into_rows(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_do_get(oids):
        # _do_get returns already-normalized (oid, value, token) triples.
        return [("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]

    monkeypatch.setattr(c, "_do_get", fake_do_get)
    rows = asyncio.run(c.get(["1.3.6.1.2.1.2.2.1.8.1"]))
    assert rows == [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]


def test_get_raises_on_absent_oid(monkeypatch):
    """get() must raise SnmpError naming the OID for a requested varbind that
    comes back noSuchObject/noSuchInstance — matching the sync CLI client,
    which raises rather than silently returning nothing for that OID."""
    c = PysnmpClient("h", "public")

    async def fake_do_get(oids):
        return [("1.3.6.1.2.1.2.2.1.8.99", "", "NOSUCHOBJECT")]

    monkeypatch.setattr(c, "_do_get", fake_do_get)
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.2.2.1.8.99")):
        asyncio.run(c.get(["1.3.6.1.2.1.2.2.1.8.99"]))


def test_get_raises_on_no_such_instance(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_do_get(oids):
        return [("1.3.6.1.2.1.2.2.1.8.99", "", "NOSUCHINSTANCE")]

    monkeypatch.setattr(c, "_do_get", fake_do_get)
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.2.2.1.8.99")):
        asyncio.run(c.get(["1.3.6.1.2.1.2.2.1.8.99"]))


def test_walk_filters_absent_and_wraps(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_do_walk(base_oid):
        return [
            ("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER"),
            ("1.3.6.1.2.1.2.2.1.8.2", "", "ENDOFMIBVIEW"),
        ]

    monkeypatch.setattr(c, "_do_walk", fake_do_walk)
    rows = asyncio.run(c.walk("1.3.6.1.2.1.2.2.1.8"))
    assert rows == [SnmpRow("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]


def test_get_error_wraps(monkeypatch):
    c = PysnmpClient("h", "public")

    async def boom(oids):
        raise RuntimeError("engine down")

    monkeypatch.setattr(c, "_do_get", boom)
    with pytest.raises(SnmpError):
        asyncio.run(c.get(["1.3.6.1.2.1.2.2.1.8.1"]))


def test_octet_value_parity_with_netsnmp_cli():
    # Parity: printable octets -> STRING/str; non-printable -> Hex-STRING/bytes,
    # exactly what the net-snmp CLI client (Task 10) renders.
    assert _octet_value(b"1/0/1") == ("1/0/1", "STRING")
    assert _octet_value(bytes([0xC0, 0x00])) == (bytes([0xC0, 0x00]), "Hex-STRING")


def test_get_returns_empty_without_calling_do_get():
    c = PysnmpClient("h", "public")
    assert asyncio.run(c.get([])) == []


def test_get_reraises_snmp_error_unwrapped(monkeypatch):
    c = PysnmpClient("h", "public")

    async def raises_snmp_error(oids):
        raise SnmpError("agent unreachable")

    monkeypatch.setattr(c, "_do_get", raises_snmp_error)
    with pytest.raises(SnmpError, match="agent unreachable"):
        asyncio.run(c.get(["1.3.6.1.2.1.2.2.1.8.1"]))


def test_walk_reraises_snmp_error_unwrapped(monkeypatch):
    c = PysnmpClient("h", "public")

    async def raises_snmp_error(base_oid):
        raise SnmpError("agent unreachable")

    monkeypatch.setattr(c, "_do_walk", raises_snmp_error)
    with pytest.raises(SnmpError, match="agent unreachable"):
        asyncio.run(c.walk("1.3.6.1.2.1.2.2.1.8"))


def test_walk_error_wraps(monkeypatch):
    c = PysnmpClient("h", "public")

    async def boom(base_oid):
        raise RuntimeError("engine down")

    monkeypatch.setattr(c, "_do_walk", boom)
    with pytest.raises(SnmpError):
        asyncio.run(c.walk("1.3.6.1.2.1.2.2.1.8"))


def test_normalize_varbind_absent_ip_oid_and_textual_fallback():
    assert _normalize_varbind("1.2.3", NoSuchInstance()) == (
        "1.2.3", "", "NOSUCHINSTANCE"
    )
    assert _normalize_varbind("1.2.3", OctetString(b"1/0/1")) == (
        "1.2.3", "1/0/1", "STRING"
    )
    assert _normalize_varbind(".1.2.3", IpAddress("10.1.5.20")) == (
        "1.2.3", "10.1.5.20", "IpAddress"
    )
    assert _normalize_varbind("1.2.3", ObjectIdentifier(".1.3.6.1.4.1")) == (
        "1.2.3", "1.3.6.1.4.1", "OID"
    )
    assert _normalize_varbind("1.2.3", _FakeTextual()) == (
        "1.2.3", "textual-value", "_FakeTextual"
    )


def test_do_get_normalizes_binds_via_fake_pysnmp(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_get_cmd(engine, community, target, context, *varbinds):
        binds = [("1.3.6.1.2.1.2.2.1.8.1", Integer32(1))]
        return None, 0, 0, binds

    calls = _install_fake_pysnmp(monkeypatch, get_cmd=fake_get_cmd)
    rows = asyncio.run(c._do_get(["1.3.6.1.2.1.2.2.1.8.1"]))
    assert rows == [("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]
    assert calls["closed"] is True


def test_do_get_raises_on_error_indication(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_get_cmd(engine, community, target, context, *varbinds):
        return "timeout", 0, 0, []

    calls = _install_fake_pysnmp(monkeypatch, get_cmd=fake_get_cmd)
    with pytest.raises(SnmpError):
        asyncio.run(c._do_get(["1.3.6.1.2.1.2.2.1.8.1"]))
    assert calls["closed"] is True


def test_do_walk_raises_on_error_status(monkeypatch):
    """A nonzero errorStatus/errorIndication mid-walk must RAISE, never be
    silently swallowed — otherwise a timeout mid-walk looks identical to a
    completed walk and truncates results without any signal (Fix 2)."""
    c = PysnmpClient("h", "public")

    async def fake_bulk_walk_cmd(
        engine,
        community,
        target,
        context,
        non_rep,
        max_rep,
        obj,
        *,
        lexicographicMode,  # noqa: N803 - matches pysnmp's bulk_walk_cmd kwarg
    ):
        yield None, 0, 0, [("1.3.6.1.2.1.2.2.1.8.1", Integer32(1))]
        yield None, 1, 0, []  # errorStatus set mid-walk -> must raise

    calls = _install_fake_pysnmp(monkeypatch, bulk_walk_cmd=fake_bulk_walk_cmd)
    with pytest.raises(SnmpError):
        asyncio.run(c._do_walk("1.3.6.1.2.1.2.2.1.8"))
    assert calls["closed"] is True


def test_do_walk_raises_on_error_indication(monkeypatch):
    c = PysnmpClient("h", "public")

    async def fake_bulk_walk_cmd(
        engine, community, target, context, non_rep, max_rep, obj,
        *, lexicographicMode,  # noqa: N803
    ):
        yield "timeout", 0, 0, []

    calls = _install_fake_pysnmp(monkeypatch, bulk_walk_cmd=fake_bulk_walk_cmd)
    with pytest.raises(SnmpError):
        asyncio.run(c._do_walk("1.3.6.1.2.1.2.2.1.8"))
    assert calls["closed"] is True


def test_do_walk_raises_on_no_such_instance_mid_walk(monkeypatch):
    """A noSuchObject/noSuchInstance varbind mid-walk is a real absence, not
    a benign terminator, and must raise (only endOfMibView is benign)."""
    c = PysnmpClient("h", "public")

    async def fake_bulk_walk_cmd(
        engine, community, target, context, non_rep, max_rep, obj,
        *, lexicographicMode,  # noqa: N803
    ):
        yield None, 0, 0, [("1.3.6.1.2.1.2.2.1.8.1", NoSuchInstance())]

    calls = _install_fake_pysnmp(monkeypatch, bulk_walk_cmd=fake_bulk_walk_cmd)
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.2.2.1.8.1")):
        asyncio.run(c._do_walk("1.3.6.1.2.1.2.2.1.8"))
    assert calls["closed"] is True


def test_do_walk_stops_cleanly_on_end_of_mib_view(monkeypatch):
    """endOfMibView is the ONE benign terminator (mirrors the sync client's
    _END_OF_MIB_MARKERS): stop iterating and return rows collected so far,
    without emitting a row for the terminator itself and without raising."""
    c = PysnmpClient("h", "public")

    async def fake_bulk_walk_cmd(
        engine, community, target, context, non_rep, max_rep, obj,
        *, lexicographicMode,  # noqa: N803
    ):
        yield None, 0, 0, [("1.3.6.1.2.1.2.2.1.8.1", Integer32(1))]
        yield None, 0, 0, [("1.3.6.1.2.1.2.2.1.8.2", EndOfMibView())]

    calls = _install_fake_pysnmp(monkeypatch, bulk_walk_cmd=fake_bulk_walk_cmd)
    rows = asyncio.run(c._do_walk("1.3.6.1.2.1.2.2.1.8"))
    assert rows == [("1.3.6.1.2.1.2.2.1.8.1", 1, "INTEGER")]
    assert calls["closed"] is True
