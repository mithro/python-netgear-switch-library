# tests/transport/test_value_parity.py
"""Direct sync/async SNMP value-parity pin (Task 11 Fix 3 companion check).

For a representative sample of SNMP types, build the pysnmp varbind fake AND
the exact net-snmp CLI text line for the SAME underlying value, run each
through its own transport's normalizer, and assert the resulting
``SnmpRow.value`` is identical (same Python type + content). This pins the
value-parity contract described in ``snmp_pysnmp.py``'s module docstring and
``SnmpRow``'s docstring directly, independent of any higher-level parser.
"""
from __future__ import annotations

from netgear_switch.transport.aio.snmp_pysnmp import _normalize_varbind
from netgear_switch.transport.sync.snmp_netsnmp_cli import parse_netsnmp_lines

_OID = "1.3.6.1.2.1.2.2.1.8.1"


class Integer:
    """Stands in for pysnmp's Integer/Integer32: int()-convertible.

    Named to match the real pysnmp class, since ``_normalize_varbind``
    dispatches on ``value.__class__.__name__``.
    """

    def __init__(self, value: int) -> None:
        self._value = value

    def __int__(self) -> int:
        return self._value


class Gauge32:
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


def _sync_value(line: str):
    rows = parse_netsnmp_lines(f"{_OID} = {line}")
    assert len(rows) == 1
    return rows[0].value


def test_integer_value_parity():
    async_oid, async_value, _typ = _normalize_varbind(_OID, Integer(5))
    sync_value = _sync_value("INTEGER: 5")
    assert async_oid == _OID
    assert async_value == sync_value == 5
    assert type(async_value) is type(sync_value) is int


def test_gauge32_value_parity():
    _oid, async_value, _typ = _normalize_varbind(_OID, Gauge32(1_000_000))
    sync_value = _sync_value("Gauge32: 1000000")
    assert async_value == sync_value == 1_000_000
    assert type(async_value) is type(sync_value) is int


def test_printable_string_value_parity():
    _oid, async_value, _typ = _normalize_varbind(_OID, OctetString(b"1/0/1"))
    sync_value = _sync_value('STRING: "1/0/1"')
    assert async_value == sync_value == "1/0/1"
    assert type(async_value) is type(sync_value) is str


def test_hex_string_bytes_value_parity():
    raw = bytes([0xC0, 0x00])
    _oid, async_value, _typ = _normalize_varbind(_OID, OctetString(raw))
    sync_value = _sync_value("Hex-STRING: C0 00")
    assert async_value == sync_value == raw
    assert type(async_value) is type(sync_value) is bytes


def test_ip_address_value_parity():
    _oid, async_value, _typ = _normalize_varbind(_OID, IpAddress("10.1.5.20"))
    sync_value = _sync_value("IpAddress: 10.1.5.20")
    assert async_value == sync_value == "10.1.5.20"
    assert type(async_value) is type(sync_value) is str
