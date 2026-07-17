from __future__ import annotations

from netgear_switch.errors import NetgearSwitchError
from netgear_switch.protocols.snmp.client import (
    ABSENT_TYPES,
    SnmpError,
    SnmpRow,
    full_oid,
)


def test_snmprow_frozen_hashable():
    r = SnmpRow(oid="1.3.6.1.2.1.2.2.1.8.1", value="1", snmp_type="INTEGER")
    assert hash(r)
    assert r.oid.endswith(".8.1")


def test_snmp_error_is_library_error():
    assert issubclass(SnmpError, NetgearSwitchError)


def test_full_oid_rejoins_and_strips_leading_dot():
    assert full_oid(".1.3.6.1.2.1.2.2.1.8", "1") == "1.3.6.1.2.1.2.2.1.8.1"
    assert full_oid("1.3.6.1.2.1.2.2.1.8.1", "") == "1.3.6.1.2.1.2.2.1.8.1"


def test_absent_types():
    assert "NOSUCHINSTANCE" in ABSENT_TYPES
    assert "ENDOFMIBVIEW" in ABSENT_TYPES
