# tests/virtual/test_virtual_snmp_face.py
"""End-to-end: a real pysnmp agent serving StateMibView, hit by BOTH real
transport clients (net-snmp CLI subprocess and pysnmp asyncio hlapi).

Deviates from the Task 15 brief's sample test in two ways, both because the
brief's snippet didn't match the real client API:
* ``PysnmpClient.get``/``.walk`` take a *list* of OIDs / one base OID and
  return a *list* of ``SnmpRow`` (not a single row) — the brief's
  ``client.get(f"...")`` (a bare string, not ``[f"..."]``) would have
  iterated the OID string's characters as if it were a list of OIDs.
* ``pytest.mark.asyncio_or_run`` isn't a registered marker anywhere in this
  project (no pytest-asyncio dependency); every other async test in this
  repo (e.g. ``tests/transport/test_snmp_pysnmp.py``) is a plain ``def``
  that calls ``asyncio.run(...)`` itself, so this file follows that same
  convention instead.
"""
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

_PORT_1_OPER_STATUS = f"{oids.IF_OPER_STATUS}.1"


def test_get_and_walk_against_virtual_face_with_pysnmp_client():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)

        rows = asyncio.run(client.get([_PORT_1_OPER_STATUS]))
        assert rows == [SnmpRow(_PORT_1_OPER_STATUS, 1, "INTEGER")]  # port 1: link up

        rows = asyncio.run(client.walk(oids.DOT1Q_VLAN_STATIC_NAME))
        names = {r.value for r in rows}
        assert names == {"default", "iot"}
    finally:
        sw.stop()


def test_get_and_walk_against_virtual_face_with_netsnmp_cli_client():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")

        rows = client.get([_PORT_1_OPER_STATUS])
        assert rows == [SnmpRow(_PORT_1_OPER_STATUS, 1, "INTEGER")]

        rows = client.walk(oids.DOT1Q_VLAN_STATIC_NAME)
        names = {r.value for r in rows}
        assert names == {"default", "iot"}
    finally:
        sw.stop()


def test_walk_reaches_end_of_mib_view_cleanly():
    """A GETBULK walk of the whole ``1.3.6.1`` (internet) subtree must
    terminate (endOfMibView), not hang or raise, and must yield every seeded
    OID under that subtree exactly once. (The seed's LLDP rows live under
    ``1.0.8802`` — the standard LLDP-MIB enterprise arc, RFC-correctly
    outside ``1.3.6.1`` — so they are excluded from this subtree's expected
    set; ordering/completeness across the *whole* address space, spanning
    both top-level arcs, is already covered by
    ``tests/virtual/test_mibview.py``'s pure ``StateMibView`` walk test.)"""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        rows = asyncio.run(client.walk("1.3.6.1"))
        expected = {k for k in sw.state.oid_map() if k.startswith("1.3.6.1")}
        assert len(rows) == len(expected)
        assert {r.oid for r in rows} == expected
    finally:
        sw.stop()


def test_plus_model_has_no_snmp_face():
    with pytest.raises(UnsupportedCapabilityError):
        VirtualSwitch(model="gs110emx").start()


def test_stop_before_start_is_a_noop():
    VirtualSwitch(model="gsm7252ps").stop()  # must not raise
