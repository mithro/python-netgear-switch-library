# tests/virtual/test_snmp_write_face.py
"""End-to-end SET->mutate->read against a live ``VirtualSwitch`` mock.

``tests/virtual/test_mutable_state.py`` covers ``apply_write``/coherence
purely at the state layer (no network). This file drives the same mutation
through the real SNMP SET path (``SetCommandResponder`` -> ``write_variables``
-> ``StateMibView.apply_write``) using both real transport clients, then
reads the new value back over the wire -- proving the whole SET->mutate->read
loop, not just the state layer in isolation.
"""
from __future__ import annotations

import asyncio
import gc
import warnings

import pytest

from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch


def test_set_via_pysnmp_client_then_read_back_ifadmin():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        oid = f"{oids.IF_ADMIN_STATUS}.3"
        oper_oid = f"{oids.IF_OPER_STATUS}.3"

        # Seed: port 3 starts admin-up (though link-down in the seed).
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, 1, "INTEGER")]

        asyncio.run(client.set(SetVarbind(oid, 2, "i")))  # admin down

        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, 2, "INTEGER")]
        # Coherence: admin-down forces the data link down too.
        rows = asyncio.run(client.get([oper_oid]))
        assert rows == [SnmpRow(oper_oid, 2, "INTEGER")]
        assert sw.state.ports[3].admin is False
        assert sw.state.ports[3].link is False
    finally:
        sw.stop()


def test_set_via_pysnmp_client_poe_admin_cycles_detect_coherence():
    """Drives the exact coherence ``cycle_poe``/``clear_poe_fault`` rely on:
    admin off -> detect=unused(1) + link down; admin on -> detect=delivering(3).
    """
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        admin_oid = f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
        detect_oid = f"{oids.PETH_PSE_PORT_TABLE}.6.1.1"
        oper_oid = f"{oids.IF_OPER_STATUS}.1"

        assert sw.state.poe[1].admin is True
        assert sw.state.poe[1].detect == 3

        asyncio.run(client.set(SetVarbind(admin_oid, 2, "i")))  # admin off
        detect_rows = asyncio.run(client.get([detect_oid]))
        assert detect_rows == [SnmpRow(detect_oid, 1, "INTEGER")]
        oper_rows = asyncio.run(client.get([oper_oid]))
        assert oper_rows == [SnmpRow(oper_oid, 2, "INTEGER")]

        asyncio.run(client.set(SetVarbind(admin_oid, 1, "i")))  # admin on
        admin_rows = asyncio.run(client.get([admin_oid]))
        assert admin_rows == [SnmpRow(admin_oid, 1, "INTEGER")]
        detect_rows = asyncio.run(client.get([detect_oid]))
        assert detect_rows == [SnmpRow(detect_oid, 3, "INTEGER")]
    finally:
        sw.stop()


def test_set_via_netsnmp_cli_client_then_read_back_pvid():
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        oid = f"{oids.DOT1Q_PVID}.10"

        client.set(SetVarbind(oid, 90, "u"))

        rows = client.get([oid])
        assert rows == [SnmpRow(oid, 90, "Gauge32")]
        assert sw.state.pvids[10] == 90
    finally:
        sw.stop()


def test_set_unknown_oid_raises_snmperror_not_a_timeout():
    """A SET to an OID this mock never recognizes as writable must come back
    as a clean SNMP error (notWritable), not silently succeed and not hang
    the client until timeout (which would make this test flaky)."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port, timeout=2.0, retries=0)
        with pytest.raises(SnmpError):
            asyncio.run(client.set(SetVarbind("1.2.3.4.5", 1, "i")))
    finally:
        sw.stop()


def test_set_read_only_oid_raises_snmperror():
    """ifOperStatus is read-only (device-derived, not admin-settable) in this
    mock -- SETting it must be rejected, not silently accepted."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        with pytest.raises(SnmpError):
            client.set(SetVarbind(f"{oids.IF_OPER_STATUS}.1", 2, "i"))
    finally:
        sw.stop()


def test_set_malformed_value_maps_to_snmperror_not_a_timeout():
    """A structurally-wrong SET value (an OctetString where an integer
    RowStatus is expected) must raise via ``apply_write`` -> the mapped
    pysnmp ``WrongValueError`` -> a clean client-side ``SnmpError``, never
    propagate into the asyncio dispatcher (which would surface as a client
    timeout -- flaky, not a deterministic failure)."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port, timeout=2.0, retries=0)
        oid = f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.300"
        with pytest.raises(SnmpError):
            asyncio.run(client.set(SetVarbind(oid, b"\xff\xfe", "x")))
        # The malformed write must not have partially created the VLAN.
        assert 300 not in sw.state.vlans
    finally:
        sw.stop()


def test_set_get_stop_lifecycle_emits_no_resource_warning():
    """Mirrors the existing GET-only lifecycle check in
    ``test_virtual_snmp_face.py`` for the SET path: a full
    start -> SET -> GET -> stop cycle must not leak the UDP socket/transport."""

    def _lifecycle() -> None:
        sw = VirtualSwitch(model="gsm7252ps")
        sw.start()
        try:
            client = PysnmpClient(sw.host, "public", port=sw.port)
            oid = f"{oids.IF_ADMIN_STATUS}.5"
            asyncio.run(client.set(SetVarbind(oid, 2, "i")))
            asyncio.run(client.get([oid]))
        finally:
            sw.stop()

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        _lifecycle()  # must not raise

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _lifecycle()
        gc.collect()
    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []
