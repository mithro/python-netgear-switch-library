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
import gc
import importlib
import os
import subprocess
import warnings
from typing import Any

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import AsyncSnmpReader, SnmpReader
from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch
from netgear_switch.virtual.state import encode_port_bitmap

_PORT_1_OPER_STATUS = f"{oids.IF_OPER_STATUS}.1"


def _pysnmp_asyncio() -> Any:
    """Lazily import pysnmp's hlapi, for a raw one-shot GETNEXT below (mirrors
    transport/aio/snmp_pysnmp.py's own lazy-import seam)."""
    return importlib.import_module("pysnmp.hlapi.v3arch.asyncio")


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


def test_plus_model_binds_nsdp_not_snmp():
    """A Plus model (NSDP+HTTP backends, no SNMP) must not raise on start() —
    Task 9 gives it a real NSDP face instead of the SNMP one; see
    ``tests/virtual/test_virtual_nsdp_face.py`` for full NSDP-face coverage."""
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        assert sw._snmp_face is None
        assert sw.port != 0
    finally:
        sw.stop()


def test_model_with_neither_backend_raises_unsupported():
    """``VirtualSwitch.start()`` still raises for a hypothetical model with
    no bindable backend at all (every real registry entry has SNMP or NSDP,
    so this exercises the ``else`` branch directly against a stub)."""
    from netgear_switch.registry import SwitchClass, SwitchModel

    sw = VirtualSwitch(model="gsm7252ps")
    sw._model_info = SwitchModel(
        key="stub-no-backend",
        display_name="stub",
        switch_class=SwitchClass.FULLY_MANAGED,
        port_count=1,
        poe_port_count=0,
        backends=frozenset(),
        snmp_vendor_base=None,
    )
    with pytest.raises(UnsupportedCapabilityError):
        sw.start()


def test_stop_before_start_is_a_noop():
    VirtualSwitch(model="gsm7252ps").stop()  # must not raise


def test_start_get_stop_lifecycle_emits_no_resource_warning():
    """A full start -> one GET -> stop lifecycle must close the agent's UDP
    socket/transport deterministically, not leave it for GC to warn about.

    ``ResourceWarning`` for an unclosed socket/transport is raised from a
    C-level finalizer during garbage collection, where CPython treats any
    exception the finalizer raises as *unraisable* (routed to
    ``sys.unraisablehook``, printed to stderr, never propagated to the
    caller) -- confirmed empirically: on the pre-fix code, wrapping the
    lifecycle in ``warnings.simplefilter("error", ResourceWarning)`` alone
    does NOT raise, even though the leak is very much still there. So the
    literal "must not raise under an error filter" check below is
    necessary-but-not-sufficient; the *recording* check after it is what
    actually proves the fd was closed deterministically rather than left
    for GC.
    """

    def _lifecycle() -> None:
        sw = VirtualSwitch(model="gsm7252ps")
        sw.start()
        try:
            client = PysnmpClient(sw.host, "public", port=sw.port)
            asyncio.run(client.get([_PORT_1_OPER_STATUS]))
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


def test_ten_start_stop_cycles_do_not_leak_fds_or_warn():
    """Ten start/stop cycles: no ResourceWarning, and (where /proc is
    available) the process's open-fd count does not grow across cycles."""
    fd_dir = f"/proc/{os.getpid()}/fd"
    try:
        before = len(os.listdir(fd_dir))
    except OSError:
        before = None  # /proc unavailable on this platform

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(10):
            sw = VirtualSwitch(model="gsm7252ps")
            sw.start()
            sw.stop()
        gc.collect()

    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []

    if before is not None:
        after = len(os.listdir(fd_dir))
        assert after <= before + 2  # small constant slack; no per-cycle growth


def test_type_token_round_trips_through_pysnmp_client():
    """Pin Gauge32/Counter32/Counter64/IpAddress/OCTETSTR-bytes/vendor-PoE
    round-trips through the real wire, so a regression in ``_to_smi_value``'s
    ``(snmp_type, value)`` -> pysnmp SMI object mapping is caught, not just
    the INTEGER/OCTETSTR-text cases the other tests already cover. Every
    expected value below is read straight out of the seeded
    ``VirtualSwitchState`` (via ``seed_gsm7252ps``), never hardcoded.
    """
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = PysnmpClient(sw.host, "public", port=sw.port)
        port1 = sw.state.ports[1]
        vlan90 = sw.state.vlans[90]
        vendor = oids.vendor_oids(get_model("gsm7252ps"))

        assert port1.rx_octets is not None
        assert port1.rx_errors is not None

        # Gauge32: ifHighSpeed.1
        oid = f"{oids.IF_HIGH_SPEED}.1"
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, port1.speed, "Gauge32")]

        # Counter64: ifHCInOctets.1
        oid = f"{oids.IF_HC_IN_OCTETS}.1"
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, port1.rx_octets, "Counter64")]

        # Counter32: ifInErrors.1
        oid = f"{oids.IF_IN_ERRORS}.1"
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, port1.rx_errors, "Counter32")]

        # IpAddress: ipAdEntAddr.<mgmt address>
        oid = f"{oids.IP_ADENT_ADDR}.{sw.state.mgmt.address}"
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, sw.state.mgmt.address, "IpAddress")]

        # OCTETSTR-as-bytes bitmap: dot1qVlanStaticEgressPorts.90
        oid = f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
        expected_bitmap = encode_port_bitmap(vlan90.member).encode("latin-1")
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, expected_bitmap, "Hex-STRING")]

        # Vendor PoE delivered power (mW) on port 1, the delivering port.
        oid = f"{vendor.poe_power_mw}.1.1"
        rows = asyncio.run(client.get([oid]))
        assert rows == [SnmpRow(oid, sw.state.poe[1].power_mw, "Gauge32")]
    finally:
        sw.stop()


# --- Gap 2/3: non-PoE model's PoE MIB answers noSuchObject on the wire -----
#
# m4300-24x (0 PoE ports, verified real capture: poe=[]) is the faithful,
# non-PoE M4300 mock seed (see virtual/seed.py::seed_m4300_24x). These tests
# prove get_poe() degrades to [] through BOTH transports/readers AND that the
# mock actually answers noSuchObject on the wire for the PoE MIB root -- not
# merely that the client-side walk boundary check happens to yield [] anyway
# (which it would even for the old, unfaithful "jump to an unrelated
# subtree" mock behaviour this replaces).


def test_sync_get_poe_on_non_poe_model_is_empty_and_wire_emits_no_such_object():
    sw = VirtualSwitch(model="m4300-24x")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        reader = SnmpReader(client, get_model("m4300-24x"))
        assert reader.get_poe() == []

        # Wire-level proof: a raw snmpbulkwalk of the PoE MIB root emits the
        # actual net-snmp text for a noSuchObject varbind, not merely an
        # empty result the client inferred some other way.
        result = subprocess.run(
            [
                "snmpbulkwalk", "-v2c", "-c", "public", "-On", "-Oe", "-OU", "-Ln",
                f"{sw.host}:{sw.port}", oids.PETH_PSE_PORT_TABLE,
            ],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "No Such Object available on this agent at this OID" in result.stdout
    finally:
        sw.stop()


def test_async_get_poe_on_non_poe_model_is_empty_and_wire_emits_no_such_object():
    async def run() -> None:
        sw = VirtualSwitch(model="m4300-24x")
        sw.start()
        try:
            client = PysnmpClient(sw.host, "public", port=sw.port)
            reader = AsyncSnmpReader(client, get_model("m4300-24x"))
            assert await reader.get_poe() == []

            # Wire-level proof: a raw one-shot GETNEXT (bypassing the
            # higher-level bulk_walk_cmd's own subtree-boundary handling)
            # returns the literal pysnmp NoSuchObject SMI value for the PoE
            # MIB root, matching real hardware exactly (see
            # protocols/snmp/oids.py::unimplemented_roots).
            hlapi = _pysnmp_asyncio()
            engine = hlapi.SnmpEngine()
            try:
                target = await hlapi.UdpTransportTarget.create(
                    (sw.host, sw.port), timeout=2.0, retries=1
                )
                err_ind, err_stat, _idx, binds = await hlapi.next_cmd(
                    engine, hlapi.CommunityData("public"), target,
                    hlapi.ContextData(),
                    hlapi.ObjectType(
                        hlapi.ObjectIdentity(oids.PETH_PSE_PORT_TABLE)
                    ),
                )
                assert not err_ind
                assert not err_stat
                (_name, value), = binds
                assert value.__class__.__name__ == "NoSuchObject"
            finally:
                engine.close_dispatcher()
        finally:
            sw.stop()

    asyncio.run(run())


def test_m4300_24x_ascii_base_mac_round_trips_through_the_mock_end_to_end():
    """m4300-24x's dot1dBaseBridgeAddress is VERIFIED to come back as ASCII
    colon-hex TEXT on real hardware (see protocols/snmp/parse.py's
    _mac_from_ascii_text) -- unlike the other seeds' raw-bytes encoding, this
    exercises that exact quirk end-to-end through a real virtual-mock SNMP
    agent + client + SnmpReader, not just a synthetic unit-test row."""
    sw = VirtualSwitch(model="m4300-24x")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        reader = SnmpReader(client, get_model("m4300-24x"))
        mgmt = reader.get_mgmt_ip()
        assert mgmt.base_mac == "8C:3B:AD:6B:BB:E0"
        assert mgmt.address == "10.1.5.13"
    finally:
        sw.stop()


def test_m4300_24x_ascii_base_mac_round_trips_through_the_mock_end_to_end_async():
    """Async twin of the sync test above: same VERIFIED real-hardware ASCII
    colon-hex TEXT quirk (see protocols/snmp/parse.py's _mac_from_ascii_text),
    exercised through AsyncSnmpReader + PysnmpClient instead of
    SnmpReader + NetsnmpCliClient -- proves the quirk round-trips end-to-end
    over BOTH transports, not just the sync one."""
    async def run() -> None:
        sw = VirtualSwitch(model="m4300-24x")
        sw.start()
        try:
            client = PysnmpClient(sw.host, "public", port=sw.port)
            reader = AsyncSnmpReader(client, get_model("m4300-24x"))
            mgmt = await reader.get_mgmt_ip()
            assert mgmt.base_mac == "8C:3B:AD:6B:BB:E0"
            assert mgmt.address == "10.1.5.13"
        finally:
            sw.stop()

    asyncio.run(run())


def test_ip_address_and_bitmap_round_trip_through_netsnmp_cli_client():
    """The two parity-critical types (raw-bytes bitmap + IpAddress) pinned
    through the OTHER transport too: Task 16's sync/async equivalence relies
    on both clients decoding the exact same wire bytes identically."""
    sw = VirtualSwitch(model="gsm7252ps")
    sw.start()
    try:
        client = NetsnmpCliClient(f"{sw.host}:{sw.port}", "public")
        vlan90 = sw.state.vlans[90]

        oid = f"{oids.IP_ADENT_ADDR}.{sw.state.mgmt.address}"
        rows = client.get([oid])
        assert rows == [SnmpRow(oid, sw.state.mgmt.address, "IpAddress")]

        oid = f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
        expected_bitmap = encode_port_bitmap(vlan90.member).encode("latin-1")
        rows = client.get([oid])
        assert rows == [SnmpRow(oid, expected_bitmap, "Hex-STRING")]
    finally:
        sw.stop()
