# tests/test_snmp_read.py
from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import (
    AsyncSnmpReader,
    SnmpReader,
    async_read_system_info,
    read_system_info,
)


def _walk_by_prefix(
    tables: dict[str, list[SnmpRow]], base_oid: str
) -> list[SnmpRow]:
    """Every canned row at or under ``base_oid``, as a real agent answers.

    Prefix semantics, not exact-key lookup: a walk of a single COLUMN must
    return that column's rows out of a table canned under the table root, the
    way ``snmpbulkwalk 1.3.6.1.2.1.105.1.1.1.3`` does against hardware. A fake
    that only matched whole-table keys would answer nothing for a column walk
    and so disagree with every real switch.
    """
    return [
        row
        for rows in tables.values()
        for row in rows
        if row.oid == base_oid or row.oid.startswith(base_oid + ".")
    ]


class FakeClient:
    """Serves canned SnmpRows by OID prefix."""

    def __init__(self, tables: dict[str, list[SnmpRow]]):
        self._tables = tables

    def get(self, oids):  # not used by these read paths
        return [row for oid in oids for row in self.walk(oid)]

    def walk(self, base_oid):
        return _walk_by_prefix(self._tables, base_oid)


class FakeAsyncClient:
    """Async twin of FakeClient: identical table lookup, async methods."""

    def __init__(self, tables: dict[str, list[SnmpRow]]):
        self._tables = tables

    async def get(self, oids):  # not used by these read paths
        rows: list[SnmpRow] = []
        for oid in oids:
            rows.extend(await self.walk(oid))
        return rows

    async def walk(self, base_oid):
        return _walk_by_prefix(self._tables, base_oid)


def _r(base, pairs, typ="INTEGER"):
    return [SnmpRow(f"{base}.{k}", v, typ) for k, v in pairs.items()]


def test_get_ports_via_reader():
    tables = {
        "1.3.6.1.2.1.2.2.1.7": _r("1.3.6.1.2.1.2.2.1.7", {1: "1"}),
        "1.3.6.1.2.1.2.2.1.8": _r("1.3.6.1.2.1.2.2.1.8", {1: "1"}),
        "1.3.6.1.2.1.31.1.1.1.15": _r(
            "1.3.6.1.2.1.31.1.1.1.15", {1: "1000"}, "Gauge32"
        ),
        "1.3.6.1.2.1.31.1.1.1.1": _r(
            "1.3.6.1.2.1.31.1.1.1.1", {1: "1/0/1"}, "OCTETSTR"
        ),
        "1.3.6.1.2.1.31.1.1.1.18": _r(
            "1.3.6.1.2.1.31.1.1.1.18", {1: "uplink"}, "OCTETSTR"
        ),
    }
    r = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    ports = r.get_ports()
    assert ports[0].port == 1
    assert ports[0].speed_mbps == 1000
    assert ports[0].description == "uplink"


def test_get_poe_joins_status_and_vendor_mw():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    tables = {
        tbl: [
            SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER"),
            SnmpRow(f"{tbl}.6.1.1", "3", "INTEGER"),
        ],
        "1.3.6.1.4.1.4526.10.15.1.1.1.2": [
            SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", "12800", "Gauge32"),
        ],
    }
    r = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    poe = r.get_poe()
    assert poe[0].detect is PoEDetect.DELIVERING
    assert poe[0].power_mw == 12800


def test_snmp_reader_rejects_non_snmp_model():
    # The constructor itself is the capability gate for a Plus model, so the
    # construction MUST be inside the raises-block (it never returns a reader).
    with pytest.raises(UnsupportedCapabilityError):
        SnmpReader(FakeClient({}), get_model("gs110emx"))  # Plus, no SNMP backend


def test_snmp_reader_constructs_for_managed_model():
    # Positive control: a managed model constructs fine and is usable.
    reader = SnmpReader(FakeClient({}), get_model("gsm7252ps"))
    assert reader.model.key == "gsm7252ps"


def _full_tables() -> dict[str, list[SnmpRow]]:
    """One table set exercising every SnmpReader/AsyncSnmpReader method."""
    vendor = oids.vendor_oids(get_model("gsm7252ps"))
    lldp_base = f"{oids.LLDP_REM_TABLE}.1"
    fdb_base = oids.DOT1Q_TP_FDB_PORT
    tables: dict[str, list[SnmpRow]] = {
        oids.IF_ADMIN_STATUS: _r(oids.IF_ADMIN_STATUS, {1: "1"}),
        oids.IF_OPER_STATUS: _r(oids.IF_OPER_STATUS, {1: "1"}),
        oids.IF_HIGH_SPEED: _r(oids.IF_HIGH_SPEED, {1: "1000"}, "Gauge32"),
        oids.IF_NAME: _r(oids.IF_NAME, {1: "1/0/1"}, "OCTETSTR"),
        oids.IF_ALIAS: _r(oids.IF_ALIAS, {1: "uplink"}, "OCTETSTR"),
        oids.IF_HC_IN_OCTETS: _r(oids.IF_HC_IN_OCTETS, {1: "100"}, "Counter64"),
        oids.IF_HC_OUT_OCTETS: _r(oids.IF_HC_OUT_OCTETS, {1: "200"}, "Counter64"),
        oids.IF_HC_IN_UCAST: _r(oids.IF_HC_IN_UCAST, {1: "10"}, "Counter64"),
        oids.IF_HC_OUT_UCAST: _r(oids.IF_HC_OUT_UCAST, {1: "20"}, "Counter64"),
        oids.IF_IN_ERRORS: _r(oids.IF_IN_ERRORS, {1: "0"}),
        oids.IF_OUT_ERRORS: _r(oids.IF_OUT_ERRORS, {1: "0"}),
        oids.DOT1Q_VLAN_STATIC_NAME: [
            SnmpRow(f"{oids.DOT1Q_VLAN_STATIC_NAME}.5", "net", "OCTETSTR"),
        ],
        oids.DOT1Q_VLAN_STATIC_EGRESS: [
            SnmpRow(
                f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.5", bytes([0b11000000]), "OCTETSTR"
            ),
        ],
        oids.DOT1Q_VLAN_STATIC_UNTAGGED: [
            SnmpRow(
                f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.5", bytes([0b01000000]), "OCTETSTR"
            ),
        ],
        oids.DOT1Q_PVID: _r(oids.DOT1Q_PVID, {1: "5"}, "Gauge32"),
        # walk() is keyed by the un-suffixed table OID; the ".1." entry
        # index lives inside each row's OID, not the walk-table key.
        oids.LLDP_REM_TABLE: [
            SnmpRow(f"{lldp_base}.9.75.1.7", "sw-cisco-shed", "OCTETSTR"),
            SnmpRow(f"{lldp_base}.8.75.1.7", "1/xg1.uplink", "OCTETSTR"),
            SnmpRow(f"{lldp_base}.7.75.1.7", "1/xg1", "OCTETSTR"),
        ],
        fdb_base: [
            SnmpRow(f"{fdb_base}.5.200.0.132.137.113.112", "1", "INTEGER"),
        ],
        oids.DOT1D_BASE_PORT_IF_INDEX: [
            SnmpRow(f"{oids.DOT1D_BASE_PORT_IF_INDEX}.1", "1", "INTEGER"),
        ],
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", "1", "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.1", "3", "INTEGER"),
        ],
        vendor.poe_power_mw: [
            SnmpRow(f"{vendor.poe_power_mw}.1.1", "12800", "Gauge32"),
        ],
        vendor.box_fan: [SnmpRow(f"{vendor.box_fan}.0", "3500", "OCTETSTR")],
        vendor.box_psu_power: [SnmpRow(f"{vendor.box_psu_power}.0", "45", "OCTETSTR")],
        vendor.box_temp: [SnmpRow(f"{vendor.box_temp}.0", "30", "OCTETSTR")],
        oids.IP_ADENT_ADDR: [
            SnmpRow(f"{oids.IP_ADENT_ADDR}.10.1.5.20", "10.1.5.20", "IPADDR"),
        ],
        oids.IP_ADENT_NETMASK: [
            SnmpRow(f"{oids.IP_ADENT_NETMASK}.10.1.5.20", "255.255.255.0", "IPADDR"),
        ],
        oids.IP_ROUTE_DEST: [
            SnmpRow(f"{oids.IP_ROUTE_DEST}.0.0.0.0", "0.0.0.0", "IPADDR"),
        ],
        oids.IP_ROUTE_NEXTHOP: [
            SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", "10.1.5.1", "IPADDR"),
        ],
        oids.DOT1D_BASE_BRIDGE_ADDRESS: [
            SnmpRow(
                f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0",
                bytes([0x28, 0xC6, 0x8E, 0x00, 0x00, 0x01]),
                "OCTETSTR",
            ),
        ],
        # dhcp-mode vendor OID is deliberately ABSENT from these tables: the
        # subtree is walked (never get()), so its absence must not raise, and
        # the parser must fall back to IpMode.UNKNOWN.
    }
    return tables


def test_get_stats_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    stats = r.get_stats()
    assert stats[0].port == 1
    assert stats[0].rx_bytes == 100
    assert stats[0].tx_bytes == 200
    assert stats[0].rx_packets == 10
    assert stats[0].tx_packets == 20
    assert stats[0].rx_errors == 0
    assert stats[0].tx_errors == 0


def test_get_vlans_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    vlans = r.get_vlans()
    assert len(vlans) == 1
    assert vlans[0].vlan_id == 5
    assert vlans[0].name == "net"
    assert vlans[0].member_ports == frozenset({1, 2})
    assert vlans[0].untagged_ports == frozenset({2})
    assert vlans[0].tagged_ports == frozenset({1})


def test_get_pvids_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    assert r.get_pvids() == [(1, 5)]


def test_get_lldp_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    neighbors = r.get_lldp()
    assert len(neighbors) == 1
    assert neighbors[0].local_port == 1
    assert neighbors[0].remote_sys_name == "sw-cisco-shed"
    assert neighbors[0].remote_port_desc == "1/xg1.uplink"
    # remote_port_id (lldpRemPortId, col 7) is a distinct value from
    # remote_port_desc (lldpRemPortDesc, col 8).
    assert neighbors[0].remote_port_id == "1/xg1"
    assert neighbors[0].remote_port_id != neighbors[0].remote_port_desc


def test_get_macs_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    macs = r.get_macs()
    assert len(macs) == 1
    assert macs[0].mac == "C8:00:84:89:71:70"
    assert macs[0].vlan_id == 5
    assert macs[0].port == 1


def test_get_sensors_via_reader():
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    sensors = r.get_sensors()
    kinds = {s.kind for s in sensors}
    assert kinds == {"fan", "power", "temperature"}


def test_get_poe_raises_for_zero_pse_model():
    # Parity fix 1: m4300-24x has poe_port_count == 0. SnmpReader.get_poe must
    # RAISE UnsupportedCapabilityError (consistent with CliReader/HttpReader),
    # never return [] from an empty pethPsePortTable. It must raise BEFORE
    # walking, so even a client that would answer the PoE table raises.
    tables = {
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", "1", "INTEGER"),
        ],
    }
    r = SnmpReader(FakeClient(tables), get_model("m4300-24x"))
    with pytest.raises(UnsupportedCapabilityError):
        r.get_poe()
    ar = AsyncSnmpReader(FakeAsyncClient(tables), get_model("m4300-24x"))
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(ar.get_poe())


def test_get_poe_still_works_for_poe_model_with_vendor_power():
    # Positive control: a model WITH PoE (gsm7252ps) is unaffected by the
    # zero-PSE guard -- it still joins standard status + vendor mW.
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    poe = r.get_poe()
    assert poe[0].detect is PoEDetect.DELIVERING
    assert poe[0].power_mw == 12800


def test_get_sensors_raises_when_claimed_vendor_walk_is_empty():
    # Parity fix 2: a model that CLAIMS a vendor sensor subtree
    # (snmp_vendor_base set -> has_vendor_oids True) but whose vendor fan/PSU/
    # temperature walk returns NO rows must RAISE UnsupportedCapabilityError,
    # not silently return [] (the gs728tpp silent-empty bug class). gsm7252ps
    # has a vendor base; feed it empty tables so every vendor column walks dry.
    r = SnmpReader(FakeClient({}), get_model("gsm7252ps"))
    with pytest.raises(UnsupportedCapabilityError):
        r.get_sensors()
    ar = AsyncSnmpReader(FakeAsyncClient({}), get_model("gsm7252ps"))
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(ar.get_sensors())


def test_get_sensors_no_vendor_base_still_returns_entity_inventory():
    # Control for the fix-2 guard: a model with NO vendor base (gs728tpp) does
    # NOT hit the vendor-walk-empty raise; it uses the standard ENTITY-MIB
    # inventory path. With no entity rows it honestly returns [] (a model that
    # never claimed vendor sensors is a different, honest case).
    r = SnmpReader(FakeClient({}), get_model("gs728tpp"))
    assert r.get_sensors() == []


def test_get_mgmt_ip_walks_absent_vendor_oid_to_unknown_mode():
    # The dhcp-mode vendor OID is absent from these tables entirely. Since the
    # reader WALKS the subtree (never get()s a single OID that may be
    # absent), this must not raise -- it must simply come back with no rows,
    # and the parser maps that absence to IpMode.UNKNOWN.
    r = SnmpReader(FakeClient(_full_tables()), get_model("gsm7252ps"))
    cfg = r.get_mgmt_ip()
    assert cfg.address == "10.1.5.20"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.1.5.1"
    assert cfg.mode is IpMode.UNKNOWN
    assert cfg.base_mac == "28:C6:8E:00:00:01"


def test_async_reader_rejects_non_snmp_model():
    with pytest.raises(UnsupportedCapabilityError):
        AsyncSnmpReader(FakeAsyncClient({}), get_model("gs110emx"))


def test_async_reader_matches_sync_reader_for_every_method():
    # Structural-parity pin (Task 16 depends on this): the same table data
    # fed through SnmpReader and AsyncSnmpReader must yield identical model
    # objects for every read method -- the only difference is await.
    tables = _full_tables()
    sync_reader = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    async_reader = AsyncSnmpReader(FakeAsyncClient(tables), get_model("gsm7252ps"))

    async def _collect_async():
        return {
            "ports": await async_reader.get_ports(),
            "stats": await async_reader.get_stats(),
            "vlans": await async_reader.get_vlans(),
            "pvids": await async_reader.get_pvids(),
            "lldp": await async_reader.get_lldp(),
            "macs": await async_reader.get_macs(),
            "poe": await async_reader.get_poe(),
            "sensors": await async_reader.get_sensors(),
            "mgmt_ip": await async_reader.get_mgmt_ip(),
        }

    async_results = asyncio.run(_collect_async())
    sync_results = {
        "ports": sync_reader.get_ports(),
        "stats": sync_reader.get_stats(),
        "vlans": sync_reader.get_vlans(),
        "pvids": sync_reader.get_pvids(),
        "lldp": sync_reader.get_lldp(),
        "macs": sync_reader.get_macs(),
        "poe": sync_reader.get_poe(),
        "sensors": sync_reader.get_sensors(),
        "mgmt_ip": sync_reader.get_mgmt_ip(),
    }
    assert async_results == sync_results
    # Sanity: not vacuously equal -- some real data actually came through.
    assert sync_results["ports"]
    assert sync_results["poe"]
    assert sync_results["mgmt_ip"].mode is IpMode.UNKNOWN
    assert sync_results["ports"][0].description == "uplink"
    assert sync_results["mgmt_ip"].base_mac == "28:C6:8E:00:00:01"


# --- Task 2: model detection via sysDescr -----------------------------------


def _system_info_tables(sys_descr: str) -> dict[str, list[SnmpRow]]:
    return {
        oids.SYS_DESCR: [SnmpRow(oids.SYS_DESCR, sys_descr, "STRING")],
        oids.SYS_OBJECT_ID: [
            SnmpRow(oids.SYS_OBJECT_ID, "1.3.6.1.4.1.4526.10.100.14", "OID")
        ],
    }


def test_read_system_info_matches_known_model():
    tables = _system_info_tables("NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6")
    detected = read_system_info(FakeClient(tables))
    assert detected.key == "gsm7252ps"
    assert detected.matched is True
    assert detected.sys_descr == "NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"
    assert detected.sys_object_id == "1.3.6.1.4.1.4526.10.100.14"


def test_read_system_info_unregistered_model_is_honestly_unmatched():
    # sysObjectID is READ (see detected.sys_object_id) but never used to
    # guess a model -- an unregistered Netgear model name in sysDescr must
    # come back as key=None, not be coerced onto some other registered model.
    tables = _system_info_tables("NETGEAR M7300-28G")
    detected = read_system_info(FakeClient(tables))
    assert detected.key is None
    assert detected.matched is False
    assert detected.sys_descr == "NETGEAR M7300-28G"
    assert detected.sys_object_id == "1.3.6.1.4.1.4526.10.100.14"


def test_read_system_info_no_reply_at_all_is_honestly_unmatched():
    detected = read_system_info(FakeClient({}))
    assert detected.key is None
    assert detected.sys_descr is None
    assert detected.sys_object_id is None


def test_snmp_reader_get_system_info_reuses_readers_client():
    tables = _system_info_tables("NETGEAR GSM7252PS")
    reader = SnmpReader(FakeClient(tables), get_model("gsm7252ps"))
    detected = reader.get_system_info()
    assert detected.key == "gsm7252ps"


def test_async_read_system_info_matches_sync_read_system_info():
    tables = _system_info_tables("NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6")
    sync_detected = read_system_info(FakeClient(tables))
    async_detected = asyncio.run(async_read_system_info(FakeAsyncClient(tables)))
    assert sync_detected == async_detected
    assert sync_detected.key == "gsm7252ps"


def test_async_snmp_reader_get_system_info_is_independent_of_bound_model():
    # get_system_info() reflects what the DEVICE actually reports, not what
    # model the reader happens to be constructed with -- useful to detect a
    # reader was built against the wrong model key.
    tables = _system_info_tables("NETGEAR GS110EMX")
    reader = AsyncSnmpReader(FakeAsyncClient(tables), get_model("gsm7252ps"))
    detected = asyncio.run(reader.get_system_info())
    assert detected.key == "gs110emx"
