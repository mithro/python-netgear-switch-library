# tests/virtual/test_gs728tpp_vlan_fidelity.py
"""The fake GS728TPP must have the same VLAN *shape* as the real switch.

Everything asserted here was measured on
sw-netgear-gs728tpp.monarto.mithis.com (10.2.5.10, firmware 6.0.1.30) on
2026-08-02, driving each backend directly over the ten64 jump host:

* ``dot1qVlanStaticName/Egress/Untagged/RowStatus`` walk to 12 rows -- ids
  2,3,4,5,6,7,10,20,31,41,90,99. ``dot1qVlanCurrentTable`` walks to 13. The
  extra row is VLAN 1, whose ``dot1qVlanStatus`` reads 1 (other) where every
  other VLAN reads 2 (permanent).
* Every PortList is 126 bytes, and 11 of the 13 VLANs set bit 1000 -- ``po 1``,
  ifType 161, one of eight LAGs at ifIndex 1000-1007. ``dot1dBasePortIfIndex``
  is identity-mapped, so the bit position IS the ifIndex.

Those two facts broke SNMP get_vlans in two different ways, so the mock has to
carry them or the fix cannot be regression-tested without hardware.
"""

from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.http_read import HttpReader
from netgear_switch.models import VlanMode
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.snmp_read import SnmpReader
from netgear_switch.snmp_write import SnmpWriter
from netgear_switch.transport.http.client import HttpClient
from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient
from netgear_switch.virtual.server import VirtualSwitch

MODEL = get_model("gs728tpp")
LAGS = frozenset(range(1000, 1008))
#: Measured PortList width on this switch, in bytes.
PORTLIST_WIDTH = 126


@pytest.fixture
def mock():
    with VirtualSwitch(model="gs728tpp") as switch:
        yield switch


def _snmp(mock) -> NetsnmpCliClient:
    return NetsnmpCliClient(f"{mock.host}:{mock.port}", mock.community)


def _http_reader(mock) -> HttpReader:
    client = HttpClient(
        f"{mock.host}:{mock.http_port}", mock.http_password, http_spec(MODEL)
    )
    return HttpReader(client, MODEL)


def test_vlan_1_has_no_static_row_but_is_still_reported(mock) -> None:
    client = _snmp(mock)
    static_ids = {
        int(r.oid.rsplit(".", 1)[1]) for r in client.walk(oids.DOT1Q_VLAN_STATIC_NAME)
    }
    current_ids = {
        int(r.oid.rsplit(".", 1)[1])
        for r in client.walk(oids.DOT1Q_VLAN_CURRENT_EGRESS)
    }
    assert 1 not in static_ids, "the fake must NOT invent a static row for VLAN 1"
    assert 1 in current_ids
    assert current_ids - static_ids == {1}

    reported = {v.vlan_id for v in SnmpReader(client, MODEL).get_vlans()}
    assert 1 in reported, "a static-table-only read loses VLAN 1 -- that was the bug"
    assert reported == current_ids


def test_vlan_status_marks_the_static_less_vlan_as_other(mock) -> None:
    rows = {
        r.oid.rsplit(".", 1)[1]: r.value
        for r in _snmp(mock).walk(oids.DOT1Q_VLAN_STATUS)
    }
    assert rows["1"] == 1, "dot1qVlanStatus other(1) -- what the live switch reports"
    assert rows["5"] == 2, "permanent(2) for a configured VLAN"


def test_the_lag_bit_is_really_on_the_wire_and_really_filtered_out(mock) -> None:
    """The filter must be doing work: assert the raw bitmap DOES carry bit 1000.

    Without this the LAG test could pass against a mock that simply never sets
    the bit -- agreeing with the code while both disagree with the switch.
    """
    client = _snmp(mock)
    raw = {
        int(r.oid.rsplit(".", 1)[1]): r.value
        for r in client.walk(oids.DOT1Q_VLAN_STATIC_EGRESS)
    }
    vlan5 = raw[5]
    assert isinstance(vlan5, bytes)
    assert len(vlan5) == PORTLIST_WIDTH, "the device's own 126-byte PortList width"
    assert vlan5[999 // 8] & (0x80 >> (999 % 8)), "bit 1000 (po 1) must be set"

    for vlan in SnmpReader(client, MODEL).get_vlans():
        assert not (vlan.member_ports & LAGS), f"VLAN {vlan.vlan_id} leaked a LAG port"
        assert max(vlan.member_ports, default=0) <= MODEL.port_count


def test_snmp_and_http_report_the_same_vlans(mock) -> None:
    """Both backends driven directly -- neither can be the other answering."""
    snmp = {v.vlan_id: v for v in SnmpReader(_snmp(mock), MODEL).get_vlans()}
    http = {v.vlan_id: v for v in _http_reader(mock).get_vlans()}
    assert sorted(snmp) == sorted(http)
    for vid, want in http.items():
        got = snmp[vid]
        assert got.member_ports == want.member_ports, f"VLAN {vid} members disagree"
        assert got.untagged_ports == want.untagged_ports, (
            f"VLAN {vid} untagged disagree"
        )
        assert got.name == want.name, f"VLAN {vid} name disagrees"


def test_membership_write_preserves_the_lag_bits(mock) -> None:
    """A read-modify-write must not evict ``po 1`` from the VLAN.

    The writer flips one bit in the device's OWN octets, so the LAG bits ride
    along untouched. If it ever re-encoded from the decoded (now LAG-free) port
    set instead, every membership change would silently drop the LAG from the
    VLAN -- real config loss, invisible to a reader that also filters LAGs.
    """
    client = _snmp(mock)
    writer = SnmpWriter(client, MODEL)

    def raw_egress() -> bytes:
        for row in client.walk(oids.DOT1Q_VLAN_STATIC_EGRESS):
            if row.oid.endswith(".5"):
                assert isinstance(row.value, bytes)
                return row.value
        raise AssertionError("VLAN 5 has no egress bitmap")

    def lag_bit(data: bytes) -> bool:
        return bool(data[999 // 8] & (0x80 >> (999 % 8)))

    assert lag_bit(raw_egress()), "precondition: po 1 is a member of VLAN 5"

    writer.set_vlan_membership(5, 26, VlanMode.TAGGED, force=True)

    after = raw_egress()
    assert lag_bit(after), "the membership write evicted the LAG from the VLAN"
    assert len(after) == PORTLIST_WIDTH, "and it must keep the device's own width"
    vlan5 = next(v for v in SnmpReader(client, MODEL).get_vlans() if v.vlan_id == 5)
    assert 26 in vlan5.tagged_ports, "the change the caller actually asked for"


def test_snmp_refuses_vlan_creation_the_way_the_switch_does(mock) -> None:
    """This agent cannot create a VLAN, and both layers must say so.

    MEASURED 2026-08-03 on 10.2.5.10 (firmware 6.0.1.30): every documented
    RowStatus creation mechanism answers inconsistentValue --

        createAndGo(4) alone                                inconsistentValue
        createAndGo(4) + dot1qVlanStaticName in ONE PDU     inconsistentValue
        createAndWait(5) -> name -> active(1)               inconsistentValue
        dot1qVlanStaticName alone (implicit create)         inconsistentValue
        createAndGo(4) + name + empty 126-byte PortList     inconsistentValue

    while the SAME table's membership columns accept writes and destroy(6)
    removes a VLAN. So the writer must refuse BY NAME before sending anything,
    and the fake must refuse the raw SET -- otherwise a create_vlan that cannot
    work on this hardware would pass its tests.
    """
    client = _snmp(mock)
    writer = SnmpWriter(client, MODEL)

    with pytest.raises(UnsupportedCapabilityError, match="cannot create a VLAN"):
        writer.create_vlan(4007, "nope")

    # The fake refuses the raw row-status SET too, so the refusal is a property
    # of the modelled device rather than only of the writer's guard.
    with pytest.raises(SnmpError):
        client.set(
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.4007",
                oids.ROW_STATUS_CREATE_AND_GO,
                "i",
            )
        )
    assert 4007 not in {v.vlan_id for v in SnmpReader(client, MODEL).get_vlans()}


def test_snmp_delete_and_membership_still_work(mock) -> None:
    """Creation is the ONLY thing refused -- proving it is not a read-only table.

    All three were driven against the live switch: membership on VLAN 90 port
    17 (tagged -> excluded -> tagged), dot1qPvid, and destroy(6) removing a
    VLAN the web UI had created.
    """
    client = _snmp(mock)
    writer = SnmpWriter(client, MODEL)
    reader = SnmpReader(client, MODEL)

    writer.set_vlan_membership(90, 17, VlanMode.EXCLUDED, force=True)
    vlan90 = next(v for v in reader.get_vlans() if v.vlan_id == 90)
    assert 17 not in vlan90.member_ports
    writer.set_vlan_membership(90, 17, VlanMode.TAGGED, force=True)
    assert 17 in next(v for v in reader.get_vlans() if v.vlan_id == 90).tagged_ports

    writer.set_pvid(17, 90)
    assert dict(reader.get_pvids())[17] == 90

    writer.delete_vlan(90, force=True)
    assert 90 not in {v.vlan_id for v in reader.get_vlans()}


def test_pvids_and_ports_exclude_the_lags(mock) -> None:
    client = _snmp(mock)
    raw_pvids = client.walk(oids.DOT1Q_PVID)
    assert len(raw_pvids) == MODEL.port_count + len(LAGS), (
        "the fake must present the LAG PVID rows the real walk returns (36)"
    )
    reader = SnmpReader(client, MODEL)
    assert {p for p, _ in reader.get_pvids()} == set(range(1, MODEL.port_count + 1))
    assert {p.port for p in reader.get_ports()} == set(range(1, MODEL.port_count + 1))
