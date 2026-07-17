from __future__ import annotations

import asyncio

import pytest

from netgear_switch.errors import ProtectedPortError, WriteVerificationError
from netgear_switch.models import PoEDetect, VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.protocols.snmp.parse import decode_port_bitmap
from netgear_switch.protocols.snmp.write import SetVarbind, encode_port_bitmap
from netgear_switch.registry import get_model
from netgear_switch.snmp_write import AsyncSnmpWriter, PoeCycleTimeouts, SnmpWriter


class FakeWriteClient:
    """Read tables keyed by base OID; SETs recorded and (optionally) applied."""

    def __init__(self, tables=None, apply=True):
        self._tables = tables or {}
        self.sets: list[SetVarbind] = []
        self._apply = apply

    def get(self, oids_):
        return [row for oid in oids_ for row in self.walk(oid)]

    def walk(self, base_oid):
        return list(self._tables.get(base_oid, []))

    def set(self, vb):
        self.set_many([vb])

    def set_many(self, vbs):
        self.sets.extend(vbs)
        if not self._apply:
            return
        for vb in vbs:  # crude apply: overwrite the exact leaf row
            # Match the existing table this leaf belongs to by OID prefix
            # (tables can have multi-component index suffixes, e.g. the PoE
            # table's <col>.<group>.<port>) rather than assuming the leaf's
            # immediate parent is the table's walk key.
            base = next(
                (k for k in self._tables if vb.oid.startswith(f"{k}.")), None
            )
            if base is None:
                base, _, _ = vb.oid.rpartition(".")
            self._tables.setdefault(base, [])
            self._tables[base] = [r for r in self._tables[base] if r.oid != vb.oid]
            self._tables[base].append(SnmpRow(vb.oid, int(vb.value), "INTEGER"))


class FakeAsyncWriteClient:
    """Async twin of FakeWriteClient: identical table lookup/apply, async I/O."""

    def __init__(self, tables=None, apply=True):
        self._tables = tables or {}
        self.sets: list[SetVarbind] = []
        self._apply = apply

    async def get(self, oids_):
        rows = []
        for oid in oids_:
            rows.extend(await self.walk(oid))
        return rows

    async def walk(self, base_oid):
        return list(self._tables.get(base_oid, []))

    async def set(self, vb):
        await self.set_many([vb])

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        if not self._apply:
            return
        for vb in vbs:
            base = next(
                (k for k in self._tables if vb.oid.startswith(f"{k}.")), None
            )
            if base is None:
                base, _, _ = vb.oid.rpartition(".")
            self._tables.setdefault(base, [])
            self._tables[base] = [r for r in self._tables[base] if r.oid != vb.oid]
            self._tables[base].append(SnmpRow(vb.oid, int(vb.value), "INTEGER"))


def _poe_tables(admin=1, detect=3):
    return {
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", admin, "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", detect, "INTEGER"),
        ],
    }


def test_set_poe_off_issues_correct_set_and_verifies():
    client = FakeWriteClient(_poe_tables(admin=1))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_poe(5, on=False)
    assert client.sets == [SetVarbind(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 2, "i")]


def test_set_poe_verification_failure_raises():
    client = FakeWriteClient(_poe_tables(admin=1), apply=False)  # device ignores write
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_poe(5, on=False)
    assert exc.value.after is not None


def test_protected_port_blocks_disruptive_write_without_force():
    client = FakeWriteClient(_poe_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        w.set_poe(5, on=False)
    assert client.sets == []            # nothing sent
    w.set_poe(5, on=False, force=True)  # force bypasses the guard
    assert client.sets


def test_set_port_enabled_disable_sets_ifadmin_2():
    tables = {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.5", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.5", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.5", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.5", "1/0/5", "STRING")],
    }
    client = FakeWriteClient(tables)
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_port_enabled(5, enabled=False, force=True)
    assert client.sets == [SetVarbind(f"{oids.IF_ADMIN_STATUS}.5", 2, "i")]


def _vlan_tables(vid=90, member=(1, 2, 10), untagged=(1, 2)):
    name_oid = oids.DOT1Q_VLAN_STATIC_NAME
    egress_oid = oids.DOT1Q_VLAN_STATIC_EGRESS
    untagged_oid = oids.DOT1Q_VLAN_STATIC_UNTAGGED
    return {
        name_oid: [SnmpRow(f"{name_oid}.{vid}", "iot", "STRING")],
        egress_oid: [
            SnmpRow(f"{egress_oid}.{vid}", encode_port_bitmap(member), "Hex-STRING")
        ],
        untagged_oid: [
            SnmpRow(
                f"{untagged_oid}.{vid}", encode_port_bitmap(untagged), "Hex-STRING"
            )
        ],
        oids.DOT1Q_PVID: [SnmpRow(f"{oids.DOT1Q_PVID}.10", 1, "Gauge32")],
    }


class ApplyingVlanClient(FakeWriteClient):
    """Applies bitmap/pvid SETs into the read tables so verify passes."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")
                ]
            elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
                self._tables[oids.DOT1Q_VLAN_STATIC_UNTAGGED] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")
                ]
            elif vb.oid.startswith(oids.DOT1Q_PVID):
                self._tables[oids.DOT1Q_PVID] = [
                    SnmpRow(vb.oid, int(vb.value), "Gauge32")
                ]


class ApplyingVlanAsyncClient(FakeAsyncWriteClient):
    """Async twin of ApplyingVlanClient: applies bitmap/pvid SETs so verify passes."""

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")
                ]
            elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
                self._tables[oids.DOT1Q_VLAN_STATIC_UNTAGGED] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")
                ]
            elif vb.oid.startswith(oids.DOT1Q_PVID):
                self._tables[oids.DOT1Q_PVID] = [
                    SnmpRow(vb.oid, int(vb.value), "Gauge32")
                ]


class EgressOnlyVlanAsyncClient(FakeAsyncWriteClient):
    """Async twin of EgressOnlyVlanClient: drops the untagged SET (buggy device)."""

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")]
            # untagged column deliberately not applied


class VlanDisappearsClient(FakeWriteClient):
    """Applies the SET, but the VLAN row vanishes from every column afterward
    (simulates the VLAN being concurrently deleted mid-write)."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for base in (
            oids.DOT1Q_VLAN_STATIC_NAME,
            oids.DOT1Q_VLAN_STATIC_EGRESS,
            oids.DOT1Q_VLAN_STATIC_UNTAGGED,
        ):
            self._tables[base] = []


def test_set_pvid_sets_gauge32():
    client = ApplyingVlanClient(_vlan_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_pvid(10, 90, force=True)
    sv = client.sets[0]
    assert sv.oid == f"{oids.DOT1Q_PVID}.10"
    assert sv.type_letter == "u"
    assert sv.value == 90


def test_set_pvid_verification_failure_raises():
    # apply=False: the SET is recorded but never lands in the read tables, so
    # the post-write PVID read-back still shows the pre-write value.
    client = FakeWriteClient(_vlan_tables(), apply=False)
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_pvid(10, 90, force=True)
    assert exc.value.after is not None
    assert (10, 90) not in exc.value.after


def test_async_set_pvid_happy_path():
    client = ApplyingVlanAsyncClient(_vlan_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    asyncio.run(w.set_pvid(10, 90, force=True))
    sv = client.sets[0]
    assert sv.oid == f"{oids.DOT1Q_PVID}.10"
    assert sv.type_letter == "u"
    assert sv.value == 90


def test_async_set_pvid_verification_failure_raises():
    client = FakeAsyncWriteClient(_vlan_tables(), apply=False)
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        asyncio.run(w.set_pvid(10, 90, force=True))
    assert exc.value.after is not None
    assert (10, 90) not in exc.value.after


def test_set_vlan_membership_rmw_preserves_other_ports():
    client = ApplyingVlanClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    egress_oid = f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
    egress_sv = next(s for s in client.sets if s.oid == egress_oid)
    assert egress_sv.type_letter == "x"
    assert decode_port_bitmap(egress_sv.value) == frozenset({1, 2, 10, 25})  # kept
    untagged_oid = f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.90"
    untag_sv = next(s for s in client.sets if s.oid == untagged_oid)
    assert decode_port_bitmap(untag_sv.value) == frozenset({1, 2})  # 25 tagged only


class EgressOnlyVlanClient(FakeWriteClient):
    """Applies the egress SET but IGNORES the untagged SET (buggy device)."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
                self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                    SnmpRow(vb.oid, vb.value, "Hex-STRING")]
            # untagged column deliberately not applied


def test_set_vlan_membership_catches_dropped_untagged_write():
    # UNTAGGED mode sets both egress AND untagged; the client drops untagged.
    client = EgressOnlyVlanClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_vlan_membership(90, 25, VlanMode.UNTAGGED, force=True)
    assert "untagged" in str(exc.value)


def test_set_vlan_membership_missing_vlan_is_precondition_not_verify_error():
    client = ApplyingVlanClient({})  # no VLAN 90 present
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(SnmpError):
        w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    assert client.sets == []  # precondition failed before any SET


def test_set_vlan_membership_vlan_disappears_after_write_raises_verification_error():
    # after is None: the "VLAN/port disappeared from the walk" branch.
    client = VlanDisappearsClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    assert "disappeared" in str(exc.value)
    assert exc.value.after is None


def test_set_vlan_membership_bitmaps_are_8_bytes_for_52_port_model():
    # Width-preservation (Fix 2): a real 52-port model's re-encoded bitmaps
    # must stay 8 bytes wide, unchanged from before the width-threading fix.
    client = ApplyingVlanClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True)
    egress_sv = next(
        s for s in client.sets if s.oid == f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
    )
    untagged_sv = next(
        s for s in client.sets if s.oid == f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.90"
    )
    assert len(egress_sv.value) == 8
    assert len(untagged_sv.value) == 8


def test_async_set_vlan_membership_rmw_preserves_other_ports():
    client = ApplyingVlanAsyncClient(_vlan_tables(member=(1, 2, 10), untagged=(1, 2)))
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    asyncio.run(w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True))
    egress_oid = f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.90"
    egress_sv = next(s for s in client.sets if s.oid == egress_oid)
    assert egress_sv.type_letter == "x"
    assert decode_port_bitmap(egress_sv.value) == frozenset({1, 2, 10, 25})  # kept
    untagged_oid = f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.90"
    untag_sv = next(s for s in client.sets if s.oid == untagged_oid)
    assert decode_port_bitmap(untag_sv.value) == frozenset({1, 2})  # 25 tagged only


def test_async_set_vlan_membership_catches_dropped_untagged_write():
    # UNTAGGED mode sets both egress AND untagged; the client drops untagged.
    client = EgressOnlyVlanAsyncClient(
        _vlan_tables(member=(1, 2, 10), untagged=(1, 2))
    )
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        asyncio.run(w.set_vlan_membership(90, 25, VlanMode.UNTAGGED, force=True))
    assert "untagged" in str(exc.value)


def test_async_set_vlan_membership_missing_vlan_is_precondition_not_verify_error():
    client = ApplyingVlanAsyncClient({})  # no VLAN 90 present
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(SnmpError):
        asyncio.run(w.set_vlan_membership(90, 25, VlanMode.TAGGED, force=True))
    assert client.sets == []  # precondition failed before any SET


_ROW_STATUS_NAME = oids.DOT1Q_VLAN_STATIC_NAME
_ROW_STATUS_COL = oids.DOT1Q_VLAN_STATIC_ROW_STATUS


def _apply_row_status_and_name(tables, vbs):
    """Shared apply logic for ApplyingRowStatusClient/-AsyncClient."""
    names = tables.setdefault(_ROW_STATUS_NAME, [])
    for vb in vbs:
        if vb.oid.startswith(_ROW_STATUS_COL):
            vid = vb.oid.rsplit(".", 1)[1]
            if int(vb.value) == oids.ROW_STATUS_DESTROY:
                tables[_ROW_STATUS_NAME] = [
                    r for r in names if not r.oid.endswith(f".{vid}")
                ]
            elif int(vb.value) == oids.ROW_STATUS_CREATE_AND_GO:
                names.append(SnmpRow(f"{_ROW_STATUS_NAME}.{vid}", "", "STRING"))
        elif vb.oid.startswith(_ROW_STATUS_NAME):
            vid = vb.oid.rsplit(".", 1)[1]
            tables[_ROW_STATUS_NAME] = [
                r for r in tables[_ROW_STATUS_NAME] if not r.oid.endswith(f".{vid}")
            ]
            val = vb.value.decode() if isinstance(vb.value, bytes) else str(vb.value)
            tables[_ROW_STATUS_NAME].append(SnmpRow(vb.oid, val, "STRING"))


class ApplyingRowStatusClient(FakeWriteClient):
    """Applies RowStatus create/destroy + name into read tables so verify passes."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        _apply_row_status_and_name(self._tables, vbs)


class ApplyingRowStatusAsyncClient(FakeAsyncWriteClient):
    """Async twin of ApplyingRowStatusClient."""

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        _apply_row_status_and_name(self._tables, vbs)

    async def set(self, vb):
        await self.set_many([vb])


def test_create_vlan_sets_rowstatus_and_name():
    client = ApplyingRowStatusClient({})
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.create_vlan(200, "guests")
    kinds = {(s.oid, s.type_letter, s.value) for s in client.sets}
    assert (f"{_ROW_STATUS_COL}.200", "i", oids.ROW_STATUS_CREATE_AND_GO) in kinds
    assert (f"{_ROW_STATUS_NAME}.200", "s", "guests") in kinds


def test_delete_vlan_destroys_and_verifies_absent():
    client = ApplyingRowStatusClient(
        {_ROW_STATUS_NAME: [SnmpRow(f"{_ROW_STATUS_NAME}.200", "guests", "STRING")]}
    )
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.delete_vlan(200)
    assert client.sets == [
        SetVarbind(f"{_ROW_STATUS_COL}.200", oids.ROW_STATUS_DESTROY, "i")
    ]


def test_delete_vlan_protected_member_requires_force():
    # VLAN 90 has member ports {1, 2, 10}; port 1 is protected. Deleting it
    # would strip membership from the protected port (review item 3).
    client = ApplyingRowStatusClient(
        _vlan_tables(vid=90, member=(1, 2, 10), untagged=(1, 2))
    )
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({1}))
    with pytest.raises(ProtectedPortError):
        w.delete_vlan(90)
    assert client.sets == []           # nothing sent when the guard fires
    w.delete_vlan(90, force=True)      # force bypasses the guard
    assert any(s.oid == f"{_ROW_STATUS_COL}.90" for s in client.sets)


def test_delete_vlan_missing_vlan_is_precondition_not_verify_error():
    client = ApplyingRowStatusClient({})  # VLAN 999 does not exist
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(SnmpError):
        w.delete_vlan(999)
    assert client.sets == []  # precondition failed before any SET


def test_async_create_vlan_sets_rowstatus_and_name():
    client = ApplyingRowStatusAsyncClient({})
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    asyncio.run(w.create_vlan(200, "guests"))
    kinds = {(s.oid, s.type_letter, s.value) for s in client.sets}
    assert (f"{_ROW_STATUS_COL}.200", "i", oids.ROW_STATUS_CREATE_AND_GO) in kinds
    assert (f"{_ROW_STATUS_NAME}.200", "s", "guests") in kinds


def test_async_delete_vlan_destroys_and_verifies_absent():
    client = ApplyingRowStatusAsyncClient(
        {_ROW_STATUS_NAME: [SnmpRow(f"{_ROW_STATUS_NAME}.200", "guests", "STRING")]}
    )
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    asyncio.run(w.delete_vlan(200))
    assert client.sets == [
        SetVarbind(f"{_ROW_STATUS_COL}.200", oids.ROW_STATUS_DESTROY, "i")
    ]


def test_async_delete_vlan_protected_member_requires_force():
    client = ApplyingRowStatusAsyncClient(
        _vlan_tables(vid=90, member=(1, 2, 10), untagged=(1, 2))
    )
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({1}))
    with pytest.raises(ProtectedPortError):
        asyncio.run(w.delete_vlan(90))
    assert client.sets == []
    asyncio.run(w.delete_vlan(90, force=True))
    assert any(s.oid == f"{_ROW_STATUS_COL}.90" for s in client.sets)


def test_async_delete_vlan_missing_vlan_is_precondition_not_verify_error():
    client = ApplyingRowStatusAsyncClient({})  # VLAN 999 does not exist
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(SnmpError):
        asyncio.run(w.delete_vlan(999))


# --- cycle_poe / clear_poe_fault (injectable timeouts) ----------------------


class CoherentPoeClient(FakeWriteClient):
    """Mimics device coherence: admin off -> detect=1 + link down; on -> detect=3."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1."):
                port = int(vb.oid.rsplit(".", 1)[1])
                on = int(vb.value) == 1
                pse = oids.PETH_PSE_PORT_TABLE
                self._tables[oids.PETH_PSE_PORT_TABLE] = [
                    SnmpRow(f"{pse}.3.1.{port}", 1 if on else 2, "INTEGER"),
                    SnmpRow(f"{pse}.6.1.{port}", 3 if on else 1, "INTEGER"),
                ]
                self._tables[oids.IF_OPER_STATUS] = [
                    SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1 if on else 2, "INTEGER")]


class AsyncCoherentPoeClient(FakeAsyncWriteClient):
    """Async twin of ``CoherentPoeClient``."""

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1."):
                port = int(vb.oid.rsplit(".", 1)[1])
                on = int(vb.value) == 1
                pse = oids.PETH_PSE_PORT_TABLE
                self._tables[oids.PETH_PSE_PORT_TABLE] = [
                    SnmpRow(f"{pse}.3.1.{port}", 1 if on else 2, "INTEGER"),
                    SnmpRow(f"{pse}.6.1.{port}", 3 if on else 1, "INTEGER"),
                ]
                self._tables[oids.IF_OPER_STATUS] = [
                    SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1 if on else 2, "INTEGER")]


class AsyncStuckOffPoeClient(FakeAsyncWriteClient):
    """Async twin of ``StuckOffPoeClient``: admin off is coherent, but admin-on
    never resumes delivering (detect stays 'searching' forever)."""

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1."):
                port = int(vb.oid.rsplit(".", 1)[1])
                if int(vb.value) == 2:  # admin off: coherent transition
                    self._tables[oids.PETH_PSE_PORT_TABLE] = [
                        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}", 2, "INTEGER"),
                        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}", 1, "INTEGER"),
                    ]
                    self._tables[oids.IF_OPER_STATUS] = [
                        SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 2, "INTEGER")]
                # admin on: intentionally left un-wired -> detect stays "searching"
                # forever, so phase 2 (-> delivering) never terminates on its own.


class StuckOffPoeClient(FakeWriteClient):
    """Turns off coherently, but admin-on never resumes delivering -- used to
    exercise the phase-2 (on_timeout) branch of ``cycle_poe``."""

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            if vb.oid.startswith(f"{oids.PETH_PSE_PORT_TABLE}.3.1."):
                port = int(vb.oid.rsplit(".", 1)[1])
                if int(vb.value) == 2:  # admin off: coherent transition
                    self._tables[oids.PETH_PSE_PORT_TABLE] = [
                        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}", 2, "INTEGER"),
                        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}", 1, "INTEGER"),
                    ]
                    self._tables[oids.IF_OPER_STATUS] = [
                        SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 2, "INTEGER")]
                # admin on: intentionally left un-wired -> detect stays "searching"
                # forever, so phase 2 (-> delivering) never terminates on its own.


def _incrementing_clock(start: float = 0.0, step: float = 100.0):
    """A fake ``clock`` that jumps far past any small timeout on every call --
    guarantees a bounded, deterministic test runtime with zero real sleeping,
    instead of racing a real wall clock."""
    state = {"t": start}

    def _clock() -> float:
        state["t"] += step
        return state["t"]

    return _clock


def _poe_full_tables(port=5):
    return {
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}", 1, "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.{port}", 3, "INTEGER"),
        ],
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.{port}", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.{port}", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.{port}", "1/0/5", "STRING")],
    }


def test_cycle_poe_off_then_on_terminates_fast():
    client = CoherentPoeClient(_poe_full_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    calls: list[float] = []
    w.cycle_poe(5, force=True,
                timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
                sleep=calls.append)
    prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
    admin_sets = [s.value for s in client.sets if s.oid.startswith(prefix)]
    assert admin_sets == [2, 1]  # off then on


def test_clear_poe_fault_recovers_detect():
    tables = _poe_full_tables()
    tables[oids.PETH_PSE_PORT_TABLE] = [
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 1, "INTEGER"),
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", 4, "INTEGER"),  # FAULT
    ]
    client = CoherentPoeClient(tables)
    w = SnmpWriter(client, get_model("gsm7252ps"))
    calls: list[float] = []
    w.clear_poe_fault(5, force=True,
                      timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
                      sleep=calls.append)
    detect = next(p.detect for p in w._reader.get_poe() if p.port == 5)
    assert detect is not PoEDetect.FAULT


def test_cycle_poe_protected_port_requires_force():
    client = CoherentPoeClient(_poe_full_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        w.cycle_poe(5)
    assert client.sets == []  # nothing sent without force


def test_clear_poe_fault_protected_port_requires_force():
    client = CoherentPoeClient(_poe_full_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        w.clear_poe_fault(5)
    assert client.sets == []  # nothing sent without force


def test_cycle_poe_off_never_reached_raises_timeout_and_terminates():
    """A device that never turns PoE off must raise a typed timeout error
    instead of looping forever. The incrementing fake clock proves the loop
    terminates deterministically without depending on real elapsed time."""
    client = FakeWriteClient(_poe_full_tables(), apply=False)  # SET never applied
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError, match="did not turn off"):
        w.cycle_poe(5, force=True,
                    timeouts=PoeCycleTimeouts(off_timeout=1, poll_interval=0),
                    sleep=lambda _: None, clock=_incrementing_clock())


def test_cycle_poe_on_never_reached_raises_timeout_and_terminates():
    """Phase 2 (-> delivering) must also time out with a typed error, not
    hang, when detect never leaves 'searching' after admin is re-enabled."""
    client = StuckOffPoeClient(_poe_full_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError, match="did not return to delivering"):
        w.cycle_poe(
            5, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
            sleep=lambda _: None, clock=_incrementing_clock())


def test_clear_poe_fault_never_recovers_raises_timeout_and_terminates():
    tables = _poe_full_tables()
    tables[oids.PETH_PSE_PORT_TABLE] = [
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 1, "INTEGER"),
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", 4, "INTEGER"),  # stuck FAULT
    ]
    client = FakeWriteClient(tables, apply=False)  # SETs never applied
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError, match="still in FAULT"):
        w.clear_poe_fault(5, force=True,
                          timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
                          sleep=lambda _: None, clock=_incrementing_clock())


def test_async_cycle_poe_off_then_on_terminates_fast():
    client = AsyncCoherentPoeClient(_poe_full_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    calls: list[float] = []

    async def _sleep(seconds: float) -> None:
        calls.append(seconds)

    asyncio.run(w.cycle_poe(
        5, force=True,
        timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
        sleep=_sleep))
    prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
    admin_sets = [s.value for s in client.sets if s.oid.startswith(prefix)]
    assert admin_sets == [2, 1]


def test_async_clear_poe_fault_recovers_detect():
    tables = _poe_full_tables()
    tables[oids.PETH_PSE_PORT_TABLE] = [
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 1, "INTEGER"),
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", 4, "INTEGER"),  # FAULT
    ]
    client = AsyncCoherentPoeClient(tables)
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))

    async def _sleep(seconds: float) -> None:
        return None

    asyncio.run(w.clear_poe_fault(
        5, force=True,
        timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
        sleep=_sleep))
    detect = next(p.detect for p in asyncio.run(w._reader.get_poe()) if p.port == 5)
    assert detect is not PoEDetect.FAULT


def test_async_cycle_poe_protected_port_requires_force():
    client = AsyncCoherentPoeClient(_poe_full_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        asyncio.run(w.cycle_poe(5))
    assert client.sets == []


def test_async_cycle_poe_off_never_reached_raises_timeout_and_terminates():
    client = FakeAsyncWriteClient(_poe_full_tables(), apply=False)
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))

    async def _sleep(seconds: float) -> None:
        return None

    with pytest.raises(WriteVerificationError, match="did not turn off"):
        asyncio.run(w.cycle_poe(
            5, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, poll_interval=0),
            sleep=_sleep, clock=_incrementing_clock()))
    assert client.sets  # the off SET was issued, but never took effect


def test_async_cycle_poe_on_never_reached_raises_timeout_and_terminates():
    """Async phase-2 timeout: detect never leaves 'searching' after admin
    is re-enabled. Must raise typed error and terminate deterministically."""
    client = AsyncStuckOffPoeClient(_poe_full_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))

    async def _sleep(seconds: float) -> None:
        return None

    with pytest.raises(WriteVerificationError, match="did not return to delivering"):
        asyncio.run(w.cycle_poe(
            5, force=True,
            timeouts=PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0),
            sleep=_sleep, clock=_incrementing_clock()))


def test_async_clear_poe_fault_never_recovers_raises_timeout_and_terminates():
    """Async clear_poe_fault timeout: FAULT state never clears despite device
    being re-enabled. Must raise typed error and terminate deterministically."""
    tables = _poe_full_tables()
    tables[oids.PETH_PSE_PORT_TABLE] = [
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.5", 1, "INTEGER"),
        SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.5", 4, "INTEGER"),  # stuck FAULT
    ]
    client = FakeAsyncWriteClient(tables, apply=False)  # SETs never applied
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))

    async def _sleep(seconds: float) -> None:
        return None

    with pytest.raises(WriteVerificationError, match="still in FAULT"):
        asyncio.run(w.clear_poe_fault(
            5, force=True,
            timeouts=PoeCycleTimeouts(on_timeout=1, poll_interval=0),
            sleep=_sleep, clock=_incrementing_clock()))


def test_async_clear_poe_fault_protected_port_requires_force():
    """Protected port guard must block clear_poe_fault unless force=True."""
    client = AsyncCoherentPoeClient(_poe_full_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"), protected_ports=frozenset({5}))
    with pytest.raises(ProtectedPortError):
        asyncio.run(w.clear_poe_fault(5))
    assert client.sets == []  # nothing sent without force
    asyncio.run(w.clear_poe_fault(5, force=True))  # force bypasses the guard
    assert client.sets


_PPE = ProtectedPortError  # alias for clarity in the mgmt-IP tests below


def _mgmt_tables(addr="10.1.5.20", mask="255.255.255.0", gw="10.1.5.1"):
    return {
        oids.IP_ADENT_ADDR: [
            SnmpRow(f"{oids.IP_ADENT_ADDR}.{addr}", addr, "IpAddress")
        ],
        oids.IP_ADENT_NETMASK: [
            SnmpRow(f"{oids.IP_ADENT_NETMASK}.{addr}", mask, "IpAddress")
        ],
        oids.IP_ROUTE_DEST: [
            SnmpRow(f"{oids.IP_ROUTE_DEST}.0.0.0.0", "0.0.0.0", "IpAddress")
        ],
        oids.IP_ROUTE_NEXTHOP: [
            SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", gw, "IpAddress")
        ],
    }


def test_set_mgmt_ip_requires_force():
    client = FakeWriteClient(_mgmt_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(_PPE):
        w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
    assert client.sets == []


class _MgmtApply(FakeWriteClient):
    """Applies all three mgmt-IP write OIDs into the read projection.

    Optionally skips one field (``skip``) to simulate a device that accepts the
    address but silently drops the netmask/gateway write.
    """

    def __init__(self, tables, *, skip=None):
        super().__init__(tables)
        self._vo = oids.vendor_oids(get_model("gsm7252ps"))
        self._skip = skip
        self._addr = "10.1.5.20"  # current mgmt address key for the ip tables

    def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            val = str(vb.value)
            if (
                vb.oid == self._vo.mgmt_write_addr_unverified
                and self._skip != "address"
            ):
                self._addr = val
                self._tables[oids.IP_ADENT_ADDR] = [
                    SnmpRow(f"{oids.IP_ADENT_ADDR}.{val}", val, "IpAddress")
                ]
            elif (
                vb.oid == self._vo.mgmt_write_netmask_unverified
                and self._skip != "netmask"
            ):
                self._tables[oids.IP_ADENT_NETMASK] = [
                    SnmpRow(f"{oids.IP_ADENT_NETMASK}.{self._addr}", val, "IpAddress")
                ]
            elif (
                vb.oid == self._vo.mgmt_write_gateway_unverified
                and self._skip != "gateway"
            ):
                self._tables[oids.IP_ROUTE_NEXTHOP] = [
                    SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", val, "IpAddress")
                ]


def test_set_mgmt_ip_emits_three_ipaddress_sets():
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    client = _MgmtApply(_mgmt_tables())
    w = SnmpWriter(client, get_model("gsm7252ps"))
    w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    letters = {(s.oid, s.type_letter) for s in client.sets}
    assert (vo.mgmt_write_addr_unverified, "a") in letters
    assert (vo.mgmt_write_netmask_unverified, "a") in letters
    assert (vo.mgmt_write_gateway_unverified, "a") in letters


def test_set_mgmt_ip_verifies_gateway_not_just_address():
    # Device accepts address+netmask but drops the gateway write; verify must
    # catch it and name the gateway field (review item 2).
    client = _MgmtApply(_mgmt_tables(), skip="gateway")
    w = SnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    assert "gateway" in str(exc.value)


class _AsyncMgmtApply(FakeAsyncWriteClient):
    """Async twin of ``_MgmtApply``."""

    def __init__(self, tables, *, skip=None):
        super().__init__(tables)
        self._vo = oids.vendor_oids(get_model("gsm7252ps"))
        self._skip = skip
        self._addr = "10.1.5.20"

    async def set_many(self, vbs):
        self.sets.extend(vbs)
        for vb in vbs:
            val = str(vb.value)
            if (
                vb.oid == self._vo.mgmt_write_addr_unverified
                and self._skip != "address"
            ):
                self._addr = val
                self._tables[oids.IP_ADENT_ADDR] = [
                    SnmpRow(f"{oids.IP_ADENT_ADDR}.{val}", val, "IpAddress")
                ]
            elif (
                vb.oid == self._vo.mgmt_write_netmask_unverified
                and self._skip != "netmask"
            ):
                self._tables[oids.IP_ADENT_NETMASK] = [
                    SnmpRow(f"{oids.IP_ADENT_NETMASK}.{self._addr}", val, "IpAddress")
                ]
            elif (
                vb.oid == self._vo.mgmt_write_gateway_unverified
                and self._skip != "gateway"
            ):
                self._tables[oids.IP_ROUTE_NEXTHOP] = [
                    SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", val, "IpAddress")
                ]


def test_async_set_mgmt_ip_requires_force():
    client = FakeAsyncWriteClient(_mgmt_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(_PPE):
        asyncio.run(w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1"))
    assert client.sets == []


def test_async_set_mgmt_ip_emits_three_ipaddress_sets():
    vo = oids.vendor_oids(get_model("gsm7252ps"))
    client = _AsyncMgmtApply(_mgmt_tables())
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    asyncio.run(w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True))
    letters = {(s.oid, s.type_letter) for s in client.sets}
    assert (vo.mgmt_write_addr_unverified, "a") in letters
    assert (vo.mgmt_write_netmask_unverified, "a") in letters
    assert (vo.mgmt_write_gateway_unverified, "a") in letters


def test_async_set_mgmt_ip_verifies_gateway_not_just_address():
    client = _AsyncMgmtApply(_mgmt_tables(), skip="gateway")
    w = AsyncSnmpWriter(client, get_model("gsm7252ps"))
    with pytest.raises(WriteVerificationError) as exc:
        asyncio.run(w.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True))
    assert "gateway" in str(exc.value)
