from __future__ import annotations

import pytest

from netgear_switch.errors import ProtectedPortError, WriteVerificationError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.snmp_write import SnmpWriter


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
