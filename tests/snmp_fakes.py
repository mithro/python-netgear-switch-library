# tests/snmp_fakes.py
"""Shared behaviour for the suite's canned SNMP clients.

Several test modules stand up their own fake SNMP client over a dict of canned
tables. They must all answer a walk the way a real agent does, and there is
exactly one subtlety worth centralising, because getting it wrong made four
tests fail in three different modules at once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from netgear_switch.protocols.snmp.client import SnmpRow


def walk_by_prefix(
    tables: Mapping[str, Sequence[SnmpRow]], base_oid: str
) -> list[SnmpRow]:
    """Every canned row at or under ``base_oid``, as a real agent answers.

    PREFIX semantics, not exact-key lookup. A walk of a single COLUMN has to
    return that column's rows out of a table canned under its root, the way
    ``snmpbulkwalk 1.3.6.1.2.1.105.1.1.1.3`` does against hardware.

    This is not hypothetical tidiness. ``SnmpReader.get_poe`` walks the two PoE
    columns separately (that table answers at ~0.35s per varbind on real
    firmware, so fetching the whole thing cost 102s), and every exact-key fake
    then returned NOTHING for those walks -- making PoE writes "fail to read
    back" against a switch that was never asked.
    """
    return [
        row
        for rows in tables.values()
        for row in rows
        if row.oid == base_oid or row.oid.startswith(base_oid + ".")
    ]
