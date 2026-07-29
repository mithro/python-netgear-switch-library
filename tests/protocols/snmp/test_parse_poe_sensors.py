# tests/protocols/snmp/test_parse_poe_sensors.py
from __future__ import annotations

import pytest

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.snmp import parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow


def test_parse_poe_uses_col3_admin_col6_detect_and_vendor_mw():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [
        SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER"),  # admin enabled
        SnmpRow(f"{tbl}.6.1.1", "3", "INTEGER"),  # delivering
        SnmpRow(f"{tbl}.3.1.2", "2", "INTEGER"),  # admin disabled
        SnmpRow(f"{tbl}.6.1.2", "1", "INTEGER"),  # disabled/unused
    ]
    power = [
        SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.1", "12800", "Gauge32"),
        SnmpRow("1.3.6.1.4.1.4526.10.15.1.1.1.2.1.2", "0", "Gauge32"),
    ]
    poe = parse.parse_poe(status, power)
    assert [p.port for p in poe] == [1, 2]
    assert poe[0].admin_enabled is True
    assert poe[0].detect is PoEDetect.DELIVERING
    assert poe[0].power_mw == 12800
    assert poe[1].admin_enabled is False
    assert poe[1].detect is PoEDetect.DISABLED


def test_parse_poe_missing_detect_column_raises():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER")]  # no col6
    with pytest.raises(SnmpError):
        parse.parse_poe(status, [])


def test_parse_poe_missing_admin_column_raises():
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [SnmpRow(f"{tbl}.6.1.1", "3", "INTEGER")]  # no col3
    with pytest.raises(SnmpError):
        parse.parse_poe(status, [])


def test_parse_poe_non_integer_status_value_raises():
    # Present-but-malformed status value (table drift), not absence.
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [SnmpRow(f"{tbl}.3.1.1", "not_a_number", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_poe(status, [])


def test_parse_box_sensors_skips_not_supported():
    fan = "1.3.6.1.4.1.4526.10.43.1.6.1.4"
    rows = [
        SnmpRow(f"{fan}.0", "3500", "OCTETSTR"),
        SnmpRow(f"{fan}.1", "Not Supported", "OCTETSTR"),
        SnmpRow(f"{fan}.2", "3450", "OCTETSTR"),
    ]
    sensors = parse.parse_box_sensors([("fan", "RPM", rows)])
    assert [s.name for s in sensors] == ["fan0", "fan2"]
    assert sensors[0].kind == "fan"
    assert sensors[0].unit == "RPM"
    assert sensors[0].value == 3500.0


def test_parse_box_sensors_raises_on_other_non_integer():
    temp = "1.3.6.1.4.1.4526.10.43.1.15.1.3"
    rows = [SnmpRow(f"{temp}.1", "warm", "OCTETSTR")]
    with pytest.raises(SnmpError):
        parse.parse_box_sensors([("temperature", "C", rows)])


def test_parse_poe_empty_vendor_power_yields_none():
    # A model with no vendor mW column (gs728tpp) passes an empty power walk;
    # every port then reports power_mw None, never a fabricated 0.
    tbl = "1.3.6.1.2.1.105.1.1.1"
    status = [
        SnmpRow(f"{tbl}.3.1.1", "1", "INTEGER"),
        SnmpRow(f"{tbl}.6.1.1", "2", "INTEGER"),  # searching
    ]
    poe = parse.parse_poe(status, [])
    assert poe[0].admin_enabled is True
    assert poe[0].detect is PoEDetect.SEARCHING
    assert poe[0].power_mw is None


def test_parse_entity_sensors_inventory_from_real_capture():
    import math

    from netgear_switch.protocols.snmp import oids

    # Real gs728tpp ENTITY-MIB rows (10.2.5.10 capture): two PSUs (class 6) and
    # two fans (class 7); the chassis/slot/port rows (other classes) are ignored.
    cls, name, descr = (
        oids.ENT_PHYSICAL_CLASS, oids.ENT_PHYSICAL_NAME, oids.ENT_PHYSICAL_DESCR,
    )
    class_rows = [
        SnmpRow(f"{cls}.67108992", "1", "INTEGER"),   # "Netgear" chassis -> ignored
        SnmpRow(f"{cls}.67109185", "6", "INTEGER"),   # PSU
        SnmpRow(f"{cls}.67109186", "6", "INTEGER"),   # PSU
        SnmpRow(f"{cls}.67109249", "7", "INTEGER"),   # fan
        SnmpRow(f"{cls}.67109250", "7", "INTEGER"),   # fan
        SnmpRow(f"{cls}.68420352", "3", "INTEGER"),   # "GS728TPP" module -> ignored
    ]
    name_rows = [
        SnmpRow(f"{name}.67109185", "Main PowerSupply", "OCTETSTR"),
        SnmpRow(f"{name}.67109186", "Redundant PowerSupply", "OCTETSTR"),
        SnmpRow(f"{name}.67109249", "Fan1", "OCTETSTR"),
        SnmpRow(f"{name}.67109250", "Fan2", "OCTETSTR"),
    ]
    descr_rows = [
        SnmpRow(f"{descr}.67109185", "PowerSupply", "OCTETSTR"),
        SnmpRow(f"{descr}.67109249", "Fan", "OCTETSTR"),
    ]
    sensors = parse.parse_entity_sensors(class_rows, name_rows, descr_rows)
    assert [(s.name, s.kind, s.unit) for s in sensors] == [
        ("Main PowerSupply", "power", "inventory"),
        ("Redundant PowerSupply", "power", "inventory"),
        ("Fan1", "fan", "inventory"),
        ("Fan2", "fan", "inventory"),
    ]
    # Inventory only -- SNMP supplies NO live reading for these components.
    assert all(math.isnan(s.value) for s in sensors)


def test_parse_entity_sensors_falls_back_to_descr_then_index():
    from netgear_switch.protocols.snmp import oids

    cls, descr = oids.ENT_PHYSICAL_CLASS, oids.ENT_PHYSICAL_DESCR
    # No entPhysicalName rows at all -> name falls back to entPhysicalDescr,
    # then to a synthetic "<kind><index>" when descr is absent too.
    class_rows = [
        SnmpRow(f"{cls}.10", "7", "INTEGER"),
        SnmpRow(f"{cls}.11", "6", "INTEGER"),
    ]
    descr_rows = [SnmpRow(f"{descr}.10", "Fan", "OCTETSTR")]
    sensors = parse.parse_entity_sensors(class_rows, [], descr_rows)
    assert [(s.name, s.kind) for s in sensors] == [
        ("Fan", "fan"), ("power11", "power"),
    ]
