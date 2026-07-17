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
