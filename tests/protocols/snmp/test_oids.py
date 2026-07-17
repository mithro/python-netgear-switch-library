from __future__ import annotations

from netgear_switch.protocols.snmp import oids
from netgear_switch.registry import get_model


def test_standard_oids_are_dotted_no_leading_dot():
    assert oids.IF_OPER_STATUS == "1.3.6.1.2.1.2.2.1.8"
    assert oids.PETH_PSE_PORT_TABLE == "1.3.6.1.2.1.105.1.1.1"
    assert oids.DOT1Q_PVID == "1.3.6.1.2.1.17.7.1.4.5.1.1"
    assert not oids.IF_NAME.startswith(".")


def test_vendor_oids_use_registry_base_fully_managed():
    v = oids.vendor_oids(get_model("gsm7252ps"))  # base 4526.10
    assert v.poe_power_mw == "1.3.6.1.4.1.4526.10.15.1.1.1.2"
    assert v.box_fan == "1.3.6.1.4.1.4526.10.43.1.6.1.4"
    assert v.box_psu_power == "1.3.6.1.4.1.4526.10.43.1.8.1.5"
    assert v.box_temp == "1.3.6.1.4.1.4526.10.43.1.15.1.3"
    # The single named UNVERIFIED DHCP-mode OID (never a bare .99.1 literal).
    assert v.dhcp_mode_unverified == "1.3.6.1.4.1.4526.10.99.1"


def test_vendor_oids_use_registry_base_smart_managed():
    v = oids.vendor_oids(get_model("gsm7228ps"))  # base 4526.11
    assert v.poe_power_mw == "1.3.6.1.4.1.4526.11.15.1.1.1.2"


def test_vendor_oids_rejects_model_without_base():
    import pytest

    from netgear_switch.errors import UnsupportedCapabilityError

    with pytest.raises(UnsupportedCapabilityError):
        oids.vendor_oids(get_model("gs110emx"))  # Plus, no SNMP


def test_box_sensor_columns_cover_fan_psu_temp():
    kinds = {kind for kind, _unit, _suffix in oids.BOX_SENSOR_COLUMNS}
    assert kinds == {"fan", "power", "temperature"}
