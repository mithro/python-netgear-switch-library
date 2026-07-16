import pytest

from netgear_switch.errors import UnknownModelError
from netgear_switch.registry import MODELS, Backend, SwitchClass, get_model


def test_known_models_present():
    keys = ("m4300-24x", "m4300-16x", "gsm7252ps", "gsm7228ps", "gs110emx", "gs305ep")
    for key in keys:
        assert key in MODELS


def test_managed_switch_has_snmp_and_vendor_base():
    m = get_model("gsm7252ps")
    assert Backend.SNMP in m.backends
    assert m.poe_port_count == 48
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.10"
    assert m.has_mac_table is True


def test_smart_managed_pro_uses_4526_11():
    assert get_model("gsm7228ps").snmp_vendor_base == "1.3.6.1.4.1.4526.11"


def test_plus_switch_no_snmp_no_mac_table():
    p = get_model("gs110emx")
    assert Backend.SNMP not in p.backends
    assert Backend.NSDP in p.backends
    assert Backend.HTTP in p.backends
    assert p.snmp_vendor_base is None
    assert p.has_mac_table is False
    assert p.switch_class is SwitchClass.PLUS


def test_unknown_model_raises():
    with pytest.raises(UnknownModelError):
        get_model("nonesuch")
