import pytest

from netgear_switch.errors import UnknownModelError
from netgear_switch.registry import MODELS, Backend, SwitchClass, get_model

_VERIFIED_KEYS = (
    "m4300-24x", "m4300-16x", "gsm7252ps", "gsm7228ps", "gs110emx", "gs305ep",
)
_UNVERIFIED_KEYS = ("m7300", "xs748t", "gs728tpp")


def test_known_models_present():
    for key in _VERIFIED_KEYS + _UNVERIFIED_KEYS:
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


def test_verified_defaults_true_for_existing_models():
    for key in _VERIFIED_KEYS:
        assert get_model(key).verified is True, key


def test_unverified_models_are_honestly_flagged():
    for key in _UNVERIFIED_KEYS:
        assert get_model(key).verified is False, key


def test_m7300_registered_fully_managed_snmp_only():
    m = get_model("m7300")
    assert m.switch_class is SwitchClass.FULLY_MANAGED
    assert m.backends == frozenset({Backend.SNMP})
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.10"
    assert m.port_count == 24
    assert m.poe_port_count == 0
    assert m.verified is False


def test_xs748t_registered_smart_managed_pro_snmp_only():
    m = get_model("xs748t")
    assert m.switch_class is SwitchClass.SMART_MANAGED_PRO
    assert m.backends == frozenset({Backend.SNMP})
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.11"
    assert m.port_count == 48
    assert m.poe_port_count == 0
    assert m.verified is False


def test_gs728tpp_registered_smart_managed_pro_snmp_only():
    # HTTP is deliberately NOT registered here even though a web UI exists
    # (see registry.py's comment): the real login flow is a third, distinct
    # scheme this codebase doesn't implement yet.
    m = get_model("gs728tpp")
    assert m.switch_class is SwitchClass.SMART_MANAGED_PRO
    assert m.backends == frozenset({Backend.SNMP})
    assert Backend.HTTP not in m.backends
    assert m.snmp_vendor_base == "1.3.6.1.4.1.4526.11"
    assert m.port_count == 28
    assert m.poe_port_count == 24
    assert m.verified is False


def test_registry_has_no_duplicate_keys_and_valid_enums():
    keys = [m.key for m in MODELS.values()]
    assert len(keys) == len(set(keys))
    for key, model in MODELS.items():
        assert model.key == key
        assert isinstance(model.switch_class, SwitchClass)
        assert all(isinstance(b, Backend) for b in model.backends)
        assert model.backends, f"{key} has no backends"
