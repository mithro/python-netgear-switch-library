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


def test_unimplemented_roots_empty_for_poe_model():
    # gsm7252ps has PoE ports -- the PoE MIB IS registered on this model.
    assert oids.unimplemented_roots(get_model("gsm7252ps")) == []


def test_unimplemented_roots_gates_poe_mib_for_non_poe_model():
    # m4300-24x: 0 PoE ports (verified: real capture, poe=[]) -- the PoE MIB
    # is entirely unregistered, plus the vendor PoE-power column under the
    # same model's vendor subtree.
    roots = oids.unimplemented_roots(get_model("m4300-24x"))
    assert oids.PETH_PSE_PORT_TABLE in roots
    vendor = oids.vendor_oids(get_model("m4300-24x"))
    assert vendor.poe_power_mw in roots


def test_unimplemented_roots_skips_vendor_poe_power_when_no_vendor_base():
    # A hypothetical non-PoE model with no SNMP vendor subtree at all must not
    # crash trying to resolve vendor_oids() -- only the standard PoE MIB root
    # is gated in that case.
    from netgear_switch.registry import SwitchClass, SwitchModel

    stub = SwitchModel(
        key="stub",
        display_name="stub",
        switch_class=SwitchClass.FULLY_MANAGED,
        port_count=4,
        poe_port_count=0,
        backends=frozenset(),
        snmp_vendor_base=None,
    )
    assert oids.unimplemented_roots(stub) == [oids.PETH_PSE_PORT_TABLE]


def test_is_oid_implemented_true_for_poe_model_poe_oid():
    model = get_model("gsm7252ps")
    assert oids.is_oid_implemented(model, f"{oids.PETH_PSE_PORT_TABLE}.3.1.1")


def test_is_oid_implemented_false_for_non_poe_model_poe_root_or_instance():
    model = get_model("m4300-24x")
    assert not oids.is_oid_implemented(model, oids.PETH_PSE_PORT_TABLE)
    assert not oids.is_oid_implemented(model, f"{oids.PETH_PSE_PORT_TABLE}.3.1.1")
    vendor = oids.vendor_oids(model)
    assert not oids.is_oid_implemented(model, f"{vendor.poe_power_mw}.1.1")


def test_is_oid_implemented_true_for_unrelated_oid_on_non_poe_model():
    model = get_model("m4300-24x")
    assert oids.is_oid_implemented(model, oids.SYS_DESCR)
    assert oids.is_oid_implemented(model, f"{oids.IF_ADMIN_STATUS}.1")
    vendor = oids.vendor_oids(model)
    assert oids.is_oid_implemented(model, vendor.box_fan)
