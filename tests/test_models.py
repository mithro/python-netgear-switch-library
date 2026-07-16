from netgear_switch.models import (
    LLDPNeighbor,
    MacEntry,
    PoEDetect,
    PoEStatus,
    PortStatus,
    Sensor,
    SwitchData,
    VLANInfo,
    VlanMode,
)


def test_frozen_and_equatable():
    a = PortStatus(
        port=1,
        name="eth1",
        admin_enabled=True,
        link_up=True,
        speed_mbps=1000,
    )
    b = PortStatus(
        port=1,
        name="eth1",
        admin_enabled=True,
        link_up=True,
        speed_mbps=1000,
    )
    assert a == b
    assert hash(a) == hash(b)
    import dataclasses

    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        a.port = 2  # type: ignore[misc]


def test_poe_delivering_property():
    on = PoEStatus(
        port=3,
        admin_enabled=True,
        detect=PoEDetect.DELIVERING,
        power_mw=6400,
    )
    off = PoEStatus(
        port=3,
        admin_enabled=True,
        detect=PoEDetect.SEARCHING,
        power_mw=0,
    )
    assert on.delivering is True
    assert off.delivering is False


def test_vlan_and_neighbor_and_sensor_and_mac():
    v = VLANInfo(
        vlan_id=10,
        name="int",
        member_ports=frozenset({1, 2}),
        tagged_ports=frozenset({2}),
        untagged_ports=frozenset({1}),
    )
    assert 1 in v.untagged_ports
    n = LLDPNeighbor(
        local_port=1,
        remote_sys_name="ap1",
        remote_port_desc="eth0",
        remote_chassis_id="aa:bb",
    )
    assert n.remote_sys_name == "ap1"
    s = Sensor(name="fan1", kind="fan", value=3200.0, unit="RPM")
    assert s.kind == "fan"
    m = MacEntry(mac="aa:bb:cc:dd:ee:ff", port=5, vlan_id=10)
    assert m.port == 5
    assert VlanMode.UNTAGGED.value == "untagged"


def test_switchdata_defaults_empty():
    sd = SwitchData(model="m4300-24x", host="10.1.5.19")
    assert sd.ports == ()
    assert sd.pvids == {}
