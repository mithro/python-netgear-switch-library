from __future__ import annotations

import json

from netgear_switch.cli import format as fmt
from netgear_switch.models import (
    IpMode,
    LLDPNeighbor,
    MacEntry,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStatus,
    Sensor,
    SwitchData,
    VLANInfo,
    VlanMode,  # noqa: F401 -- imported to pin the public model surface
)


def test_to_json_serializes_dataclass_enum_and_frozenset() -> None:
    vlan = VLANInfo(
        vlan_id=90,
        name="iot",
        member_ports=frozenset({10, 2}),
        tagged_ports=frozenset({2}),
        untagged_ports=frozenset({10}),
    )
    data = json.loads(fmt.to_json(vlan))
    assert data["vlan_id"] == 90
    assert data["member_ports"] == [2, 10]  # frozenset -> sorted list


def test_to_json_serializes_enum_value() -> None:
    poe = PoEStatus(
        port=1, admin_enabled=True, detect=PoEDetect.DELIVERING, power_mw=12800
    )
    data = json.loads(fmt.to_json(poe))
    assert data["detect"] == "delivering"
    assert data["power_mw"] == 12800


def test_ports_table_has_header_and_rows() -> None:
    ports = [
        PortStatus(
            port=1, name="1/0/1", admin_enabled=True, link_up=True, speed_mbps=1000
        )
    ]
    text = fmt.ports_table(ports)
    lines = text.splitlines()
    assert lines[0].split() == ["Port", "Name", "Link", "Admin", "Speed"]
    assert lines[1] == "1     1/0/1  up    enabled  1000 "


def test_ports_table_renders_none_speed_as_dash() -> None:
    # link_up=True but admin_enabled=False: distinct values in the Link and
    # Admin columns so the exact text below fails if they are transposed.
    ports = [
        PortStatus(
            port=3, name=None, admin_enabled=False, link_up=True, speed_mbps=None
        )
    ]
    text = fmt.ports_table(ports)
    assert text == (
        "Port  Name  Link  Admin     Speed\n3     -     up    disabled  -    "
    )


def test_ports_table_distinguishes_link_admin_name_and_speed_columns() -> None:
    # Two ports with fully "crossed" values: if any pair of columns (Link/
    # Admin, or the per-row Name/Speed) were swapped, at least one of these
    # exact rows would change.
    ports = [
        PortStatus(
            port=1, name="uplink", admin_enabled=False, link_up=True, speed_mbps=1000
        ),
        PortStatus(
            port=2, name="downlink", admin_enabled=True, link_up=False, speed_mbps=None
        ),
    ]
    text = fmt.ports_table(ports)
    assert text == (
        "Port  Name      Link  Admin     Speed\n"
        "1     uplink    up    disabled  1000 \n"
        "2     downlink  down  enabled   -    "
    )


def test_mgmt_ip_text_labels_every_field() -> None:
    # address/netmask/gateway are all distinct strings so the exact-text
    # assertion below fails if netmask and gateway were swapped.
    cfg = MgmtIpConfig(
        mode=IpMode.STATIC,
        address="10.1.5.20",
        netmask="255.255.255.0",
        gateway="10.1.5.1",
    )
    text = fmt.mgmt_ip_text(cfg)
    assert text == (
        "mode:    static\n"
        "address: 10.1.5.20\n"
        "netmask: 255.255.255.0\n"
        "gateway: 10.1.5.1"
    )


def test_poe_table_distinguishes_admin_and_detect_columns() -> None:
    # Port 1 is admin-enabled but only "searching"; port 2 is admin-disabled
    # yet "delivering". This exact text fails if Admin and Detect were
    # transposed.
    entries = [
        PoEStatus(
            port=1, admin_enabled=True, detect=PoEDetect.SEARCHING, power_mw=1500
        ),
        PoEStatus(
            port=2, admin_enabled=False, detect=PoEDetect.DELIVERING, power_mw=None
        ),
    ]
    text = fmt.poe_table(entries)
    assert text == (
        "Port  Admin     Detect      Power(mW)\n"
        "1     enabled   searching   1500     \n"
        "2     disabled  delivering  -        "
    )


def test_vlans_table_distinguishes_tagged_and_untagged_columns() -> None:
    # Ports {1, 2} are untagged and port {3} is tagged: the exact text fails
    # if the Tagged/Untagged columns were swapped.
    vlans = [
        VLANInfo(
            vlan_id=10,
            name="data",
            member_ports=frozenset({1, 2, 3}),
            tagged_ports=frozenset({3}),
            untagged_ports=frozenset({1, 2}),
        )
    ]
    text = fmt.vlans_table(vlans)
    assert text == ("VLAN  Name  Untagged  Tagged\n10    data  1,2       3     ")


def test_pvids_table_renders_exact_port_to_pvid_rows() -> None:
    pvids = [(1, 10), (2, 20)]
    text = fmt.pvids_table(pvids)
    assert text == ("Port  PVID\n1     10  \n2     20  ")


def test_lldp_table_renders_exact_neighbor_fields() -> None:
    neighbors = [
        LLDPNeighbor(
            local_port=1,
            remote_sys_name="switch-b",
            remote_port_desc="ge-0/0/1",
            remote_chassis_id="aa:bb:cc:dd:ee:ff",
        )
    ]
    text = fmt.lldp_table(neighbors)
    assert text == (
        "Port  Neighbor  RemotePort  ChassisID        \n"
        "1     switch-b  ge-0/0/1    aa:bb:cc:dd:ee:ff"
    )


def test_macs_table_renders_exact_mac_port_vlan_cells() -> None:
    entries = [MacEntry(mac="00:11:22:33:44:55", port=7, vlan_id=30)]
    text = fmt.macs_table(entries)
    assert text == (
        "MAC                Port  VLAN\n00:11:22:33:44:55  7     30  "
    )


def test_sensors_table_renders_exact_name_kind_value_unit_cells() -> None:
    sensors = [Sensor(name="CPU", kind="temperature", value=45.5, unit="C")]
    text = fmt.sensors_table(sensors)
    assert text == (
        "Sensor  Kind         Value  Unit\nCPU     temperature  45.5   C   "
    )


def test_snapshot_text_includes_all_sections() -> None:
    data = SwitchData(
        model="gsm7252ps",
        host="10.1.5.20",
        ports=(PortStatus(1, "1/0/1", True, True, 1000),),
        mgmt_ip=MgmtIpConfig(IpMode.STATIC, "10.1.5.20", "255.255.255.0", "10.1.5.1"),
    )
    text = fmt.snapshot_text(data)
    for heading in ("## Ports", "## PoE", "## VLANs", "## Mgmt IP"):
        assert heading in text
