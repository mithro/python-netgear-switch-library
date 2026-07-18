from __future__ import annotations

import json

from netgear_switch.cli import format as fmt
from netgear_switch.models import (
    IpMode,
    MgmtIpConfig,
    PoEDetect,
    PoEStatus,
    PortStatus,
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
    assert "1/0/1" in lines[1]
    assert "up" in lines[1]
    assert "1000" in lines[1]


def test_ports_table_renders_none_speed_as_dash() -> None:
    ports = [
        PortStatus(
            port=3, name=None, admin_enabled=False, link_up=False, speed_mbps=None
        )
    ]
    row = fmt.ports_table(ports).splitlines()[1]
    assert "down" in row
    assert "disabled" in row
    assert "-" in row


def test_mgmt_ip_text_labels_every_field() -> None:
    cfg = MgmtIpConfig(
        mode=IpMode.STATIC,
        address="10.1.5.20",
        netmask="255.255.255.0",
        gateway="10.1.5.1",
    )
    text = fmt.mgmt_ip_text(cfg)
    assert "mode:    static" in text
    assert "10.1.5.20" in text


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
