"""Tests for SNMP read model extensions: PortStats, MgmtIpConfig, IpMode."""

from __future__ import annotations

from netgear_switch.models import IpMode, MgmtIpConfig, PortStats, SwitchData


def test_portstats_is_frozen_and_hashable():
    s = PortStats(
        port=1,
        rx_bytes=10,
        tx_bytes=20,
        rx_packets=3,
        tx_packets=4,
        rx_errors=0,
        tx_errors=None,
    )
    assert hash(s) == hash(PortStats(1, 10, 20, 3, 4, 0, None))
    import dataclasses

    assert dataclasses.is_dataclass(s)


def test_mgmtipconfig_frozen_and_mode_enum():
    m = MgmtIpConfig(
        mode=IpMode.STATIC,
        address="10.1.5.20",
        netmask="255.255.255.0",
        gateway="10.1.5.1",
    )
    assert m.mode is IpMode.STATIC
    assert hash(m)  # hashable


def test_switchdata_defaults_include_stats_and_mgmt_ip():
    d = SwitchData(model="gsm7252ps", host="10.1.5.20")
    assert d.stats == ()
    assert d.mgmt_ip is None
