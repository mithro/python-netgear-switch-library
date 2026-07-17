# tests/protocols/snmp/test_parse_mgmt_ip.py
from __future__ import annotations

import re

import pytest

from netgear_switch.models import IpMode
from netgear_switch.protocols.snmp import oids, parse
from netgear_switch.protocols.snmp.client import SnmpError, SnmpRow
from netgear_switch.registry import get_model

# The DHCP-mode OID comes from the ONE named constant, never a bare .99.1 literal.
_DHCP_MODE_OID = f"{oids.vendor_oids(get_model('gsm7252ps')).dhcp_mode_unverified}.0"


def test_parse_mgmt_ip_static_with_gateway():
    addr = [
        SnmpRow("1.3.6.1.2.1.4.20.1.1.127.0.0.1", "127.0.0.1", "IPADDR"),
        SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR"),
    ]
    netmask = [
        SnmpRow("1.3.6.1.2.1.4.20.1.3.10.1.5.20", "255.255.255.0", "IPADDR"),
    ]
    route_dest = [SnmpRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0", "IPADDR")]
    route_next = [SnmpRow("1.3.6.1.2.1.4.21.1.7.0.0.0.0", "10.1.5.1", "IPADDR")]
    dhcp = [SnmpRow(_DHCP_MODE_OID, "2", "INTEGER")]  # static

    cfg = parse.parse_mgmt_ip(addr, netmask, route_dest, route_next, dhcp)
    assert cfg.address == "10.1.5.20"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.1.5.1"
    assert cfg.mode is IpMode.STATIC


def test_parse_mgmt_ip_dhcp_and_unknown_default():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    cfg = parse.parse_mgmt_ip(
        addr, [], [], [],
        [SnmpRow(_DHCP_MODE_OID, "1", "INTEGER")],
    )
    assert cfg.mode is IpMode.DHCP
    # Mode OID absent -> UNKNOWN (never a guessed dhcp/static), gateway None.
    cfg2 = parse.parse_mgmt_ip(addr, [], [], [], [])
    assert cfg2.mode is IpMode.UNKNOWN
    assert cfg2.gateway is None


def test_parse_mgmt_ip_unrecognized_dhcp_mode_value_is_unknown():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    dhcp = [SnmpRow(_DHCP_MODE_OID, "3", "INTEGER")]  # unrecognized value
    cfg = parse.parse_mgmt_ip(addr, [], [], [], dhcp)
    assert cfg.mode is IpMode.UNKNOWN


def test_parse_mgmt_ip_malformed_address_raises_snmp_error():
    # Present-but-malformed (non-str where an IpAddress is required) is drift,
    # not absence, and must raise SnmpError naming the offending OID.
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", 12345, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.20.1.1.10.1.5.20")):
        parse.parse_mgmt_ip(addr, [], [], [], [])


def test_parse_mgmt_ip_malformed_netmask_raises_snmp_error():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    netmask = [SnmpRow("1.3.6.1.2.1.4.20.1.3.10.1.5.20", 255, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.20.1.3.10.1.5.20")):
        parse.parse_mgmt_ip(addr, netmask, [], [], [])


def test_parse_mgmt_ip_malformed_gateway_raises_snmp_error():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    route_dest = [SnmpRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0", "IPADDR")]
    route_next = [SnmpRow("1.3.6.1.2.1.4.21.1.7.0.0.0.0", 12345, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.21.1.7.0.0.0.0")):
        parse.parse_mgmt_ip(addr, [], route_dest, route_next, [])
