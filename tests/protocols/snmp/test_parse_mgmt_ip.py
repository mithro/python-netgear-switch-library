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
    # INTEGER OIDs are normalized to Python int by both transports (see
    # SnmpRow's docstring) -- never the str the real transports never produce.
    dhcp = [SnmpRow(_DHCP_MODE_OID, 2, "INTEGER")]  # static

    base_mac = [
        SnmpRow(
            f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0",
            bytes([0x28, 0xC6, 0x8E, 0x00, 0x00, 0x01]),
            "OCTETSTR",
        )
    ]

    cfg = parse.parse_mgmt_ip(addr, netmask, route_dest, route_next, dhcp, base_mac)
    assert cfg.address == "10.1.5.20"
    assert cfg.netmask == "255.255.255.0"
    assert cfg.gateway == "10.1.5.1"
    assert cfg.mode is IpMode.STATIC
    assert cfg.base_mac == "28:C6:8E:00:00:01"


def test_parse_mgmt_ip_dhcp_and_unknown_default():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    cfg = parse.parse_mgmt_ip(
        addr, [], [], [],
        [SnmpRow(_DHCP_MODE_OID, 1, "INTEGER")],
        [],
    )
    assert cfg.mode is IpMode.DHCP
    # Mode OID absent -> UNKNOWN (never a guessed dhcp/static), gateway None.
    cfg2 = parse.parse_mgmt_ip(addr, [], [], [], [], [])
    assert cfg2.mode is IpMode.UNKNOWN
    assert cfg2.gateway is None
    # base_mac walk absent entirely -> honest None, never fabricated.
    assert cfg2.base_mac is None


def test_parse_mgmt_ip_unrecognized_dhcp_mode_value_is_unknown():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    dhcp = [SnmpRow(_DHCP_MODE_OID, 3, "INTEGER")]  # unrecognized value
    cfg = parse.parse_mgmt_ip(addr, [], [], [], dhcp, [])
    assert cfg.mode is IpMode.UNKNOWN


def test_parse_mgmt_ip_non_int_coercible_dhcp_mode_value_is_unknown():
    # This OID is explicitly UNVERIFIED/best-effort (see
    # oids.VendorOids.dhcp_mode_unverified) -- a genuinely non-int-coercible
    # value (e.g. non-digit bytes, which real transports never produce for an
    # INTEGER OID) must degrade to UNKNOWN, never raise.
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    dhcp = [SnmpRow(_DHCP_MODE_OID, b"\xc0\x00", "INTEGER")]
    cfg = parse.parse_mgmt_ip(addr, [], [], [], dhcp, [])
    assert cfg.mode is IpMode.UNKNOWN


def test_parse_mgmt_ip_malformed_address_raises_snmp_error():
    # Present-but-malformed (non-str where an IpAddress is required) is drift,
    # not absence, and must raise SnmpError naming the offending OID.
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", 12345, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.20.1.1.10.1.5.20")):
        parse.parse_mgmt_ip(addr, [], [], [], [], [])


def test_parse_mgmt_ip_malformed_netmask_raises_snmp_error():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    netmask = [SnmpRow("1.3.6.1.2.1.4.20.1.3.10.1.5.20", 255, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.20.1.3.10.1.5.20")):
        parse.parse_mgmt_ip(addr, netmask, [], [], [], [])


def test_parse_mgmt_ip_malformed_gateway_raises_snmp_error():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    route_dest = [SnmpRow("1.3.6.1.2.1.4.21.1.1.0.0.0.0", "0.0.0.0", "IPADDR")]
    route_next = [SnmpRow("1.3.6.1.2.1.4.21.1.7.0.0.0.0", 12345, "INTEGER")]
    with pytest.raises(SnmpError, match=re.escape("1.3.6.1.2.1.4.21.1.7.0.0.0.0")):
        parse.parse_mgmt_ip(addr, [], route_dest, route_next, [], [])


def test_parse_mgmt_ip_malformed_base_mac_raises_snmp_error():
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.20", "10.1.5.20", "IPADDR")]
    base_mac = [
        SnmpRow(f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0", "not-six-bytes", "OCTETSTR")
    ]
    with pytest.raises(
        SnmpError, match=re.escape(f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0")
    ):
        parse.parse_mgmt_ip(addr, [], [], [], [], base_mac)


def test_parse_mgmt_ip_base_mac_from_ascii_colon_hex_string():
    # The M4300-24X (verified live) returns dot1dBaseBridgeAddress as a
    # 17-char ASCII string "8C:3B:AD:6B:BB:E0" rather than 6 raw bytes; it
    # must parse to the normalized upper-case MAC, not raise "malformed".
    addr = [SnmpRow("1.3.6.1.2.1.4.20.1.1.10.1.5.13", "10.1.5.13", "IPADDR")]
    base_mac = [
        SnmpRow(f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0", "8c:3b:ad:6b:bb:e0", "STRING")
    ]
    cfg = parse.parse_mgmt_ip(addr, [], [], [], [], base_mac)
    assert cfg.base_mac == "8C:3B:AD:6B:BB:E0"


def test_parse_base_mac_absent_is_none():
    assert parse.parse_base_mac([]) is None


def test_parse_base_mac_decodes_bytes_octetstring():
    rows = [
        SnmpRow(
            f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0",
            bytes([0xC8, 0x00, 0x84, 0x89, 0x71, 0x70]),
            "OCTETSTR",
        )
    ]
    assert parse.parse_base_mac(rows) == "C8:00:84:89:71:70"


def test_parse_base_mac_decodes_latin1_str_octetstring():
    # A transport that normalizes an OCTET STRING to latin-1 text (mirrors
    # the chassis-id / port-bitmap precedent elsewhere in this module).
    rows = [
        SnmpRow(
            f"{oids.DOT1D_BASE_BRIDGE_ADDRESS}.0",
            "".join(chr(b) for b in (0xC8, 0x00, 0x84, 0x89, 0x71, 0x70)),
            "OCTETSTR",
        )
    ]
    assert parse.parse_base_mac(rows) == "C8:00:84:89:71:70"
