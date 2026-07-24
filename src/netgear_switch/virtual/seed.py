"""Hand-authored ``VirtualSwitchState`` seeds, one builder per model.

``seed_gsm7252ps`` is the original, most exhaustively-documented seed: every
read op (Task 5-9) has at least one non-empty, non-vacuous example -- ports
with link/admin/speed, RX/TX counters on >=2 ports, >=1 VLAN with egress/
untagged bitmaps and PVIDs, PoE with a delivering port, fan/temperature/PSU
sensors (including a "Not Supported" fan slot), >=2 MAC/FDB entries with
their bridge-port->ifIndex mappings, >=1 LLDP neighbour, and a static
management IP. This makes the Task 16 SNMP<->SNMP equivalence test (and the
round-trip tests here) exercise real data on every parser, not an empty
table. Port 1 also carries an ifAlias description (ports 2+ deliberately
leave it unset) so the ifAlias column exercises both the present and
absent-instance paths. A sysDescr containing "GSM7252PS" plus a placeholder
sysObjectID (Task 2 model detection) round out the identity signals -- see
``VirtualSwitchState.sys_descr``/``sys_object_id``.

``seed_m4300_24x``/``seed_m4300_16x`` are transcribed directly from the
committed real-hardware captures (``tests/fixtures/captures/m4300-*.json``)
rather than hand-invented, so the M4300 pair's headline capability contrast
(24X has NO PoE, 16X has PoE on all 16 ports) is grounded, not guessed -- see
each function's docstring for exactly what is captured-real vs illustrative.
"""
from __future__ import annotations

from .state import (
    LldpSim,
    MacSim,
    MgmtSim,
    PoeSim,
    PortSim,
    SensorSim,
    VirtualSwitchState,
    VlanSim,
)

_POE_PORT_COUNT = 48
_TOTAL_PORT_COUNT = 52


def _port_name(port: int) -> str:
    # FASTPATH ifName is "1/0/<port>" for EVERY physical port -- including the
    # SFP+ uplinks 49-52. Verified against BOTH faces of the real gsm7252ps:
    # the SNMP capture (tests/fixtures/captures/gsm7252ps.json) and the web UI
    # (tests/fixtures/http/gsm7252ps_portsConfiguration.html) name port 49
    # "1/0/49", never "1/xg1". An earlier "1/xg<n>" scheme for the uplinks was
    # a fabrication that matched neither capture.
    return f"1/0/{port}"


# --- gsm7252ps, TRANSCRIBED from tests/fixtures/captures/gsm7252ps.json ---
# (a real SNMP capture of 10.1.5.22) and cross-checked against that same
# switch's HTTP captures in tests/fixtures/http/gsm7252ps_*.html.
#
# port -> (admin_enabled, link_up, speed_mbps, ifAlias description)
_GSM7252PS_PORTS = {
    1: (True, True, 1000, 'eth0.rpi5-pmod'),
    2: (True, True, 1000, 'eth0.rpi4-pmod'),
    3: (True, True, 1000, 'eth0.reterm2'),
    4: (True, True, 1000, 'eth0.rpi3b-gwifi'),
    5: (True, True, 1000, 'eth0.rpi4-usbdev'),
    6: (True, False, 0, None),
    7: (True, True, 1000, 'eth0.rpib-sdcard'),
    8: (True, False, 0, None),
    9: (True, True, 100, 'eth0.rpib-serial'),
    10: (True, False, 0, None),
    11: (True, True, 100, 'eth0.puck11'),
    12: (True, True, 1000, 'eth0.puck07'),
    13: (True, True, 1000, 'eth0.rpi5-433mhz'),
    14: (True, True, 1000, 'eth0.rpi-birds-welland-back'),
    15: (True, False, 0, None),
    16: (True, True, 1000, 'eth0.rpi-sdr-pluto'),
    17: (True, True, 1000, 'eth0.rpi5-zigbee'),
    18: (True, True, 1000, 'eth0.rpi4-asus-aspeed2050-dev'),
    19: (True, False, 0, None),
    20: (True, True, 1000, 'eth0.rpi4-hppdu-dev'),
    21: (True, False, 0, None),
    22: (True, True, 1000, 'eth0.rpi4-precursor'),
    23: (True, False, 0, None),
    24: (True, True, 1000, 'eth0.rpi4-gwifi'),
    25: (True, True, 1000, None),
    26: (True, True, 100, 'eth0.rpiz-3'),
    27: (True, True, 1000, 'eth0.rpi4-esp'),
    28: (True, False, 0, None),
    29: (True, False, 0, None),
    30: (True, True, 1000, 'eth0.rpi5-rfbridge'),
    31: (True, True, 1000, 'eth0.minnow-turbot-2'),
    32: (True, True, 1000, 'eth0.minnow-turbot-1'),
    33: (True, True, 1000, 'eth0.rpi4-kindle'),
    34: (True, False, 0, None),
    35: (True, False, 0, None),
    36: (True, False, 0, None),
    37: (True, True, 1000, 'eth0.rpi5-netv2'),
    38: (True, True, 1000, 'eth0.rpi3-netv2'),
    39: (True, False, 0, None),
    40: (True, False, 0, None),
    41: (True, True, 100, 'eth0.rpiz-serial'),
    42: (True, True, 1000, 'eth0.rpi-sdr-rtlsdr-v3'),
    43: (True, False, 0, 'end0.hifive-unmatched-1'),
    44: (True, False, 0, 'end0.hifive-unmatched-2'),
    45: (True, True, 100, 'wired.fritz-box-7270-1'),
    46: (True, True, 1000, 'eth0.puck12'),
    47: (True, True, 1000, 'p5.sw-poe-micro3'),
    48: (True, False, 0, 'spare.ex-cisco'),
    49: (True, True, 10000, '1/0/2.sw-netgear-m4300-24x'),
    50: (True, True, 10000, '1/0/49.sw-netgear-gsm7252ps-s2'),
    51: (True, True, 10000, '1/0/51.sw-netgear-gsm7252ps-s2'),
    52: (True, False, 10000, None),
}

# port -> (rx_octets, tx_octets, rx_packets, tx_packets, rx_errors, tx_errors)
_GSM7252PS_COUNTERS = {
    1: (45747246, 912689098, 217358, 235430, 0, 0),
    2: (43729612, 982042673, 227304, 287393, 0, 0),
    3: (309174274, 2763396970, 2703903, 2832210, 0, 0),
    4: (392406056, 1208220179, 455946, 362560, 0, 0),
    5: (45296975, 1784117938, 252396, 695269, 0, 0),
    6: (0, 0, 0, 0, 0, 0),
    7: (45478982, 1213479258, 243846, 319720, 0, 0),
    8: (0, 0, 0, 0, 0, 0),
    9: (43952641, 2474560700, 203437, 525017, 188, 0),
    10: (0, 0, 0, 0, 0, 0),
    11: (191245854, 2353135188, 504340, 779331, 0, 0),
    12: (242753298, 2405690445, 568614, 871728, 98, 0),
    13: (54822647, 1790957945, 314512, 686411, 0, 0),
    14: (1371471567, 2391786115, 5452154, 8842491, 0, 0),
    15: (0, 0, 0, 0, 0, 0),
    16: (458026172, 2161853643, 4479341, 7845883, 0, 0),
    17: (48254266, 1370034013, 247191, 559339, 0, 0),
    18: (107301127, 3428968332, 662009, 1912062, 0, 0),
    19: (0, 0, 0, 0, 0, 0),
    20: (48094973, 1600286182, 261316, 548326, 0, 0),
    21: (0, 0, 0, 0, 0, 0),
    22: (44983852, 1761230194, 274092, 651683, 0, 0),
    23: (0, 0, 0, 0, 0, 0),
    24: (60929816, 1662046751, 292512, 618541, 0, 0),
    25: (860424, 432228822, 5367, 11254, 0, 0),
    26: (42636836, 1207912561, 221448, 441634, 0, 0),
    27: (43106121, 1783468534, 249904, 681000, 0, 0),
    28: (0, 0, 0, 0, 0, 0),
    29: (0, 0, 0, 0, 0, 0),
    30: (46856497, 1781675389, 238217, 691884, 0, 0),
    31: (34224983, 1103571183, 191771, 227719, 0, 0),
    32: (36725195, 1103043544, 199490, 236217, 0, 0),
    33: (41767749, 1780610707, 235994, 676190, 0, 0),
    34: (0, 0, 0, 0, 0, 0),
    35: (0, 0, 0, 0, 0, 0),
    36: (0, 0, 0, 0, 0, 0),
    37: (61212753, 1383861442, 366925, 650250, 0, 0),
    38: (44488789, 1286245977, 339689, 516784, 0, 0),
    39: (0, 0, 0, 0, 0, 0),
    40: (0, 0, 0, 0, 0, 0),
    41: (47611153, 1597050827, 285613, 729735, 0, 0),
    42: (2121062532, 3300194902, 18659985, 20148348, 0, 0),
    43: (0, 0, 0, 0, 0, 0),
    44: (0, 0, 0, 0, 0, 0),
    45: (895931591, 720798804, 1283153, 515947, 1, 0),
    46: (215009366, 3079995766, 735039, 1206637, 111, 0),
    47: (20987280, 2708586643, 114946, 390277, 0, 0),
    48: (88601206, 3713706826, 1025558, 2517756, 0, 0),
    49: (28392074220, 9325801127, 77433287, 62142947, 0, 0),
    50: (278014432, 1694871324, 2069292, 2139039, 0, 0),
    51: (1075552286, 2278779253, 9235681, 9547144, 0, 0),
    52: (0, 0, 0, 0, 0, 0),
}

_GSM7252PS_PVIDS = {
    1: 90, 2: 90, 3: 90, 4: 90, 5: 90, 6: 1, 7: 90, 8: 1,
    9: 90, 10: 1, 11: 4, 12: 4, 13: 90, 14: 90, 15: 1, 16: 90,
    17: 90, 18: 90, 19: 1, 20: 90, 21: 1, 22: 90, 23: 90, 24: 90,
    25: 90, 26: 90, 27: 90, 28: 1, 29: 1, 30: 90, 31: 90, 32: 90,
    33: 90, 34: 1, 35: 1, 36: 1, 37: 90, 38: 90, 39: 1, 40: 1,
    41: 90, 42: 90, 43: 90, 44: 90, 45: 20, 46: 4, 47: 5, 48: 5,
    49: 1, 50: 1, 51: 1, 52: 1,
}

# vid -> (name, member ifIndexes, untagged ifIndexes) -- a LITERAL transcription
# of dot1qVlanStaticEgressPorts / dot1qVlanStaticUntaggedPorts from
# tests/fixtures/captures/gsm7252ps.json. Both the physical ports (1-52) and the
# aggregation ifIndexes (``*range(418, 482)`` = lag 1..lag 64) are taken exactly
# as the real switch reported them -- including the genuine hardware quirk that
# ``untagged`` is NOT a subset of ``member`` (e.g. VLAN 6 lists ports 1-45 as
# untagged though only 46/47/... are egress members) and that per-VLAN LAG
# membership varies (all 64 LAGs on VLAN 1, only lag 1-2 on VLAN 90). The web UI
# lists only the physical ports; the LAG ifIndexes are kept here so a renderer
# that forgets to drop them is caught (see test_web_projection).
_GSM7252PS_VLANS = {
    1: ('default', (6, 8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49,
        50, 51, 52, *range(418, 482)), (3, 4, 6, 7, 8, 10, 14, 15, 16, 18, 19, 20,
        21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 39, 40, 42, 49, 50,
        51, 52, *range(418, 482))),
    4: ('wifi', (11, 12, 46, 49, 50, 51), (11, 12, 46)),
    5: ('net', (3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22,
        24, 25, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 39, 40, 42, 46, 47, 48, 49,
        50, 51, 52, *range(418, 420)), (9, 45, 47, 48, *range(420, 482))),
    6: ('pwr', (46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52)),
    7: ('store', (), (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        *range(418, 482))),
    10: ('int', (9, 11, 12, 46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4, 5,
        6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52)),
    20: ('roam', (9, 11, 12, 45, 46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3,
        4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        48, 52)),
    21: ('fpgas', (), (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        *range(418, 482))),
    41: ('sm', (46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52)),
    89: ('sdr', (), (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        *range(418, 482))),
    90: ('iot', (1, 2, 3, 4, 5, 7, 9, 11, 12, 13, 14, 16, 17, 18, 20, 22, 23, 24,
        25, 26, 27, 30, 31, 32, 33, 37, 38, 41, 42, 43, 44, 46, 47, 49, 50, 51,
        *range(418, 420)), (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 43, 44, 45, 48, 52)),
    99: ('guest', (9, 11, 12, 46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4,
        5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48,
        52)),
    121: ('t-fpgas', (46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        48, 52)),
    141: ('t-sm', (46, 47, 49, 50, 51, *range(418, 420)), (1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48,
        52)),
}

# port -> (admin_enabled, RFC3621 detect code, delivered power mW)
_GSM7252PS_POE = {
    1: (True, 3, 3500),
    2: (True, 3, 2700),
    3: (True, 3, 3500),
    4: (True, 3, 9000),
    5: (True, 3, 5800),
    6: (True, 6, 0),  # otherFault: outside SNMP's 1-4 detect map -> UNKNOWN
    7: (True, 3, 3900),
    8: (True, 3, 1500),
    9: (True, 3, 3800),
    10: (True, 2, 0),
    11: (True, 3, 4100),
    12: (True, 3, 4700),
    13: (True, 3, 4600),
    14: (True, 3, 3800),
    15: (True, 2, 0),
    16: (True, 2, 0),
    17: (True, 3, 3400),
    18: (True, 3, 8500),
    19: (True, 2, 0),
    20: (True, 3, 6000),
    21: (True, 2, 0),
    22: (True, 3, 6000),
    23: (True, 2, 0),
    24: (True, 3, 7700),
    25: (True, 3, 3700),
    26: (True, 3, 1700),
    27: (True, 3, 7100),
    28: (True, 2, 0),
    29: (True, 2, 0),
    30: (True, 3, 4100),
    31: (True, 3, 3800),
    32: (True, 3, 3900),
    33: (True, 3, 5700),
    34: (True, 2, 0),
    35: (True, 2, 0),
    36: (True, 2, 0),
    37: (True, 3, 9400),
    38: (True, 3, 9900),
    39: (True, 2, 0),
    40: (True, 2, 0),
    41: (True, 3, 3200),
    42: (True, 3, 6900),
    43: (True, 2, 0),
    44: (True, 2, 0),
    45: (True, 2, 0),
    46: (True, 3, 4300),
    47: (True, 3, 1900),
    48: (True, 2, 0),
}


def seed_gsm7252ps() -> VirtualSwitchState:
    """Build a GSM7252PS (52-port, 48-PoE) state from the REAL capture.

    TRANSCRIBED, not invented, for everything the device's own captures show:
    per-port admin/link/speed/ifAlias, per-port counters, every PVID, all 14
    VLANs with their exact member/untagged ifIndex sets (physical ports AND the
    per-VLAN lag 1..lag 64 ifIndexes, including the genuine hardware quirk that
    ``untagged`` is not a subset of ``member``), all 48 PoE ports, the box
    sensors, the management IP (10.1.5.22), base MAC, serial and firmware --
    from ``tests/fixtures/captures/gsm7252ps.json`` (SNMP, host 10.1.5.22) plus
    that same switch's HTTP captures (``tests/fixtures/http/gsm7252ps_*.html``,
    the source of the serial/firmware/hostname and the ``http_sensors`` set).
    This is a strict transcription and is guarded as one -- see
    ``tests/virtual/test_state_seed.py::test_seed_gsm7252ps_matches_capture_strictly``,
    which runs it through the same ``capture_parity.assert_seed_matches_capture``
    helper the M4300 seeds use. It replaced an earlier HAND-INVENTED seed that
    contradicted the captures throughout (mgmt 10.1.5.20, 2 VLANs vs the real
    14, one PoE port delivering vs 30).

    TWO real sensor sets, one per interface (see ``sensors`` and
    ``http_sensors`` below): the SNMP walk returns fan RPM + PSU watts and NO
    temperature; the HTTP sysInfo page returns temperatures + fan/PSU HEALTH
    text. Both are transcribed from their respective captures, neither is forced
    onto the other face.

    Genuinely ILLUSTRATIVE (regression traps the capture cannot express, each
    documented where defined): the MAC/FDB entries and their bridge-port ->
    ifIndex join, the single LLDP neighbour, and ``mgmt.mode``/``gateway`` (the
    real capture reports mode "unknown" and no gateway route; the mock needs a
    definite DHCP-mode OID to serve and to flip on write).

    Non-physical interfaces are represented by two of the capture's 65
    (ifIndex 417 "CPU Interface" and 418 "lag 1") plus the per-VLAN LAG
    ifIndexes in VLAN membership, so a renderer/parser that forgets that the web
    UI lists ONLY physical ports is caught.
    """
    ports: dict[int, PortSim] = {}
    for port, (admin, link, speed, description) in _GSM7252PS_PORTS.items():
        rx_octets, tx_octets, rx_pkts, tx_pkts, rx_errs, tx_errs = (
            _GSM7252PS_COUNTERS[port]
        )
        ports[port] = PortSim(
            name=_port_name(port),
            admin=admin,
            link=link,
            speed=speed,
            rx_octets=rx_octets,
            tx_octets=tx_octets,
            rx_ucast=rx_pkts,
            tx_ucast=tx_pkts,
            rx_errors=rx_errs,
            tx_errors=tx_errs,
            description=description,
        )
    # Two of the capture's non-physical interfaces (it has 65: one CPU port
    # and 64 LAGs). They must never appear on a web-UI page. Both are
    # transcribed from the capture: the CPU port reports no speed/ifAlias; lag 1
    # is a 20 Gbit/s aggregation with a configured ifAlias.
    ports[417] = PortSim(name="CPU Interface:  0/5/1", admin=True, link=True, speed=0)
    ports[418] = PortSim(
        name="lag 1",
        admin=True,
        link=True,
        speed=20000,
        description="lag.sw-netgear-gsm7252ps-s2",
    )

    # member/untagged are already the EXACT captured ifIndex sets (physical
    # ports plus whichever lag 1..lag 64 ifIndexes each VLAN actually carries --
    # see _GSM7252PS_VLANS); nothing is added or dropped here.
    vlans = {
        vid: VlanSim(name=name, member=set(member), untagged=set(untagged))
        for vid, (name, member, untagged) in _GSM7252PS_VLANS.items()
    }

    pvids = dict(_GSM7252PS_PVIDS)

    poe = {
        port: PoeSim(admin=admin, detect=detect, power_mw=power_mw)
        for port, (admin, detect, power_mw) in _GSM7252PS_POE.items()
    }

    # SNMP box sensors -- a LITERAL transcription of the real walk in
    # tests/fixtures/captures/gsm7252ps.json: two fan RPMs (fan0, fan2 -- the
    # device has no fan1 OID) and four PSU wattages (power0..power3). This
    # interface reports NO temperature at all. Nothing here is invented; the
    # SNMP get_sensors output matches the capture value-for-value.
    sensors = [
        SensorSim(kind="fan", instance="0", raw="2850"),
        SensorSim(kind="fan", instance="2", raw="2350"),
        SensorSim(kind="power", instance="0", raw="49"),
        SensorSim(kind="power", instance="1", raw="30"),
        SensorSim(kind="power", instance="2", raw="32"),
        SensorSim(kind="power", instance="3", raw="31"),
    ]

    # HTTP sysInfo box sensors -- a SEPARATE, equally real sensor set that the
    # web UI exposes and SNMP does not (see tests/fixtures/http/
    # gsm7252ps_sysInfo.html). The two hardware interfaces genuinely surface
    # different sensors: sysInfo.html carries a Temperature Status table
    # (System/CPU/MAC-A/MAC-B degC; the MAC row reads N/A on this unit and the
    # parser skips it), a FAN Status table reporting fan HEALTH as OK/NA text
    # (never RPM), and a Device Status table with the RPS + Power Module
    # operational flags. Every value here is transcribed from that captured
    # page, not invented, and the labels are the page's own. Keeping this list
    # distinct from ``sensors`` is what lets each face render ITS OWN real
    # shape instead of forcing one interface's data onto the other.
    http_sensors = [
        SensorSim(kind="temperature", instance="System", raw="29"),
        SensorSim(kind="temperature", instance="CPU", raw="49"),
        SensorSim(kind="temperature", instance="MAC", raw="N/A"),
        SensorSim(kind="temperature", instance="MAC-A", raw="32"),
        SensorSim(kind="temperature", instance="MAC-B", raw="31"),
        SensorSim(kind="fan", instance="Fan1/PWR", raw="OK"),
        SensorSim(kind="fan", instance="Fan2/CPU", raw="OK"),
        SensorSim(kind="fan", instance="Fan3/SYS", raw="OK"),
        SensorSim(kind="fan", instance="Fan4", raw="NA"),
        SensorSim(kind="fan", instance="Fan5", raw="NA"),
        SensorSim(kind="power", instance="RPS", raw="Operational"),
        SensorSim(kind="power", instance="Power Module", raw="Operational"),
    ]

    macs = [
        MacSim(vlan=90, mac_bytes=(0xC8, 0x00, 0x84, 0x89, 0x71, 0x70), bridge_port=10),
        MacSim(vlan=1, mac_bytes=(0x00, 0x1B, 0x21, 0x3C, 0x4D, 0x5E), bridge_port=11),
    ]
    # bridge_port 10 deliberately maps to a DIFFERENT ifIndex (110, not 10) so
    # a regression that drops the dot1dBasePortIfIndex join (or falls back to
    # the bridge-port number itself) is detectable: get_macs() must surface
    # the mapped ifIndex 110, never the bridge port 10. bridge_port 11 stays
    # identity-mapped to prove the join also passes through unmapped/1:1 rows
    # unchanged.
    bridge_ports = {10: 110, 11: 11}

    lldp = [
        LldpSim(
            time_mark=75,
            local_port=49,
            rem_idx=7,
            chassis="".join(chr(b) for b in (0xC8, 0x00, 0x84, 0x89, 0x71, 0x70)),
            port_id="1/xg51",
            port_desc="eth0",
            sys_name="sw-cisco-shed",
        ),
    ]

    # address/netmask are the captured ones. mode/gateway are NOT: the real
    # capture reports mode "unknown" (the vendor DHCP-mode OID answered
    # nothing) and no gateway route, but the mock must serve a definite
    # writable DHCP-mode OID, so "static" + the subnet's router are the
    # structural stand-ins -- never a claim about the real device.
    mgmt = MgmtSim(
        address="10.1.5.22", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gsm7252ps",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,
        sensors=sensors,
        http_sensors=http_sensors,
        macs=macs,
        bridge_ports=bridge_ports,
        lldp=lldp,
        mgmt=mgmt,
        model_name="GSM7252PS",
        # serial/firmware/hostname are transcribed from the real sysInfo.html
        # capture of this switch (tests/fixtures/http/gsm7252ps_sysInfo.html).
        serial="2BW20A47000CC",
        firmware="10.0.0.53",
        hostname="sw-netgear-gsm7252ps-s1.welland.mithis.com",
        nsdp_mac=b"\xe0\x91\xf5\x0c\xd6\xdb",  # captured System MAC Address
        # Illustrative sysDescr text -- NOT a captured real firmware string;
        # its only requirement is containing the model name "GSM7252PS" so
        # detect_model_from_sysdescr's string matching has something real to
        # key off end-to-end. sys_object_id is a plausible-looking UNVERIFIED
        # virtual/test placeholder under the model's own 4526.10 vendor
        # subtree -- NOT a claim about the real device's sysObjectID (no
        # capture of the real value exists).
        sys_descr="NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6",
        sys_object_id="1.3.6.1.4.1.4526.10.100.14",
    )


def seed_gsm7228ps() -> VirtualSwitchState:
    """Build a MINIMAL-BUT-VALID GSM7228PS (S3300, 52-port/48-PoE Smart
    Managed Pro) virtual switch state.

    ``gsm7228ps`` is registered ``verified=True`` in ``registry.py`` for its
    SNMP+HTTP backends and port/PoE counts (52/48, matching the real product
    spec) -- but that registry fact is NOT a claim that any value seeded here
    is captured-real. Unlike ``seed_gsm7252ps`` (the codebase's original,
    most-exhaustively-worked illustrative seed) or the M4300 pair (literal
    capture transcriptions -- see their own docstrings), NO real-hardware
    capture exists for this model at all. This seed exists purely so
    ``VirtualSwitch("gsm7228ps")`` can serve every SNMP read op non-vacuously
    for testing, following the exact shape of ``seed_gsm7252ps`` (same real
    port/PoE counts) but with entirely illustrative/structural data -- same
    honesty convention as that function's own ``sys_object_id`` precedent:
    never a claim about a real GSM7228PS's actual configuration.
    """
    ports: dict[int, PortSim] = {}
    for port in range(1, _TOTAL_PORT_COUNT + 1):
        sim = PortSim(
            name=_port_name(port),
            admin=True,
            link=port != 3,  # port 3 is admin-up but link-down
            speed=1000,
        )
        if port in (1, 2):
            sim.rx_octets = 500_000
            sim.tx_octets = 700_000
            sim.rx_ucast = 4_000
            sim.tx_ucast = 4_500
            sim.rx_errors = 0
            sim.tx_errors = 0
        if port == 1:
            sim.description = "uplink-to-core"  # port 2+ left None: absent ifAlias
        ports[port] = sim

    vlans = {
        1: VlanSim(
            name="default",
            member=set(range(1, _TOTAL_PORT_COUNT + 1)),
            untagged=set(range(3, _TOTAL_PORT_COUNT + 1)),
        ),
        50: VlanSim(name="lab", member={1, 2, 5}, untagged={1, 2}),
    }

    pvids = dict.fromkeys(range(1, _TOTAL_PORT_COUNT + 1), 1)
    pvids[1] = 50
    pvids[2] = 50

    poe: dict[int, PoeSim] = {}
    for port in range(1, _POE_PORT_COUNT + 1):
        if port == 1:
            poe[port] = PoeSim(admin=True, detect=3, power_mw=9_000)
        else:
            poe[port] = PoeSim(admin=True, detect=1, power_mw=0)

    sensors = [
        SensorSim(kind="fan", instance="0", raw="3200"),
        SensorSim(kind="power", instance="0", raw="45"),
        SensorSim(kind="temperature", instance="0", raw="40"),
    ]

    macs = [
        MacSim(vlan=50, mac_bytes=(0x00, 0x11, 0x22, 0x33, 0x44, 0x55), bridge_port=1),
        MacSim(vlan=1, mac_bytes=(0x00, 0x11, 0x22, 0x33, 0x44, 0x56), bridge_port=2),
    ]

    lldp = [
        LldpSim(
            time_mark=1,
            local_port=1,
            rem_idx=1,
            chassis="".join(chr(b) for b in (0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            port_id="eth0",
            port_desc="lab-uplink",
            sys_name="sw-lab-example",
        ),
    ]

    mgmt = MgmtSim(
        address="10.1.5.21", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gsm7228ps",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        mgmt=mgmt,
        # Illustrative sysDescr/sysObjectID -- same honesty convention as
        # seed_gsm7252ps: sysDescr just needs to contain the real model name;
        # sysObjectID is a plausible-looking UNVERIFIED placeholder under this
        # model's own 4526.11 (Smart Managed Pro) vendor subtree, never a
        # claim about real hardware (no capture exists to confirm either).
        sys_descr="NETGEAR GSM7228PS (S3300) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.11.100.28",
    )


def seed_gs110emx() -> VirtualSwitchState:
    """Build a GS110EMX (10-port Plus, NSDP+HTTP) state from the REAL capture.

    Identity, mgmt-IP and per-port link/speed/description are transcribed from
    this model's OWN committed captures (``tests/fixtures/http/
    gs110emx_{sysinfo,port_settings,interface_stats}.html``, host 10.1.5.25):
    ports 6/8/9/10 up at 100M/1G/10G/10G with port 8 described "rumpus", the
    rest down; static 10.1.5.25/24 via 10.1.5.1; MAC bc:a5:11:b8:ec:f1.

    Previously these were hand-invented values (hostname "plus-sw", 10.1.5.20,
    the default MAC, 1M/2M counters on idle ports, all-untagged VLAN 1, PVIDs
    90) that CONTRADICTED this model's own captures while tests pinned them as
    if true. Now transcribed: identity, mgmt-IP, port link/speed/description,
    per-port counters, VLAN 1 membership and every PVID.

    STILL ILLUSTRATIVE (no capture exists, and this says so rather than
    implying otherwise): VLAN 90's member/untagged sets -- only VLAN 1's
    membership page was captured -- and the QoS/mirroring/IGMP/broadcast/
    loop-detection tag values further down, which are test fixtures chosen so
    nsdp_device() has something non-vacuous to decode on every parsed tag.
    """
    real_speed = {6: 100, 8: 1000, 9: 10000, 10: 10000}
    # Counters transcribed from gs110emx_interface_stats.html: traffic is on
    # 6/8/9/10; ports 1-5 and 7 really are all zeros. (An earlier seed put
    # 1M/2M on ports 1-2, contradicting that same capture.)
    real_octets = {
        6: (0, 70_892_018_242),
        8: (59_921_732_691, 78_637_274_870),
        9: (2_963_140_428_936, 1_189_358_575_871),
        10: (1_195_417_274_187, 3_027_396_511_187),
    }
    ports: dict[int, PortSim] = {}
    for port in range(1, 11):
        sim = PortSim(
            name=f"g{port}",
            admin=True,
            link=port in real_speed,
            speed=real_speed.get(port, 0),
            description="rumpus" if port == 8 else None,
        )
        sim.rx_octets, sim.tx_octets = real_octets.get(port, (0, 0))
        sim.rx_errors = 0
        ports[port] = sim

    # VLAN 1 membership is TRANSCRIBED from gs110emx_vlanmembership.html
    # (hiddenMem "1111111122" = ports 1-8 untagged, 9-10 tagged). VLAN 90 is
    # one of the 12 VLAN IDs the real Cf8021q capture lists, but its MEMBERSHIP
    # was never captured (only VLAN 1's page was), so the member/untagged sets
    # for it are ILLUSTRATIVE, not observed.
    vlans = {
        1: VlanSim(name="", member=set(range(1, 11)), untagged=set(range(1, 9))),
        90: VlanSim(name="", member={1, 2, 10}, untagged={1, 2}),
    }
    # Transcribed from gs110emx_pvid.html: every port is PVID 1 on this unit.
    pvids = dict.fromkeys(range(1, 11), 1)

    mgmt = MgmtSim(
        address="10.1.5.25", netmask="255.255.255.0", gateway="10.1.5.1", mode="static"
    )

    return VirtualSwitchState(
        model_key="gs110emx",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        mgmt=mgmt,
        model_name="GS110EMX",
        serial="53H60253A0032",
        firmware="1.0.1.4",
        hostname="sw-netgear-gs110emx1",
        nsdp_mac=b"\xbc\xa5\x11\xb8\xec\xf1",
        nsdp_password="password",
        # QoS/mirroring/IGMP/broadcast-filtering/loop-detection test fixtures
        # (Slice 9b): illustrative, non-vacuous values so nsdp_device() has
        # something real to decode on every one of the 5 newly-parsed tags.
        nsdp_qos_engine=1,  # port-based
        nsdp_port_mirroring_dest=10,
        nsdp_port_mirroring_sources=frozenset({1, 2}),
        nsdp_igmp_snooping_enabled=True,
        nsdp_igmp_snooping_vlan=90,
        nsdp_broadcast_filtering=True,
        nsdp_loop_detection=True,
    )


def seed_gs305ep() -> VirtualSwitchState:
    """Build an ILLUSTRATIVE GS305EP (5-port, PoE ports 1-4) virtual state.

    HAND-INVENTED: no capture of any kind exists for gs305ep. The port speeds,
    the 12800 mW PoE reading, VLAN 90 and the PVIDs are all structural test
    data, NOT observed values -- same convention as ``seed_gsm7228ps``, which
    says so explicitly. Only the shape is grounded: the Plus family genuinely
    has no MAC/FDB, no box sensors and no LLDP over its web UI.
    """
    ports = {
        p: PortSim(
            name=f"Port {p}", admin=p != 3, link=p == 1, speed=1000 if p == 1 else 0
        )
        for p in range(1, 6)
    }
    ports[1].rx_octets = 1_000_000
    ports[1].tx_octets = 2_000_000
    ports[1].rx_errors = 0
    vlans = {
        1: VlanSim(name="default", member={1, 2, 3, 4, 5}, untagged={3, 4, 5}),
        90: VlanSim(name="iot", member={1, 2}, untagged={1, 2}),
    }
    pvids = {1: 90, 2: 90, 3: 1, 4: 1, 5: 1}
    poe = {
        1: PoeSim(admin=True, detect=3, power_mw=12_800),
        2: PoeSim(admin=True, detect=1, power_mw=0),
        3: PoeSim(admin=True, detect=1, power_mw=0),
        4: PoeSim(admin=False, detect=1, power_mw=0),
    }
    return VirtualSwitchState(
        model_key="gs305ep", ports=ports, vlans=vlans, pvids=pvids, poe=poe
    )


def seed_gs105pe() -> VirtualSwitchState:
    """Build a GS105PE (5-port Plus, NSDP+HTTP) virtual state from a REAL live
    capture (host 10.1.5.30 / poe-micro3, 2026-07-21 -- see
    netgear-m4300-http-cheetah / the gs105pe live findings). Every value below
    is transcribed from the captured NsdpDevice: ports 3 (100M) and 5 (1G) up,
    the rest down; VLANs 1/41/90 with their real member/untagged sets; real
    PVIDs; DHCP mgmt-IP; and the QoS/mirroring/IGMP engine tags. Port mirroring
    is OFF on this unit (dest 0, no sources) -- the 3-byte PORT_MIRRORING TLV
    that exposed the fixed-width parser bug (see parse_port_mirroring)."""
    ports = {
        p: PortSim(
            name=f"Port {p}",
            admin=True,
            link=p in (3, 5),
            speed={3: 100, 5: 1000}.get(p, 0),
        )
        for p in range(1, 6)
    }
    ports[3].tx_octets = 10_246_512
    ports[5].rx_octets = 29_303_468
    ports[5].tx_octets = 289_149
    ports[5].rx_errors = 228_666
    vlans = {
        1: VlanSim(name="", member={5}, untagged={5}),
        41: VlanSim(name="", member={1, 2, 4, 5}, untagged={1, 2, 4}),
        90: VlanSim(name="", member={3, 5}, untagged={3}),
    }
    pvids = {1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
    return VirtualSwitchState(
        model_key="gs105pe",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        mgmt=MgmtSim(
            address="10.1.5.30",
            netmask="255.255.255.0",
            gateway="10.1.5.1",
            mode="dhcp",
        ),
        model_name="GS105PE",
        serial="61W19753A00A8",
        firmware="V1.6.0.4",
        hostname="poe-micro3",
        nsdp_mac=b"\x38\x94\xed\xb7\xcd\xe0",
        nsdp_password="password",
        nsdp_qos_engine=2,
        nsdp_port_mirroring_dest=0,
        nsdp_port_mirroring_sources=frozenset(),
        nsdp_igmp_snooping_enabled=True,
        nsdp_igmp_snooping_vlan=1,
        nsdp_broadcast_filtering=False,
        nsdp_loop_detection=False,
    )


def _mac_hex_to_raw(hexstr: str) -> str:
    """``"88:A2:9E:80:87:01"`` -> the 6 raw latin-1 bytes it represents.

    The real-hardware captures (``tests/fixtures/captures/*.json``) store
    already-PARSED values (e.g. ``MacEntry.mac``/``LLDPNeighbor.remote_chassis_id``
    are colon-hex text), not the raw wire bytes. Seeding ``oid_map()`` needs
    the raw bytes back (a MAC-address chassis/port-id subtype is genuinely
    binary on the wire -- see ``parse._format_chassis_id``/``_format_port_id``),
    so this is the exact inverse of that formatting.
    """
    return "".join(chr(int(p, 16)) for p in hexstr.split(":"))


# M4300-24X (28 registered ports, 0 PoE -- Fully Managed, SNMP-only): every
# value below is transcribed directly from the real captured snapshot
# (tests/fixtures/captures/m4300-24x.json, host 10.1.5.13) -- port
# name/admin/link/speed/description/counters, VLANs (all 14, full real
# member/untagged sets), PVIDs, sensors, and the base MAC. The real switch
# exposes 155 ifIndexes (24 physical + a CPU interface + 128 LAG placeholders
# + 2 VLAN interfaces); only a representative slice of the non-physical ones
# is seeded (the one real in-use LAG plus one unused placeholder, the CPU
# interface, and both VLAN interfaces) rather than all 128 mostly-identical
# unused LAGs -- the model's CAPABILITIES (port count/names/speeds, VLANs,
# PVIDs, sensors, mgmt-IP, and CRUCIALLY the absence of PoE) match the
# capture exactly. dot1dBaseBridgeAddress is VERIFIED to come back as ASCII
# colon-hex text on this exact model (see ``_mac_from_ascii_text``), so
# ``dot1d_base_mac_ascii=True`` here specifically -- NOT on m4300-16x below,
# where no such quirk has been captured.
def seed_m4300_24x() -> VirtualSwitchState:
    """Build a realistic M4300-24X (24-port, non-PoE) virtual switch state."""
    _phys = (  # port, name, admin, link, speed_mbps(0=down), description
        (1, "1/0/1", True, True, 10000, "trunk.sw-cisco-shed"),
        (2, "1/0/2", True, True, 10000, "trunk.gsm7252ps-s1"),
        (3, "1/0/3", True, True, 1000, "bmc.big-storage"),
        (4, "1/0/4", True, False, 0, "bmc.gpu"),
        (5, "1/0/5", True, True, 100, "openmesh.wifi"),
        (6, "1/0/6", True, True, 1000, "eth0.rpi4-ups"),
        (7, "1/0/7", True, False, 0, "empty"),
        (8, "1/0/8", True, False, 0, "empty"),
        (9, "1/0/9", True, True, 1000, "oob1.sw-bb-25g"),
        (10, "1/0/10", True, True, 1000, "oob2.sw-bb-25g"),
        (11, "1/0/11", True, False, 0, "oob1.sw-bb-100g"),
        (12, "1/0/12", True, False, 0, "oob2.sw-bb-100g"),
        (13, "1/0/13", True, False, 0, "bmc1.nvmeof"),
        (14, "1/0/14", True, False, 0, "bmc2.nvmeof"),
        (15, "1/0/15", True, False, 0, "empty"),
        (16, "1/0/16", True, False, 0, "empty"),
        (17, "1/0/17", True, False, 0, "10g1.gpu"),
        (18, "1/0/18", True, False, 0, "10g2.gpu"),
        (19, "1/0/19", True, True, 10000, "10g1.big-storage"),
        (20, "1/0/20", True, True, 10000, "10g2.big-storage"),
        (21, "1/0/21", True, True, 10000, "lag.sw-bb-25g"),
        (22, "1/0/22", True, True, 10000, "lag.sw-bb-25g"),
        (23, "1/0/23", True, True, 10000, "lag.sw-bb-25g"),
        (24, "1/0/24", True, True, 10000, "lag.sw-bb-25g"),
    )
    # (port, rx_bytes, tx_bytes, rx_errors) -- real captured ifHCIn/OutOctets
    # + ifInErrors; tx_errors is 0 for every port on this capture.
    _stats = {
        1: (14778916968081, 11768639639224, 5),
        2: (22592906553, 72917119482, 0),
        3: (2762192715, 3069701383, 0),
        4: (0, 0, 0),
        5: (9928397370, 103562789705, 0),
        6: (2936543951, 6369912656, 0),
        7: (0, 0, 0),
        8: (0, 0, 0),
        9: (241280077, 1045875073, 0),
        10: (79644425, 1532447568, 0),
        11: (0, 0, 0),
        12: (0, 0, 0),
        13: (0, 4321, 0),
        14: (0, 4385, 0),
        15: (0, 0, 0),
        16: (0, 0, 0),
        17: (0, 0, 0),
        18: (0, 0, 0),
        19: (10574049492450, 7436979985884, 0),
        20: (906023695499, 3169248684569, 0),
        21: (46742037001, 214440657859, 0),
        22: (62196040279, 2295667872290, 0),
        23: (53538213549, 4490316365, 0),
        24: (60910004579, 1478343156644, 0),
    }
    ports: dict[int, PortSim] = {}
    for port, name, admin, link, speed, desc in _phys:
        rx_bytes, tx_bytes, rx_errors = _stats[port]
        ports[port] = PortSim(
            name=name, admin=admin, link=link, speed=speed, description=desc,
            rx_octets=rx_bytes, tx_octets=tx_bytes, rx_errors=rx_errors,
            tx_errors=0,
        )
    # Representative non-physical ifIndexes (see module docstring above):
    # the CPU interface, one real in-use LAG + one unused placeholder LAG,
    # and the switch's two VLAN interfaces.
    ports[769] = PortSim(name="CPU Interface:  0/15/1", admin=True, link=True, speed=0)
    ports[770] = PortSim(
        name="lag 1", admin=True, link=True, speed=40000, description="lag.sw-bb-25g"
    )
    ports[771] = PortSim(name="lag 2", admin=True, link=False, speed=0)
    ports[898] = PortSim(name="vlan 1", admin=True, link=True, speed=10)
    ports[899] = PortSim(name="vlan 5", admin=True, link=True, speed=10)

    # All 14 real VLANs, full real member/untagged port sets (including the
    # 128-wide LAG range 770-897 every VLAN's trunk carries) -- `tagged` is
    # always `member - untagged` (see VirtualSwitchState.nsdp_tlvs), matching
    # the capture's own tagged_ports for every VLAN checked.
    _lags = set(range(770, 898))  # lag 1..128 -> ifIndex 770..897
    vlans = {
        1: VlanSim(
            name="default",
            member={1, 2, 5, 7, 8} | _lags,
            untagged={1, 2, 7, 8} | _lags,
        ),
        4: VlanSim(name="wifi", member={1, 2, 770}, untagged=set()),
        5: VlanSim(
            name="net",
            member={1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 770},
            untagged={3, 4, 5, 9, 10, 11, 12, 13, 14},
        ),
        6: VlanSim(name="pwr", member={1, 2, 5, 770}, untagged=set()),
        7: VlanSim(name="store", member={1, 2, 5, 770}, untagged=set()),
        10: VlanSim(
            name="int",
            member={1, 2, 5, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 770},
            untagged={15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
        ),
        20: VlanSim(name="roam", member={1, 2, 5, 770}, untagged=set()),
        21: VlanSim(name="fpgas", member={1, 2, 770}, untagged=set()),
        41: VlanSim(name="sm", member={1, 2, 5, 770}, untagged=set()),
        89: VlanSim(name="sdr", member={1, 2, 770}, untagged=set()),
        90: VlanSim(name="iot", member={1, 2, 5, 6, 770}, untagged={6}),
        99: VlanSim(name="guest", member={1, 2, 5, 770}, untagged=set()),
        121: VlanSim(name="t-fpgas", member={1, 2, 5, 770}, untagged=set()),
        141: VlanSim(name="t-sm", member={1, 2, 5, 770}, untagged=set()),
    }
    pvids = {
        1: 1, 2: 1, 3: 5, 4: 5, 5: 5, 6: 90, 7: 1, 8: 1, 9: 5, 10: 5,
        11: 5, 12: 5, 13: 5, 14: 5, 15: 10, 16: 10, 17: 10, 18: 10, 19: 10,
        20: 10, 21: 10, 22: 10, 23: 10, 24: 10,
    }
    sensors = [
        SensorSim(kind="fan", instance="0", raw="5160"),
        SensorSim(kind="fan", instance="1", raw="4560"),
        SensorSim(kind="power", instance="0", raw="49"),
        SensorSim(kind="temperature", instance="1", raw="49"),
    ]
    # A representative slice of the real (30-capped) captured MAC/FDB table,
    # identity-mapped bridge-port -> ifIndex (see gsm7252ps's seed for the
    # non-identity-mapping case; that path is already covered there).
    macs = [
        MacSim(vlan=1, mac_bytes=(0x00, 0x0A, 0xFA, 0x24, 0x28, 0x20), bridge_port=1),
        MacSim(vlan=90, mac_bytes=(0x00, 0xE0, 0x4C, 0x68, 0x36, 0x95), bridge_port=1),
        MacSim(vlan=1, mac_bytes=(0x02, 0x00, 0x0A, 0x01, 0x00, 0x01), bridge_port=1),
    ]
    # Real LLDP neighbours (a representative few of the capture's list): mixed
    # MAC-shaped (raw-bytes) and plain-text port-id subtypes on purpose, so
    # both `_format_port_id` branches round-trip through the mock.
    lldp = [
        LldpSim(
            time_mark=1, local_port=1, rem_idx=1,
            chassis=_mac_hex_to_raw("88:A2:9E:80:87:01"),
            port_id=_mac_hex_to_raw("88:A2:9E:80:87:01"),
            port_desc="eth0", sys_name="rpi-sdr-kraken",
        ),
        LldpSim(
            time_mark=1, local_port=2, rem_idx=1,
            chassis=_mac_hex_to_raw("E0:91:F5:0C:D6:DB"),
            port_id="1/0/49",  # plain interface name, NOT a MAC -- text subtype
            port_desc="1/0/2.sw-netgear-m4300-24x",
            sys_name="sw-netgear-gsm7252ps-s1.welland.mithis.com",
        ),
        LldpSim(
            time_mark=1, local_port=6, rem_idx=1,
            chassis=_mac_hex_to_raw("E4:5F:01:8D:F4:FD"),
            port_id=_mac_hex_to_raw("E4:5F:01:8D:F4:FD"),
            port_desc="eth0", sys_name="rpi4-ups",
        ),
    ]
    mgmt = MgmtSim(
        address="10.1.5.13", netmask="255.255.255.0", gateway="10.1.5.1",
        # Real capture reports mode="unknown" (the UNVERIFIED DHCP-mode OID
        # -- see VendorOids.dhcp_mode_unverified); "static" is the honest,
        # documented best inference for a device with a real static address,
        # not itself a captured value.
        mode="static",
    )
    return VirtualSwitchState(
        model_key="m4300-24x",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe={},  # VERIFIED: real capture's poe=[] -- this model has NO PoE.
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        mgmt=mgmt,
        # Real captured base MAC (mgmt_ip.base_mac in the capture).
        nsdp_mac=bytes.fromhex("8C3BAD6BBBE0"),
        # VERIFIED on this exact model (see field docstring + parse.py's
        # _mac_from_ascii_text): dot1dBaseBridgeAddress comes back as ASCII
        # colon-hex text on the real M4300-24X, not raw OCTET STRING bytes.
        dot1d_base_mac_ascii=True,
        # Illustrative sysDescr/sysObjectID (Task 2 model detection) -- same
        # honesty convention as seed_gsm7252ps: sysDescr just needs to
        # contain the real model name; sysObjectID has no known real value
        # (no OID->model table exists) so this is a placeholder under the
        # model's own vendor subtree, never a claim about real hardware.
        sys_descr="NETGEAR M4300-24X (XSM4324CS) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.10.100.24",
    )


# M4300-16X (16 registered ports, all 16 PoE -- Fully Managed, SNMP-only):
# same transcription approach as seed_m4300_24x, from
# tests/fixtures/captures/m4300-16x.json (host unrecorded in that capture).
# The real capture's mgmt_ip.address is None (no static IP was ever
# discovered over this OID chain on that device) -- honestly left unseeded
# (the default blank 0.0.0.0/dhcp MgmtSim) rather than inventing one; the
# real captured base MAC is kept, so get_mgmt_ip().base_mac is still real.
# dot1d_base_mac_ascii is NOT set here: only the M4300-24X's ASCII-text quirk
# has been captured/verified (see seed_m4300_24x and parse.py's
# _mac_from_ascii_text docstring) -- this model uses the standard raw-bytes
# encoding.
def seed_m4300_16x() -> VirtualSwitchState:
    """Build a realistic M4300-16X (16-port, all-16 PoE) virtual switch state."""
    _phys = (  # port, name, admin, link, speed_mbps(0=down)
        (1, "1/0/1", True, False, 0),
        (2, "1/0/2", True, False, 0),
        (3, "1/0/3", True, False, 0),
        (4, "1/0/4", True, False, 0),
        (5, "1/0/5", True, False, 0),
        (6, "1/0/6", True, False, 0),
        (7, "1/0/7", True, False, 0),
        (8, "1/0/8", True, False, 0),
        (9, "1/0/9", True, False, 0),
        (10, "1/0/10", True, False, 0),
        (11, "1/0/11", True, True, 1000),
        (12, "1/0/12", True, True, 1000),
        (13, "1/0/13", True, False, 0),
        (14, "1/0/14", True, False, 0),
        (15, "1/0/15", True, False, 0),
        (16, "1/0/16", True, True, 10000),
    )
    # (port, rx_bytes, tx_bytes) -- real captured ifHCIn/OutOctets; every
    # port's ifInErrors/ifOutErrors is 0 on this capture.
    _stats = {
        1: (0, 0), 2: (0, 0), 3: (0, 0), 4: (0, 0), 5: (0, 0), 6: (0, 0),
        7: (0, 0), 8: (0, 0), 9: (0, 0), 10: (0, 0),
        11: (0, 7813924), 12: (30388, 7819868), 13: (0, 0), 14: (0, 0),
        15: (0, 0), 16: (3347925876, 7868391),
    }
    ports: dict[int, PortSim] = {}
    for port, name, admin, link, speed in _phys:
        rx_bytes, tx_bytes = _stats[port]
        ports[port] = PortSim(
            name=name, admin=admin, link=link, speed=speed,
            rx_octets=rx_bytes, tx_octets=tx_bytes, rx_errors=0, tx_errors=0,
        )
    ports[769] = PortSim(name="CPU Interface:  0/15/1", admin=True, link=True, speed=0)
    ports[770] = PortSim(name="lag 1", admin=True, link=False, speed=0)
    ports[898] = PortSim(name="vlan 5", admin=True, link=True, speed=10)

    _lags = set(range(770, 898))
    _uplink_ports = {9, 10, 11, 12, 13, 14, 15, 16}
    vlans = {
        1: VlanSim(
            name="default",
            member=set(range(1, 17)) | _lags,
            untagged=set(range(1, 17)) | _lags,
        ),
        4: VlanSim(name="wifi", member=set(_uplink_ports), untagged=set()),
        5: VlanSim(name="net", member=set(_uplink_ports), untagged=set()),
        6: VlanSim(name="pwr", member=set(_uplink_ports), untagged=set()),
        7: VlanSim(name="store", member=set(_uplink_ports), untagged=set()),
        10: VlanSim(name="int", member=set(_uplink_ports), untagged=set()),
        20: VlanSim(name="roam", member=set(_uplink_ports), untagged=set()),
        21: VlanSim(name="fpgas", member=set(_uplink_ports), untagged=set()),
        41: VlanSim(name="sm", member=set(_uplink_ports), untagged=set()),
        89: VlanSim(name="sdr", member=set(_uplink_ports), untagged=set()),
        90: VlanSim(name="iot", member=set(_uplink_ports), untagged=set()),
        99: VlanSim(name="guest", member=set(_uplink_ports), untagged=set()),
        121: VlanSim(name="t-fpgas", member=set(_uplink_ports), untagged=set()),
        141: VlanSim(name="t-sm", member=set(_uplink_ports), untagged=set()),
    }
    pvids = dict.fromkeys(range(1, 17), 1)
    poe = {
        1: PoeSim(admin=True, detect=2, power_mw=0),
        2: PoeSim(admin=True, detect=2, power_mw=0),
        3: PoeSim(admin=True, detect=2, power_mw=0),
        4: PoeSim(admin=True, detect=2, power_mw=0),
        5: PoeSim(admin=True, detect=2, power_mw=0),
        6: PoeSim(admin=True, detect=2, power_mw=0),
        7: PoeSim(admin=True, detect=2, power_mw=0),
        8: PoeSim(admin=True, detect=2, power_mw=0),
        9: PoeSim(admin=True, detect=2, power_mw=0),
        10: PoeSim(admin=True, detect=2, power_mw=0),
        11: PoeSim(admin=True, detect=3, power_mw=5000),  # delivering
        12: PoeSim(admin=True, detect=3, power_mw=2100),  # delivering
        13: PoeSim(admin=True, detect=2, power_mw=0),
        14: PoeSim(admin=True, detect=2, power_mw=0),
        15: PoeSim(admin=True, detect=2, power_mw=0),
        16: PoeSim(admin=True, detect=2, power_mw=0),
    }
    sensors = [
        SensorSim(kind="fan", instance="0", raw="4200"),
        SensorSim(kind="fan", instance="1", raw="4080"),
        SensorSim(kind="power", instance="0", raw="40"),
        SensorSim(kind="power", instance="1", raw="42"),
        SensorSim(kind="temperature", instance="1", raw="42"),
    ]
    macs = [
        MacSim(vlan=1, mac_bytes=(0x80, 0xCC, 0x9C, 0x91, 0x4F, 0x8C), bridge_port=12),
        MacSim(vlan=90, mac_bytes=(0x00, 0x08, 0xA2, 0x09, 0xEF, 0xED), bridge_port=16),
        MacSim(vlan=1, mac_bytes=(0x00, 0x0A, 0xFA, 0x24, 0x28, 0x1F), bridge_port=16),
    ]
    lldp = [
        LldpSim(
            time_mark=1, local_port=12, rem_idx=1,
            chassis=_mac_hex_to_raw("80:CC:9C:91:4F:8C"),
            port_id="5",  # plain numeric device-port label, NOT a MAC
            port_desc="Device Port 5", sys_name="sw-poe-micro2",
        ),
        LldpSim(
            time_mark=1, local_port=16, rem_idx=1,
            chassis=_mac_hex_to_raw("00:0A:FA:24:28:25"),
            port_id=_mac_hex_to_raw("00:0A:FA:24:28:1F"),
            port_desc="eth8", sys_name="ten64.welland.mithis.com",
        ),
    ]
    return VirtualSwitchState(
        model_key="m4300-16x",
        ports=ports,
        vlans=vlans,
        pvids=pvids,
        poe=poe,  # VERIFIED: real capture -- all 16 ports PoE-capable.
        sensors=sensors,
        macs=macs,
        lldp=lldp,
        # mgmt left at the default blank MgmtSim -- honest: the real capture's
        # mgmt_ip.address was None (see module docstring above).
        nsdp_mac=bytes.fromhex("8C3BAD691C38"),  # real captured base MAC
        sys_descr="NETGEAR M4300-16X (XSM4316) Managed Switch",
        sys_object_id="1.3.6.1.4.1.4526.10.100.16",
    )
