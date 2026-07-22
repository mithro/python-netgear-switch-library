from __future__ import annotations

from pathlib import Path

import pytest

from netgear_switch.errors import HttpUnexpectedPageError
from netgear_switch.models import IpMode, PoEDetect, VlanMode
from netgear_switch.protocols.http import parse

_FIX = Path(__file__).parent.parent.parent / "fixtures" / "http"


def _read(name: str) -> str:
    return (_FIX / name).read_text()


def test_parse_login_rand_and_hash() -> None:
    html = _read("gs305ep_login.html")
    assert parse.parse_login_rand(html) == "9917"
    assert parse.parse_csrf_hash(html) == "abc123def"
    assert parse.parse_login_rand("<html>no rand here</html>") is None


# --- GS110EMX: all tests below are grounded in a LIVE CAPTURE from a ---
# --- physical GS110EMX (tests/fixtures/http/gs110emx_*.html), not a  ---
# --- synthetic fixture -- see endpoints.py's _GS110EMX docstring.   ---

_GAMBIT_TOKEN = (
    "dhrelggkcbjfjgcfnbcfeekfbajfkejgpfkehbnfgbbaigdaggifhedafagfjehbdfljdbhk"
    "dgcahblfgbgalehadftkkjegeaje"
)


def test_parse_login_rand_gs110emx() -> None:
    # GET / -- the login page's <input id='rand' value="..." disabled>.
    assert parse.parse_login_rand(_read("gs110emx_login.html")) == "1172334327"


def test_parse_gambit_token() -> None:
    # POST /redirect.html response: the auto-submit form's Gambit token.
    assert parse.parse_gambit_token(_read("gs110emx_redirect.html")) == _GAMBIT_TOKEN
    # sysInfo.html/interface_stats.html also carry the same Gambit field.
    assert parse.parse_gambit_token(_read("gs110emx_sysinfo.html")) == _GAMBIT_TOKEN


def test_parse_gambit_token_absent_or_empty() -> None:
    assert parse.parse_gambit_token("<html>no token here</html>") is None
    assert (
        parse.parse_gambit_token('<input type="hidden" name="Gambit" value="">')
        == ""
    )


def test_parse_sysinfo_gs110emx() -> None:
    info = parse.parse_sysinfo(_read("gs110emx_sysinfo.html"))
    assert info.product_name == "GS110EMX"
    assert info.switch_name == "sw-netgear-gs110emx1"
    assert info.serial_number == "53H60253A0032"
    assert info.mac_address == "bc:a5:11:b8:ec:f1"
    assert info.firmware_version == "1.0.1.4"
    assert info.ip_mode is IpMode.STATIC  # data-select-value="0" -> Disable/static
    assert info.ip_address == "10.1.5.25"
    assert info.subnet_mask == "255.255.255.0"
    assert info.gateway_address == "10.1.5.1"


def test_parse_sysinfo_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_sysinfo("<html><body>Not Found</body></html>")


def test_parse_interface_stats_gs110emx() -> None:
    # Real hardware NEVER closes a <tr class="portID"> with </tr> (verified
    # in this exact fixture) -- this is the one parser that must tolerate
    # that malformed-but-real shape (parse_port_stats, used by gs305ep,
    # would swallow all 10 rows into a single match).
    stats = {
        s.port: s
        for s in parse.parse_interface_stats(_read("gs110emx_interface_stats.html"))
    }
    assert set(stats) == set(range(1, 11))
    assert stats[1].rx_bytes == 0
    assert stats[1].tx_bytes == 0
    assert stats[1].rx_errors == 0
    assert stats[6].rx_bytes == 0
    assert stats[6].tx_bytes == 70892018242
    assert stats[8].rx_bytes == 59921732691
    assert stats[8].tx_bytes == 78637274870
    assert stats[9].rx_bytes == 2963140428936
    assert stats[9].tx_bytes == 1189358575871
    assert stats[10].rx_bytes == 1195417274187
    assert stats[10].tx_bytes == 3027396511187
    assert all(s.rx_errors == 0 for s in stats.values())
    assert all(s.tx_errors is None for s in stats.values())
    assert all(s.rx_packets is None and s.tx_packets is None for s in stats.values())


def test_parse_interface_stats_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_interface_stats("<html><body>Not Found</body></html>")


def test_parse_port_status() -> None:
    ports = parse.parse_port_status(_read("gs305ep_dashboard.html"))
    by_port = {p.port: p for p in ports}
    assert by_port[1].link_up is True
    assert by_port[1].admin_enabled is True
    assert by_port[1].speed_mbps == 1000
    assert by_port[1].name == "Port 1"
    assert by_port[2].link_up is False
    assert by_port[3].admin_enabled is False


def test_parse_port_stats() -> None:
    stats = {s.port: s for s in parse.parse_port_stats(_read("gs305ep_portstats.html"))}
    assert stats[1].rx_bytes == 1_000_000
    assert stats[1].tx_bytes == 2_000_000
    assert stats[2].rx_errors == 3


def test_parse_poe_status_maps_detect() -> None:
    poe = {p.port: p for p in parse.parse_poe_status(_read("gs305ep_poestatus.html"))}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 12800
    assert poe[1].admin_enabled is True
    assert poe[2].detect is PoEDetect.SEARCHING
    assert poe[3].detect is PoEDetect.DISABLED
    assert poe[3].admin_enabled is False
    assert poe[4].detect is PoEDetect.FAULT


def test_parse_membership_wire_codes() -> None:
    # hiddenMem "21133" -> ports 1..5: 2=T,1=U,1=U,3=X,3=X
    mem = parse.parse_membership(_read("gs305ep_membership.html"), port_count=5)
    assert mem[1] is VlanMode.TAGGED
    assert mem[2] is VlanMode.UNTAGGED
    assert mem[3] is VlanMode.UNTAGGED
    assert mem[4] is VlanMode.EXCLUDED
    assert mem[5] is VlanMode.EXCLUDED
    assert parse.parse_selected_vlan(_read("gs305ep_membership.html")) == 90


def test_parse_pvids_and_vlan_ids() -> None:
    pvids = dict(parse.parse_pvids(_read("gs305ep_pvid.html")))
    assert pvids == {1: 90, 2: 1}
    assert parse.parse_vlan_ids(_read("gs305ep_vlancfg.html")) == [1, 90]


def test_parse_reboot_ok() -> None:
    assert parse.parse_reboot_ok("<html>Rebooting now</html>") is True
    assert parse.parse_reboot_ok("<html>error: bad hash</html>") is False


# --- malformed/unexpected page -> HttpUnexpectedPageError (never silent/empty) ---

_MALFORMED = "<html><body>Not Found</body></html>"


def test_parse_port_status_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_port_status(_MALFORMED)


def test_parse_port_status_rejects_short_row() -> None:
    short_row = '<html><table><tr class="portID"><td>1</td></tr></table></html>'
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_port_status(short_row)


def test_parse_port_stats_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_port_stats(_MALFORMED)


def test_parse_poe_status_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_poe_status(_MALFORMED)


def test_parse_pvids_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_pvids(_MALFORMED)


def test_parse_pvids_rejects_rows_without_sel_cells() -> None:
    # portID rows present but missing sel="text"/sel="input" cells (wrong shape)
    malformed_rows = (
        '<html><table>'
        '<tr class="portID"><td>1</td><td>90</td></tr>'
        '<tr class="portID"><td>2</td><td>1</td></tr>'
        '</table></html>'
    )
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_pvids(malformed_rows)


def test_parse_vlan_ids_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_vlan_ids(_MALFORMED)


def test_parse_membership_rejects_missing_hiddenmem() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_membership(_MALFORMED, port_count=5)


def test_parse_membership_rejects_unknown_wire_code() -> None:
    html = '<input name="hiddenMem" id="hiddenMem" value="99999" type="hidden">'
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_membership(html, port_count=5)


# --- GSM7252PS "XE_FASTPATH" pages ------------------------------------
# Every test below is grounded in a REAL capture from the live switch
# 10.1.5.22 (tests/fixtures/http/gsm7252ps_*.html); the expected values are
# transcribed from those files, and cross-checked against the SAME device's
# SNMP capture (tests/fixtures/captures/gsm7252ps.json) wherever both
# backends report the field.


def test_parse_xe_rows_groups_by_instance_prefix() -> None:
    """The instance prefix is ``1.<row-index>.<row-count>`` -- NOT the port.

    A draft design read ``NAME=1.0.52.v_1_2_1`` as "unit 1 slot 0 port 52";
    the capture disproves that: that very cell's VALUE is ``1/0/1`` and the
    LAST component (52) is the same on every one of the 52 rows (it is the
    ROW COUNT). Port identity therefore comes from the row's own cells, never
    from the prefix.
    """
    rows = parse.parse_xe_rows(_read("gsm7252ps_portsConfiguration.html"))
    assert len(rows) == 52
    assert rows[0]["1_2_1"] == "1/0/1"      # first row, instance 1.0.52
    assert rows[0]["1_2_13"] == "1"         # ifindex column
    assert rows[51]["1_2_1"] == "1/0/52"    # last row, instance 1.51.52
    assert rows[51]["1_2_13"] == "52"
    # the blank "global" template row (NAME=v_g_1_2_1) carries no instance
    # prefix and must not become a 53rd row
    assert all(r.get("1_2_1") for r in rows)


def test_parse_xe_port_status_matches_capture() -> None:
    ports = {p.port: p for p in parse.parse_xe_port_status(
        _read("gsm7252ps_portsConfiguration.html")
    )}
    assert len(ports) == 52
    assert ports[1].name == "1/0/1"
    assert ports[1].admin_enabled is True
    assert ports[1].link_up is True
    assert ports[1].speed_mbps == 1000          # "1000 Mbps"
    # 1/0/50 is a 10G uplink: "10G Full " -> 10000
    assert ports[50].speed_mbps == 10000
    # 1/0/52 is down; its Physical Status reads "Unknown" -> no speed
    assert ports[52].link_up is False
    assert ports[52].speed_mbps is None
    # "100 Mbps Full Duplex" must not be read as 100000
    assert ports[23].speed_mbps is None  # down
    assert ports[47].speed_mbps == 1000
    down = {p for p, s in ports.items() if not s.link_up}
    assert down == {6, 8, 10, 12, 15, 19, 21, 23, 28, 29, 34, 35, 36, 39, 40,
                    43, 44, 48, 52}


def test_parse_xe_port_status_rejects_malformed_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_xe_port_status(_MALFORMED)


def test_parse_xe_stats_are_packets_not_bytes() -> None:
    """portStatistics.html reports PACKETS only -- there is no octet column on
    this page, so rx_bytes/tx_bytes are honestly None (values transcribed from
    the capture: 1/0/1 received 287280 packets, transmitted 155832097)."""
    stats = {s.port: s for s in parse.parse_xe_stats(
        _read("gsm7252ps_portStatistics.html")
    )}
    assert len(stats) == 52
    assert stats[1].rx_bytes is None
    assert stats[1].tx_bytes is None
    assert stats[1].rx_packets == 287280
    assert stats[1].tx_packets == 155832097
    assert stats[1].rx_errors == 0
    assert stats[1].tx_errors == 0
    assert stats[51].rx_packets == 11421062
    assert stats[52].rx_packets == 0
    assert stats[52].tx_packets == 0


def test_parse_xe_pvids_use_the_configured_column() -> None:
    """The page has BOTH "Configured PVID" (1_2_4) and "Current PVID" (1_2_9).

    The same device's SNMP capture (tests/fixtures/captures/gsm7252ps.json)
    agrees with the CONFIGURED column on all 52 ports; the CURRENT column
    reads 0 on the two trunk-member ports (50, 51) where SNMP reports 1, so
    reading it would silently disagree with SNMP on exactly those ports.
    """
    pvids = dict(parse.parse_xe_pvids(_read("gsm7252ps_portPvidConfiguration.html")))
    assert len(pvids) == 52
    assert pvids[1] == 90
    assert pvids[46] == 4
    assert pvids[47] == 5
    assert pvids[48] == 5
    assert pvids[49] == 1
    assert pvids[50] == 1  # "Current PVID" is 0 here -- must not be used
    assert pvids[51] == 1
    assert pvids[52] == 1


def test_parse_xe_vlans_expand_physical_ports_only() -> None:
    vlans = {v.vlan_id: v for v in parse.parse_xe_vlans(
        _read("gsm7252ps_vlanStatus.html")
    )}
    assert set(vlans) == {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
    assert vlans[1].name == "default"
    assert vlans[4].name == "wifi"
    # "1/0/11 - 1/0/12, 1/0/46, 1/0/49" -- a range plus singletons
    assert vlans[4].member_ports == frozenset({11, 12, 46, 49})
    # "1/0/46 - 1/0/47, 1/0/49, lag 1, lag 2" -- lags are NOT physical ports
    assert vlans[121].member_ports == frozenset({46, 47, 49})
    # VLANs 7/21/89 really have no member ports on this switch (the SNMP
    # capture of the same device agrees) -- an empty list, not a parse failure.
    assert vlans[7].member_ports == frozenset()
    # this page cannot distinguish tagged from untagged -> both left empty
    assert vlans[4].tagged_ports == frozenset()
    assert vlans[4].untagged_ports == frozenset()


def test_parse_xe_stats_pvids_vlans_reject_malformed_pages() -> None:
    for fn in (parse.parse_xe_stats, parse.parse_xe_pvids, parse.parse_xe_vlans):
        with pytest.raises(HttpUnexpectedPageError):
            fn(_MALFORMED)


def test_parse_xe_macs_skip_non_physical_interfaces() -> None:
    """The FDB's Port cell is not always a physical interface: the real
    capture holds 11 ``lag 1`` entries and one ``0/5/1`` service-port entry --
    the switch's OWN base MAC, flagged "Management". Taking the trailing
    number would report all twelve as physical port 1."""
    macs = parse.parse_xe_macs(_read("gsm7252ps_basicAddressTable.html"))
    assert len(macs) == 231  # 243 rendered rows - 11 lag - 1 service port
    by_mac = {m.mac: m for m in macs}
    # a learned entry on a real port, agreeing with the same device's SNMP
    # capture (88:A2:9E:80:87:9B -> port 1, VLAN 90)
    assert by_mac["88:A2:9E:80:87:9B"].port == 1
    assert by_mac["88:A2:9E:80:87:9B"].vlan_id == 90
    # the switch's own base MAC lives on the 0/5/1 service port -- never a port
    assert "E0:91:F5:0C:D6:DB" not in by_mac
    # a lag-learned MAC has no physical port
    assert "E0:91:F5:0C:D5:C9" not in by_mac
    assert all(1 <= m.port <= 52 for m in macs)


def test_parse_xe_macs_refuse_truncated_page() -> None:
    """The page states the true FDB size ("Total MAC Addresses"). If it ever
    renders fewer rows than that, the table is paginated and returning it
    would be a silently-truncated answer."""
    html = _read("gsm7252ps_basicAddressTable.html")
    # the real capture is NOT truncated (242 reported, 243 rendered) ...
    assert parse.parse_xe_macs(html)
    # ... so simulate a paginated one by raising the stated total
    truncated = html.replace('NAME=v_1_1_1 VALUE="242"', 'NAME=v_1_1_1 VALUE="1213"')
    with pytest.raises(HttpUnexpectedPageError, match="paginates"):
        parse.parse_xe_macs(truncated)


def test_parse_xe_poe_matches_capture() -> None:
    poe = {p.port: p for p in parse.parse_xe_poe(
        _read("gsm7252ps_poeInterfaceConfiguration.html")
    )}
    assert len(poe) == 48  # only the 48 PoE ports, not all 52
    assert poe[1].admin_enabled is True
    assert poe[1].detect is PoEDetect.DELIVERING  # "Delivering power"
    assert poe[1].power_mw == 3500                # Output Power (mW)
    assert poe[48].detect is PoEDetect.SEARCHING
    assert poe[48].power_mw == 0
    # port 6 reads "Other Fault" -- a FAULT, not UNKNOWN (SNMP's own detect
    # map has no code for it and reports "unknown" on this same device)
    assert poe[6].detect is PoEDetect.FAULT


def test_parse_xe_lldp_matches_capture() -> None:
    nb = {n.local_port: n for n in parse.parse_xe_lldp(
        _read("gsm7252ps_lldpRemoteInventory.html")
    )}
    assert len(nb) == 31
    assert nb[1].remote_sys_name == "rpi5-pmod"
    assert nb[1].remote_chassis_id == "88:A2:9E:80:87:9B"
    assert nb[1].remote_port_id == "88:A2:9E:80:87:9B"
    # this page has NO remote-port-DESCRIPTION column (its header row lists
    # Port / Remote Device ID / Management Address / MAC Address / System Name
    # / Remote Port ID), so port_desc is honestly None -- SNMP reports it.
    assert nb[1].remote_port_desc is None
    assert nb[49].remote_sys_name == "sw-netgear-m4300-24x"
    assert nb[49].remote_chassis_id == "8C:3B:AD:6B:BB:E0"
    assert nb[49].remote_port_id == "1/0/2"


def test_parse_xe_macs_poe_lldp_reject_malformed_pages() -> None:
    for fn in (parse.parse_xe_macs, parse.parse_xe_poe, parse.parse_xe_lldp):
        with pytest.raises(HttpUnexpectedPageError):
            fn(_MALFORMED)


# --- gsm7252ps sysInfo.html: format (B), plain label/value tables ---------


def test_parse_xe_labelled_values() -> None:
    """sysInfo.html carries NO v_ cells; its values are plain labelled table
    cells (an earlier draft grepped for the v_ pattern, found none, and wrongly
    concluded the page was JS-populated)."""
    fields = parse.parse_xe_labelled_values(_read("gsm7252ps_sysInfo.html"))
    assert fields["System MAC Address"] == "E0:91:F5:0C:D6:DB"
    assert fields["IPv4 Network Interface"] == "10.1.5.22/255.255.255.0"
    assert fields["System Up Time"] == "13 days 7 hours 44 mins 6 secs"
    assert fields["Product Name"].startswith("GSM7252PS 48-Port GE L2+")
    assert fields["Serial Number"] == "2BW20A47000CC"
    assert fields["Firmware Version"] == "10.0.0.53"
    # an <INPUT>-backed row still yields its value
    assert fields["System Name"] == "sw-netgear-gsm7252ps-s1.welland.mithis.com"


def test_parse_xe_mgmt_ip() -> None:
    mgmt = parse.parse_xe_mgmt_ip(_read("gsm7252ps_sysInfo.html"))
    assert mgmt.address == "10.1.5.22"
    assert mgmt.netmask == "255.255.255.0"
    assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
    # the page carries no DHCP/static indicator and no gateway row -- both
    # honestly unknown/None (the same device's SNMP capture also reports
    # mode "unknown" and gateway None)
    assert mgmt.mode is IpMode.UNKNOWN
    assert mgmt.gateway is None


def test_parse_xe_sensors() -> None:
    sensors = parse.parse_xe_sensors(_read("gsm7252ps_sysInfo.html"))
    temps = {s.name: s.value for s in sensors if s.kind == "temperature"}
    # Temperature Status table, Unit 1 column: System 29, CPU 49, MAC N/A,
    # MAC-A 32, MAC-B 31 -- the N/A row is absent, never a fabricated 0
    assert temps == {"System": 29.0, "CPU": 49.0, "MAC-A": 32.0, "MAC-B": 31.0}
    assert all(s.unit == "C" for s in sensors if s.kind == "temperature")
    # FAN Status table: Fan1/PWR, Fan2/CPU, Fan3/SYS report OK; Fan4/Fan5 read
    # "NA" (not populated) and are skipped
    fans = {s.name: s.value for s in sensors if s.kind == "fan"}
    assert fans == {"Fan1/PWR": 1.0, "Fan2/CPU": 1.0, "Fan3/SYS": 1.0}
    # this page reports fan HEALTH as text, never RPM -- unit says so
    assert all(s.unit == "state" for s in sensors if s.kind == "fan")
    # Device Status table: RPS + Power Module (the version/serial rows in that
    # same table are identity, not sensors, and must not appear)
    power = {s.name: s.value for s in sensors if s.kind == "power"}
    assert power == {"RPS": 1.0, "Power Module": 1.0}
    assert all(s.unit == "state" for s in sensors if s.kind == "power")


def test_parse_xe_sysinfo_parsers_reject_malformed_page() -> None:
    assert parse.parse_xe_labelled_values(_MALFORMED) == {}
    assert parse.parse_xe_sensors(_MALFORMED) == []
    with pytest.raises(HttpUnexpectedPageError):
        parse.parse_xe_mgmt_ip(_MALFORMED)
