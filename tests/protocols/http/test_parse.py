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
