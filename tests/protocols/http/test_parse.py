from __future__ import annotations

from pathlib import Path

import pytest

from netgear_switch.errors import HttpUnexpectedPageError
from netgear_switch.models import PoEDetect, VlanMode
from netgear_switch.protocols.http import parse

_FIX = Path(__file__).parent.parent.parent / "fixtures" / "http"


def _read(name: str) -> str:
    return (_FIX / name).read_text()


def test_parse_login_rand_and_hash() -> None:
    html = _read("gs305ep_login.html")
    assert parse.parse_login_rand(html) == "9917"
    assert parse.parse_csrf_hash(html) == "abc123def"
    assert parse.parse_login_rand("<html>no rand here</html>") is None


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
