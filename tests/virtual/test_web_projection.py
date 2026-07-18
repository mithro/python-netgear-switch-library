from __future__ import annotations

from netgear_switch.models import PoEDetect
from netgear_switch.protocols.http import parse
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.virtual import web
from netgear_switch.virtual.seed import seed_gs305ep

_SPEC = http_spec(get_model("gs305ep"))


def test_seed_round_trips_through_render_and_parse() -> None:
    state = seed_gs305ep()
    dash = web.render_page(state, _SPEC, "/dashboard.cgi", {})
    ports = {p.port: p for p in parse.parse_port_status(dash)}
    assert ports[1].link_up is True
    poe_html = web.render_page(state, _SPEC, "/getPoePortStatus.cgi", {})
    poe = {p.port: p for p in parse.parse_poe_status(poe_html)}
    assert poe[1].detect is PoEDetect.DELIVERING
    assert poe[1].power_mw == 12800


def test_apply_poe_form_mutates_state() -> None:
    state = seed_gs305ep()
    web.apply_form(
        state, _SPEC, "/PoEPortConfig.cgi",
        {"ACTION": "Apply", "portID": "1", "ADMIN_MODE": "0", "hash": "h"},
    )
    assert state.poe[2].admin is False


def test_apply_membership_form_mutates_vlan() -> None:
    state = seed_gs305ep()
    # hiddenMem "22111": ports 1,2 Tagged; 3,4,5 Untagged, for VLAN 90.
    web.apply_form(
        state, _SPEC, "/8021qMembe.cgi",
        {"VLAN_ID": "90", "hiddenMem": "22111", "hash": "h"},
    )
    assert 1 in state.vlans[90].member
    assert 3 in state.vlans[90].untagged


def test_render_pages_carry_csrf_hash() -> None:
    state = seed_gs305ep()
    paths = (
        "/dashboard.cgi",
        "/PoEPortConfig.cgi",
        "/8021qMembe.cgi",
        "/portPVID.cgi",
        "/8021qCf.cgi",
    )
    for path in paths:
        html = web.render_page(state, _SPEC, path, {})
        assert parse.parse_csrf_hash(html) is not None
