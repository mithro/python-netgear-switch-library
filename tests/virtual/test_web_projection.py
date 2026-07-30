from __future__ import annotations

from netgear_switch.models import PoEDetect, VlanMode
from netgear_switch.protocols.http import forms, parse
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
        state,
        _SPEC,
        "/PoEPortConfig.cgi",
        {"ACTION": "Apply", "portID": "1", "ADMIN_MODE": "0", "hash": "h"},
    )
    assert state.poe[2].admin is False


def test_apply_membership_form_mutates_vlan() -> None:
    state = seed_gs305ep()
    # hiddenMem "22111": ports 1,2 Tagged; 3,4,5 Untagged, for VLAN 90.
    web.apply_form(
        state,
        _SPEC,
        "/8021qMembe.cgi",
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


def test_render_stats_round_trips_per_port_counters() -> None:
    """``_render_stats`` -> ``parse.parse_port_stats``: per-port rx/tx/error
    counters must land in the right column. Ports 1/2 are given distinct
    rx/tx/error values so a column swap (e.g. tx placed where rx is read, or
    port 1's row landing under port 2) is caught rather than masked by equal
    seed values."""
    state = seed_gs305ep()
    state.ports[1].rx_octets = 111
    state.ports[1].tx_octets = 222
    state.ports[1].rx_errors = 5
    state.ports[2].rx_octets = 333
    state.ports[2].tx_octets = 444
    state.ports[2].rx_errors = 0

    html = web.render_page(state, _SPEC, _SPEC.stats_path, {})
    stats = {p.port: p for p in parse.parse_port_stats(html)}

    assert stats[1].rx_bytes == 111
    assert stats[1].tx_bytes == 222
    assert stats[1].rx_errors == 5
    assert stats[2].rx_bytes == 333
    assert stats[2].tx_bytes == 444
    assert stats[2].rx_errors == 0


def test_render_pvid_round_trips_port_to_pvid_map() -> None:
    """``_render_pvid`` -> ``parse.parse_pvids``: the seeded map has port
    number != PVID for every port (1->90, 2->90, 3/4/5->1), so if the port
    and PVID columns were ever swapped in ``_render_pvid`` this test fails
    instead of passing by coincidence."""
    state = seed_gs305ep()

    html = web.render_page(state, _SPEC, _SPEC.pvid_path, {})
    recovered = dict(parse.parse_pvids(html))

    assert recovered == state.pvids


def test_render_vlan_cfg_round_trips_vlan_id_list() -> None:
    """``_render_vlan_cfg`` -> ``parse.parse_vlan_ids``: recovers exactly the
    seeded VLAN id set (1, 90), sorted."""
    state = seed_gs305ep()

    html = web.render_page(state, _SPEC, _SPEC.vlan_config_path, {})
    recovered = parse.parse_vlan_ids(html)

    assert recovered == sorted(state.vlans)


def test_render_membership_round_trips_tagged_untagged_excluded() -> None:
    """``_render_membership`` -> ``parse.parse_membership``/``parse_selected_vlan``.

    VLAN 1 (member={1..5}, untagged={3,4,5}) exercises both TAGGED (ports
    1/2) and UNTAGGED (ports 3/4/5) codes; VLAN 90 (member={1,2},
    untagged={1,2}) exercises EXCLUDED (ports 3/4/5) alongside UNTAGGED
    (ports 1/2). Together every wire code (1/2/3) is checked against a real
    parse, so a swapped member/untagged bit in ``hiddenMem`` is caught."""
    state = seed_gs305ep()
    port_count = get_model(state.model_key).port_count

    html_v1 = web.render_page(
        state, _SPEC, _SPEC.vlan_membership_path, {"VLAN_ID": "1"}
    )
    mem_v1 = parse.parse_membership(html_v1, port_count)
    assert parse.parse_selected_vlan(html_v1) == 1
    assert mem_v1 == {
        1: VlanMode.TAGGED,
        2: VlanMode.TAGGED,
        3: VlanMode.UNTAGGED,
        4: VlanMode.UNTAGGED,
        5: VlanMode.UNTAGGED,
    }

    html_v90 = web.render_page(
        state, _SPEC, _SPEC.vlan_membership_path, {"VLAN_ID": "90"}
    )
    mem_v90 = parse.parse_membership(html_v90, port_count)
    assert parse.parse_selected_vlan(html_v90) == 90
    assert mem_v90 == {
        1: VlanMode.UNTAGGED,
        2: VlanMode.UNTAGGED,
        3: VlanMode.EXCLUDED,
        4: VlanMode.EXCLUDED,
        5: VlanMode.EXCLUDED,
    }


def test_render_login_round_trips_rand() -> None:
    """``render_login`` -> ``parse.parse_login_rand``: the nonce must be
    recoverable verbatim."""
    html = web.render_login("abc123xyz")

    assert parse.parse_login_rand(html) == "abc123xyz"


def test_apply_poe_reset_reasserts_detect_per_admin_state() -> None:
    """``_apply_poe`` Reset branch via ``forms.poe_reset_form``: detect is
    re-asserted to DELIVERING(3) only when admin is still True (port 2);
    an admin-disabled port (port 4) stays at 1 rather than being flipped to
    3, catching a Reset that ignores admin state."""
    state = seed_gs305ep()
    assert state.poe[2].admin is True
    assert state.poe[4].admin is False

    web.apply_form(
        state,
        _SPEC,
        _SPEC.poe_config_path,
        forms.poe_reset_form(port=2, csrf_hash="h"),
    )
    web.apply_form(
        state,
        _SPEC,
        _SPEC.poe_config_path,
        forms.poe_reset_form(port=4, csrf_hash="h"),
    )

    assert state.poe[2].detect == 3
    assert state.poe[4].detect == 1


def test_apply_pvid_form_changes_only_targeted_port() -> None:
    """``_apply_pvid`` via ``forms.pvid_form``: only the targeted port's PVID
    changes; the rest of the seeded map is untouched."""
    state = seed_gs305ep()

    web.apply_form(
        state,
        _SPEC,
        _SPEC.pvid_path,
        forms.pvid_form(port=3, vlan=90, csrf_hash="h"),
    )

    assert state.pvids == {1: 90, 2: 90, 3: 90, 4: 1, 5: 1}


def test_apply_vlan_cfg_add_and_delete() -> None:
    """``_apply_vlan_cfg`` Add via ``forms.vlan_add_form`` creates a new VLAN
    row; Delete via ``forms.vlan_delete_form`` removes an existing one."""
    state = seed_gs305ep()

    web.apply_form(
        state,
        _SPEC,
        _SPEC.vlan_config_path,
        forms.vlan_add_form(vlan=50, csrf_hash="h"),
    )
    assert 50 in state.vlans

    web.apply_form(
        state,
        _SPEC,
        _SPEC.vlan_config_path,
        forms.vlan_delete_form(vlan=90, checkbox_index=1, csrf_hash="h"),
    )
    assert 90 not in state.vlans
    assert sorted(state.vlans) == [1, 50]
