from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.http.endpoints import (
    HTTP_SPECS,
    LoginScheme,
    StatsPageShape,
    http_spec,
)
from netgear_switch.registry import Backend, SwitchModel, get_model


def test_every_http_model_has_a_spec() -> None:
    for key, model in _all_models().items():
        if Backend.HTTP in model.backends:
            assert key in HTTP_SPECS, f"{key} has HTTP backend but no HttpModelSpec"


def _all_models() -> dict[str, SwitchModel]:
    from netgear_switch.registry import MODELS

    return dict(MODELS)


def test_gs305ep_spec_is_grounded_merge_hash() -> None:
    spec = http_spec(get_model("gs305ep"))
    assert spec.scheme is LoginScheme.MERGE_HASH_CGI
    assert spec.scheme_verified is True
    assert spec.login_path == "/login.cgi"
    assert spec.password_field == "password"
    assert spec.cookie_name == "SID"
    assert spec.needs_rand is True
    assert spec.dashboard_path == "/dashboard.cgi"
    assert spec.poe_config_path == "/PoEPortConfig.cgi"
    assert spec.poe_status_path == "/getPoePortStatus.cgi"
    assert spec.vlan_membership_path == "/8021qMembe.cgi"
    assert spec.pvid_path == "/portPVID.cgi"
    assert spec.is_epx_poe is True
    assert spec.reads_verified is True
    assert spec.stats_page_shape is StatsPageShape.STANDARD


def test_gs110emx_gambit_scheme_and_reads_grounded() -> None:
    """GROUNDED in a live capture from a physical GS110EMX (see
    tests/fixtures/http/gs110emx_*.html): merge-hash login + a Gambit TOKEN
    session (not a cookie), and exactly the sysInfo/interface_stats reads
    the capture proved exist -- everything else 404s on real hardware."""
    spec = http_spec(get_model("gs110emx"))
    assert spec.scheme is LoginScheme.GAMBIT
    assert spec.scheme_verified is True
    assert spec.login_path == "/"
    assert spec.login_post_path == "/redirect.html"
    assert spec.password_field == "LoginPassword"
    assert spec.session_token_field == "Gambit"
    assert spec.needs_rand is True
    assert spec.sysinfo_path == "/iss/specific/sysInfo.html"
    assert spec.stats_path == "/iss/specific/interface_stats.html"
    # Confirmed-404 on real hardware: no HTTP port-status/PoE/VLAN pages.
    assert spec.dashboard_path is None
    assert spec.poe_config_path is None
    assert spec.poe_status_path is None
    assert spec.vlan_config_path is None
    assert spec.vlan_membership_path is None
    assert spec.pvid_path is None
    assert spec.is_epx_poe is False
    assert spec.reads_verified is True
    assert spec.stats_page_shape is StatsPageShape.GS110EMX_OPEN_ROW


def test_gsm7228ps_cheetah_form_snmp_preferred() -> None:
    spec = http_spec(get_model("gsm7228ps"))
    assert spec.scheme is LoginScheme.CHEETAH_FORM
    assert spec.login_path == "/base/cheetah_login.html"
    assert spec.password_field == "pwd"
    assert spec.reads_verified is False


def test_http_spec_rejects_snmp_only_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        http_spec(get_model("m4300-24x"))
