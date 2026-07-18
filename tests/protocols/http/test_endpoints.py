from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.http.endpoints import (
    HTTP_SPECS,
    LoginScheme,
    http_spec,
)
from netgear_switch.registry import Backend, get_model


def test_every_http_model_has_a_spec() -> None:
    for key, model in _all_models().items():
        if Backend.HTTP in model.backends:
            assert key in HTTP_SPECS, f"{key} has HTTP backend but no HttpModelSpec"


def _all_models() -> dict[str, object]:
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


def test_gs110emx_gambit_reads_flagged_unverified() -> None:
    spec = http_spec(get_model("gs110emx"))
    assert spec.scheme is LoginScheme.GAMBIT
    assert spec.reads_verified is False  # UNVERIFIED-pending-capture


def test_gsm7228ps_cheetah_form_snmp_preferred() -> None:
    spec = http_spec(get_model("gsm7228ps"))
    assert spec.scheme is LoginScheme.CHEETAH_FORM
    assert spec.login_path == "/base/cheetah_login.html"
    assert spec.password_field == "pwd"
    assert spec.reads_verified is False


def test_http_spec_rejects_snmp_only_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        http_spec(get_model("m4300-24x"))
