from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.http.endpoints import (
    HTTP_SPECS,
    HtmlDialect,
    LoginScheme,
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
    assert spec.html_dialect is HtmlDialect.STANDARD


def test_gs110emx_gambit_scheme_and_reads_grounded() -> None:
    """GROUNDED in a live capture from a physical GS110EMX (see
    tests/fixtures/http/gs110emx_*.html): merge-hash login + a Gambit TOKEN
    session (not a cookie), and the full NSDP-parity read surface
    (ports/stats/VLANs/PVIDs/mgmt-IP) discovered live 2026-07-21."""
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
    # Full NSDP read parity over HTTP (real URLs, live-discovered 2026-07-21).
    assert spec.dashboard_path == "/iss/specific/port_settings.html"
    assert spec.vlan_config_path == "/iss/specific/Cf8021q.html"
    assert spec.vlan_membership_path == "/iss/specific/vlanMembership.html"
    assert spec.pvid_path == "/iss/specific/vlan_pvidsetting.html"
    # gs110emx genuinely has NO PoE (confirmed 404) -- these stay None.
    assert spec.poe_config_path is None
    assert spec.poe_status_path is None
    assert spec.is_epx_poe is False
    assert spec.reads_verified is True
    assert spec.html_dialect is HtmlDialect.GS110EMX


def test_gsm7228ps_cheetah_form_snmp_preferred() -> None:
    spec = http_spec(get_model("gsm7228ps"))
    assert spec.scheme is LoginScheme.CHEETAH_FORM
    assert spec.login_path == "/base/cheetah_login.html"
    assert spec.password_field == "pwd"
    assert spec.reads_verified is False


def test_http_spec_rejects_model_without_http_backend() -> None:
    # m4300-16x/-24x, gsm7252ps and every Plus model now have HTTP; the
    # SNMP-only models left in the registry must still refuse honestly.
    from netgear_switch.registry import MODELS

    snmp_only = [m for m in MODELS.values() if Backend.HTTP not in m.backends]
    assert snmp_only, "registry has no SNMP-only model left to check"
    for model in snmp_only:
        with pytest.raises(UnsupportedCapabilityError):
            http_spec(model)


def test_gsm7252ps_spec_xe_fastpath() -> None:
    """gsm7252ps HTTP: the CHEETAH_FORM login (uname+pwd -> SID cookie) was
    validated LIVE on 10.1.5.22, so scheme_verified is True. The read pages
    live at the ROOT prefix (not /base/, not /v1/) and are grounded in real
    captures (tests/fixtures/http/gsm7252ps_*.html) -- but reads_verified
    stays False until the live HTTP<->SNMP cross-verify runs against the
    switch itself."""
    spec = http_spec(get_model("gsm7252ps"))
    assert spec.scheme is LoginScheme.CHEETAH_FORM
    assert spec.scheme_verified is True
    assert spec.reads_verified is False
    assert spec.login_path == "/base/cheetah_login.html"
    assert spec.username_field == "uname"
    assert spec.username == "admin"
    assert spec.password_field == "pwd"
    assert spec.cookie_name == "SID"
    assert spec.needs_rand is False
    assert spec.needs_referer is False
    assert spec.dashboard_path == "/portsConfiguration.html"
    assert spec.stats_path == "/portStatistics.html"
    assert spec.pvid_path == "/portPvidConfiguration.html"
    assert spec.vlan_config_path == "/vlanStatus.html"
    assert spec.vlan_membership_path is None  # egress list is inline
    assert spec.mac_table_path == "/basicAddressTable.html"
    assert spec.poe_status_path == "/poeInterfaceConfiguration.html"
    assert spec.lldp_path == "/lldpRemoteInventory.html"
    assert spec.sysinfo_path == "/base/system/management/sysInfo.html"
    assert spec.html_dialect is HtmlDialect.XE_FASTPATH


def test_m4300_spec_live_verified_cheetah_v1() -> None:
    """M4300 HTTP is LIVE-VERIFIED (10.1.5.13): uname+pwd Cheetah /v1 login,
    Referer-required, and read pages whose URLs were recovered by driving a
    real browser through the runtime-built menu."""
    spec = http_spec(get_model("m4300-24x"))
    assert spec.scheme is LoginScheme.CHEETAH_V1
    assert spec.scheme_verified is True
    assert spec.reads_verified is True
    assert spec.needs_referer is True
    assert spec.username_field == "uname"
    assert spec.login_post_path == "/v1/base/cheetah_login.html"
    assert spec.dashboard_path == "/v1/portsConfiguration.html"
    assert spec.stats_path == "/v1/portStatistics.html"
    assert spec.vlan_config_path == "/v1/vlanStatus.html"
    assert spec.pvid_path == "/v1/portPvidConfiguration.html"
    assert spec.mac_table_path == "/v1/basicAddressTable.html"
    assert spec.html_dialect is HtmlDialect.M4300
    # no PoE on the 24X, and this UI has no LLDP neighbour table
    assert spec.poe_status_path is None


def test_gs105pe_spec_live_verified_real_paths() -> None:
    """gs105pe is LIVE-VERIFIED (10.1.5.30, 2026-07-21): merge-hash login
    confirmed, and the read paths corrected from the gs305ep copies that 404 on
    real hardware -- port status is status.cgi (NOT dashboard.cgi) and device
    identity/mgmt-IP is switch_info.cgi. It has no PoE PSE page (404)."""
    spec = http_spec(get_model("gs105pe"))
    assert spec.scheme is LoginScheme.MERGE_HASH_CGI
    assert spec.scheme_verified is True
    assert spec.login_path == "/login.cgi"
    assert spec.password_field == "password"
    assert spec.cookie_name == "SID"
    assert spec.needs_rand is True
    assert spec.reads_verified is True
    assert spec.html_dialect is HtmlDialect.GS105PE
    assert spec.dashboard_path == "/status.cgi"
    assert spec.sysinfo_path == "/switch_info.cgi"
    assert spec.stats_path == "/portStatistics.cgi"
    assert spec.pvid_path == "/portPVID.cgi"
    assert spec.vlan_config_path == "/8021qCf.cgi"
    assert spec.vlan_membership_path == "/8021qMembe.cgi"
    # confirmed 404 on real hardware: PoE pass-through, not a PSE
    assert spec.poe_status_path is None
    assert spec.poe_config_path is None
