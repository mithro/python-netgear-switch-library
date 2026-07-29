"""FASTPATH copy-scp SSL-cert deploy: the per-model profile, the deploy driver
over the in-process mock CLI face, the SyncSwitch facade dispatch, and the M4300
``show poe``/``show environment`` mock column-shape audit follow-up.

GROUNDED in prior art (certbot-hook FastpathScpUpdater), MOCK-TESTED, NOT
live-verified -- a real run is a production write needing a staging SCP server.
"""
from __future__ import annotations

import pytest

from netgear_switch.cli_read import CliReader
from netgear_switch.cli_write import deploy_certificate_scp
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import PoEDetect
from netgear_switch.protocols.cli.commands import (
    SCP_CERT_PROFILES,
    scp_cert_profile,
)
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.virtual import cli_fastpath
from netgear_switch.virtual.server import VirtualSwitch

# --- per-model profile ------------------------------------------------------


def test_scp_cert_profiles_match_prior_art() -> None:
    # Transcribed from certbot-hook MODEL_PROFILES.
    assert set(SCP_CERT_PROFILES) == {"m4300-24x", "m4300-16x", "gsm7252ps"}
    assert scp_cert_profile(get_model("m4300-24x")).writemem_stuff is False
    assert scp_cert_profile(get_model("m4300-16x")).writemem_stuff is False
    assert scp_cert_profile(get_model("m4300-16x")).verify_port == 49152
    gsm = scp_cert_profile(get_model("gsm7252ps"))
    assert gsm.writemem_stuff is True
    assert gsm.crypto == "legacy"


def test_scp_cert_profile_rejects_non_fastpath() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        scp_cert_profile(get_model("gs305ep"))  # NSDP+HTTP, no CLI backend


def test_scp_cert_profile_rejects_fastpath_without_scp() -> None:
    # gsm7228ps has an SSH backend but its cert upload is HTTP multipart, not SCP.
    with pytest.raises(UnsupportedCapabilityError):
        scp_cert_profile(get_model("gsm7228ps"))


# --- deploy driver over the in-process mock CLI face ------------------------


def test_deploy_driver_records_sequence_on_mock() -> None:
    sw = VirtualSwitch("m4300-24x")
    deploy_certificate_scp(
        sw.cli_session(),
        scp_source="switchcert@10.1.5.1",
        scp_password="x",
        remote_dir="/var/lib/switchcert/staging",
        base="10-1-5-13",
        chain=True,
        writemem_stuff=False,
    )
    d = sw.state.scp_cert_deploy
    assert d is not None
    assert d.https_disabled
    assert d.https_enabled
    assert d.saved
    assert [dest for _src, dest in d.copies] == [
        "nvram:sslpem-server",
        "nvram:sslpem-root",
    ]
    assert d.copies[0][0].endswith("10-1-5-13-server.pem")
    assert d.copies[1][0].endswith("10-1-5-13-root.pem")


def test_deploy_driver_without_chain_skips_root() -> None:
    sw = VirtualSwitch("gsm7252ps")
    deploy_certificate_scp(
        sw.cli_session(),
        scp_source="switchcert@10.1.5.1",
        scp_password="x",
        remote_dir="/staging",
        base="10-1-5-22",
        chain=False,
        writemem_stuff=True,
    )
    d = sw.state.scp_cert_deploy
    assert d is not None
    assert [dest for _src, dest in d.copies] == ["nvram:sslpem-server"]


# --- facade dispatch --------------------------------------------------------


def test_facade_upload_certificate_scp_drives_fastpath() -> None:
    sw = VirtualSwitch("m4300-24x")
    switch = SyncSwitch(
        get_model("m4300-24x"), "10.1.5.13", cli_client=sw.cli_session()
    )
    switch.upload_certificate_scp(
        scp_source="switchcert@10.1.5.1",
        scp_password="x",
        remote_dir="/var/lib/switchcert/staging",
        chain=False,
    )
    d = sw.state.scp_cert_deploy
    assert d is not None
    assert d.https_disabled
    assert d.https_enabled
    assert d.saved
    # base derived from the facade host (dots -> dashes).
    assert d.copies[0][0].endswith("10-1-5-13-server.pem")


def test_facade_upload_certificate_scp_unsupported_non_fastpath() -> None:
    switch = SyncSwitch(get_model("gs305ep"), "10.1.5.30")
    with pytest.raises(UnsupportedCapabilityError):
        switch.upload_certificate_scp(
            scp_source="s@h", scp_password="x", remote_dir="/s"
        )


def test_facade_upload_certificate_scp_unsupported_fastpath_without_scp() -> None:
    switch = SyncSwitch(get_model("gsm7228ps"), "10.1.5.28")
    with pytest.raises(UnsupportedCapabilityError):
        switch.upload_certificate_scp(
            scp_source="s@h", scp_password="x", remote_dir="/s"
        )


# --- M4300 show poe / show environment column-shape audit -------------------


def test_mock_render_poe_m4300_drops_temperature_column() -> None:
    m4300 = VirtualSwitch("m4300-16x").state
    gsm = VirtualSwitch("gsm7252ps").state
    assert "Temperature" not in cli_fastpath.render_poe(m4300)
    assert "Temperature" in cli_fastpath.render_poe(gsm)


def test_mock_render_environment_m4300_uses_power_modules_header() -> None:
    m4300 = VirtualSwitch("m4300-16x").state
    gsm = VirtualSwitch("gsm7252ps").state
    m4300_env = cli_fastpath.render_environment(m4300)
    assert "Power Modules:" in m4300_env
    assert "Power supplies:" not in m4300_env
    assert "Power supplies:" in cli_fastpath.render_environment(gsm)


def test_mock_m4300_poe_still_parses_through_reader() -> None:
    # The name-based parser must recover the same PoE values from the M4300
    # (no-Temperature) column shape the mock now emits.
    sw = VirtualSwitch("m4300-16x")
    reader = CliReader(sw.cli_session(), get_model("m4300-16x"))
    poe = {p.port: p for p in reader.get_poe()}
    assert poe[11].detect is PoEDetect.DELIVERING
    assert poe[11].power_mw == 5000
    assert poe[1].detect is PoEDetect.SEARCHING
