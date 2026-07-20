from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

import pytest

from netgear_switch.cli.resolve import resolve_switch
from netgear_switch.errors import ConfigError, CredentialError, UnknownModelError

if TYPE_CHECKING:
    from pathlib import Path


def _args(**kw: object) -> argparse.Namespace:
    base = {
        "config": None,
        "switch": None,
        "host": None,
        "model": None,
        "community": None,
        "write_community": None,
        "nsdp_interface": None,
        "http_password": None,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def test_host_and_model_builds_switch_with_cli_community() -> None:
    sw = resolve_switch(
        _args(host="10.0.0.9", model="gsm7252ps", community="secret"), env={}
    )
    assert sw.host == "10.0.0.9"
    assert sw.model.key == "gsm7252ps"
    assert sw._snmp_community == "secret"


def test_env_community_used_when_flag_absent() -> None:
    sw = resolve_switch(
        _args(host="h", model="gsm7252ps"), env={"NGSW_COMMUNITY": "fromenv"}
    )
    assert sw._snmp_community == "fromenv"


def test_prompt_used_when_no_flag_env_or_config() -> None:
    seen: list[str] = []

    def fake_prompt(text: str) -> str:
        seen.append(text)
        return "typed"

    sw = resolve_switch(
        _args(host="h", model="gsm7252ps"), env={}, prompt=fake_prompt
    )
    assert sw._snmp_community == "typed"
    assert seen  # prompt was actually invoked


def test_no_snmp_community_prompt_for_nsdp_only_switch() -> None:
    # A Plus switch (gs110emx = HTTP+NSDP, no SNMP backend) must NEVER be
    # prompted for an SNMP read community: it is irrelevant, and a prompt on
    # piped stdin raises EOFError, blocking the NSDP/HTTP reads entirely.
    def exploding_prompt(text: str) -> str:
        raise AssertionError("must not prompt for SNMP community on a Plus switch")

    sw = resolve_switch(
        _args(host="10.1.5.25", model="gs110emx"), env={}, prompt=exploding_prompt
    )
    assert sw._snmp_community is None


def test_inventory_switch_resolves_by_name(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n'
        'snmp.community = "public"\n'
    )
    sw = resolve_switch(_args(config=str(inv), switch="core"), env={})
    assert sw.host == "10.1.5.20"
    assert sw._snmp_community == "public"


def test_unknown_switch_name_raises_configerror(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text('[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n')
    with pytest.raises(ConfigError, match="nope"):
        resolve_switch(_args(config=str(inv), switch="nope"), env={})


def test_no_target_raises_configerror() -> None:
    with pytest.raises(ConfigError, match="--switch"):
        resolve_switch(_args(), env={})


# --- Precedence tests: mutation-catching -----------------------------------
#
# Each test sets MULTIPLE credential tiers simultaneously with DISTINCT,
# conflicting values so that swapping the order of the checks inside
# `_read_community` (e.g. checking env before args.community) would make the
# assertion fail. A test that only ever supplies ONE tier at a time cannot
# distinguish "tier X was checked first" from "tier X was the only one set".


def test_cli_flag_beats_env_community() -> None:
    # Both the CLI flag AND the env var are set, to distinct values: if
    # `_read_community` checked env before args.community, this would
    # observe "env_val" instead and the assertion would fail.
    sw = resolve_switch(
        _args(host="h", model="gsm7252ps", community="cli_val"),
        env={"NGSW_COMMUNITY": "env_val"},
    )
    assert sw._snmp_community == "cli_val"


def test_env_community_beats_config_value(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n'
        'snmp.community = "config_val"\n'
    )
    # Both the env var AND the inventory's snmp.community are set, to
    # distinct values: if `_read_community` checked config_value before
    # env, this would observe "config_val" instead.
    sw = resolve_switch(
        _args(config=str(inv), switch="core"),
        env={"NGSW_COMMUNITY": "env_val"},
    )
    assert sw._snmp_community == "env_val"


def test_config_value_beats_prompt(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n'
        'snmp.community = "config_val"\n'
    )

    def exploding_prompt(text: str) -> str:
        raise AssertionError("prompt must not be invoked when config has a value")

    # Both the inventory's snmp.community AND a prompt callable are
    # available, with distinct values: if `_read_community` checked
    # prompt before config_value, this would either observe a different
    # value or the exploding prompt would fire.
    sw = resolve_switch(
        _args(config=str(inv), switch="core"), env={}, prompt=exploding_prompt
    )
    assert sw._snmp_community == "config_val"


# --- Write-community override --------------------------------------------


def test_cli_write_community_override_reaches_switch() -> None:
    sw = resolve_switch(
        _args(
            host="h", model="gsm7252ps", community="ro_secret",
            write_community="wr_secret",
        ),
        env={},
    )
    assert sw._snmp_write_community == "wr_secret"
    # Also confirm the resolver actually surfaces the override (this is
    # what every write op consults, not the raw attribute).
    assert sw._resolve_write_community() == "wr_secret"


def test_env_write_community_override_reaches_switch() -> None:
    sw = resolve_switch(
        _args(host="h", model="gsm7252ps", community="ro_secret"),
        env={"NGSW_WRITE_COMMUNITY": "env_wr_secret"},
    )
    assert sw._snmp_write_community == "env_wr_secret"
    assert sw._resolve_write_community() == "env_wr_secret"


def test_inventory_cli_write_community_override_wins_over_spec(
    tmp_path: Path,
) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n'
        'snmp.community = "public"\nsnmp.write_community = "spec_secret"\n'
    )
    inv.chmod(0o600)
    sw = resolve_switch(
        _args(config=str(inv), switch="core", write_community="override_secret"),
        env={},
    )
    assert sw._snmp_write_community == "override_secret"
    assert sw._resolve_write_community() == "override_secret"


# --- Unknown model ----------------------------------------------------------


def test_unknown_model_raises_unknownmodelerror() -> None:
    with pytest.raises(UnknownModelError, match="bogus-model"):
        resolve_switch(
            _args(host="h", model="bogus-model", community="secret"), env={}
        )


# --- Blank prompt result is treated as unresolved --------------------------


def test_blank_prompt_result_is_treated_as_unresolved() -> None:
    sw = resolve_switch(
        _args(host="h", model="gsm7252ps"), env={}, prompt=lambda _: ""
    )
    assert sw._snmp_community is None
    # The library's existing lazy CredentialError must fire at SNMP-build
    # time, not silently pass "" through as a real community.
    with pytest.raises(CredentialError, match="no SNMP read community"):
        sw.get_ports()


def test_whitespace_only_prompt_result_is_treated_as_unresolved() -> None:
    sw = resolve_switch(
        _args(host="h", model="gsm7252ps"), env={}, prompt=lambda _: "   "
    )
    assert sw._snmp_community is None


# --- Inventory passthrough: nsdp_interface + http/nsdp password resolvers --


def test_inventory_switch_passes_nsdp_interface_and_password_resolvers(
    tmp_path: Path,
) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.plus1]\nmodel = "gs110emx"\nhost = "10.1.5.25"\n'
        'nsdp.interface = "br-net"\nhttp.password = "s3cr3t"\n'
    )
    inv.chmod(0o600)  # a literal http.password secret requires secure perms
    sw = resolve_switch(_args(config=str(inv), switch="plus1"), env={})
    # The SyncSwitch actually received the inventory's nsdp_interface (not
    # just that construction succeeded) -- this is what build_sync_nsdp_client
    # uses for SO_BINDTODEVICE/read_interface_mac.
    assert sw._nsdp_interface == "br-net"
    # Both the NSDP write password and the HTTP password resolvers are wired
    # to the same inventory http.password secret (Plus switches share one
    # web-admin secret across HTTP and NSDP v1 auth).
    assert sw._resolve_nsdp_password() == "s3cr3t"
    assert sw._resolve_http_password() == "s3cr3t"


def test_no_snmp_community_prompt_for_nsdp_only_switch_via_inventory(
    tmp_path: Path,
) -> None:
    # Mirrors test_no_snmp_community_prompt_for_nsdp_only_switch (the
    # --host/--model path) on the --switch (inventory) path: a Plus switch
    # (gs110emx = HTTP+NSDP, no SNMP backend) must never be prompted for an
    # SNMP read community.
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.plus1]\nmodel = "gs110emx"\nhost = "10.1.5.25"\n'
    )

    def exploding_prompt(text: str) -> str:
        raise AssertionError("must not prompt for SNMP community on a Plus switch")

    sw = resolve_switch(
        _args(config=str(inv), switch="plus1"), env={}, prompt=exploding_prompt
    )
    assert sw._snmp_community is None


# --- --nsdp-interface / --http-password CLI flags --------------------------


def test_cli_nsdp_interface_reaches_switch_on_host_model_path() -> None:
    sw = resolve_switch(
        _args(host="10.1.5.25", model="gs110emx", nsdp_interface="eth1"), env={}
    )
    assert sw._nsdp_interface == "eth1"


def test_cli_http_password_reaches_switch_on_host_model_path() -> None:
    sw = resolve_switch(
        _args(host="10.1.5.25", model="gs110emx", http_password="clipass"), env={}
    )
    assert sw._resolve_http_password() == "clipass"
    assert sw._resolve_nsdp_password() == "clipass"


def test_cli_nsdp_interface_overrides_inventory_value(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.plus1]\nmodel = "gs110emx"\nhost = "10.1.5.25"\n'
        'nsdp.interface = "br-net"\n'
    )
    sw = resolve_switch(
        _args(config=str(inv), switch="plus1", nsdp_interface="cli-eth0"), env={}
    )
    assert sw._nsdp_interface == "cli-eth0"


def test_cli_http_password_overrides_inventory_value(tmp_path: Path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.plus1]\nmodel = "gs110emx"\nhost = "10.1.5.25"\n'
        'http.password = "inv_secret"\n'
    )
    inv.chmod(0o600)  # a literal http.password secret requires secure perms
    sw = resolve_switch(
        _args(config=str(inv), switch="plus1", http_password="cli_secret"), env={}
    )
    assert sw._resolve_http_password() == "cli_secret"
    assert sw._resolve_nsdp_password() == "cli_secret"
