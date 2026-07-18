from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

import pytest

from netgear_switch.cli.resolve import resolve_switch
from netgear_switch.errors import ConfigError

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
