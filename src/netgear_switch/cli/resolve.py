"""Resolve the target ``SyncSwitch`` from CLI args (inventory or host+model).

Credential precedence (design spec Sec5.1): CLI flag -> environment variable ->
config value -> interactive prompt.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from netgear_switch.config import load_inventory
from netgear_switch.errors import ConfigError
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable, Mapping

    from netgear_switch.config import SwitchConfig


def _read_community(
    args: argparse.Namespace,
    env: Mapping[str, str],
    config_value: str | None,
    prompt: Callable[[str], str] | None,
) -> str | None:
    if args.community:
        return str(args.community)
    if env.get("NGSW_COMMUNITY"):
        return env["NGSW_COMMUNITY"]
    if config_value:
        return config_value
    if prompt is not None:
        typed = prompt("SNMP read community: ")
        # A bare Enter at the prompt must NOT become a literal empty-string
        # SNMP community; treat it as unresolved so the library's existing
        # lazy CredentialError fires at SNMP-build time instead. (CLI/env/
        # config tiers are out of scope here -- separate hardening later.)
        return typed if typed.strip() else None
    return None


def _write_community_override(
    args: argparse.Namespace, env: Mapping[str, str]
) -> str | None:
    if args.write_community:
        return str(args.write_community)
    return env.get("NGSW_WRITE_COMMUNITY")


def _from_inventory(
    args: argparse.Namespace,
    env: Mapping[str, str],
    prompt: Callable[[str], str] | None,
) -> SyncSwitch:
    if not args.config:
        raise ConfigError("--switch requires --config <inventory.toml>")
    inventory = load_inventory(args.config, env=env)
    try:
        cfg: SwitchConfig = inventory[args.switch]
    except KeyError:
        raise ConfigError(
            f"switch {args.switch!r} not found in {args.config}"
        ) from None
    community = _read_community(args, env, cfg.snmp_community, prompt)
    write_override = _write_community_override(args, env)
    return SyncSwitch(
        cfg.model,
        cfg.host,
        snmp_community=community,
        snmp_write_community=write_override,
        snmp_write_community_resolver=lambda: cfg.snmp_write_community(env=env),
        protected_ports=cfg.protected_ports,
    )


def resolve_switch(
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] | None = None,
) -> SyncSwitch:
    """Build a ``SyncSwitch`` from ``--config``/``--switch``/``--host``/``--model``.

    Resolution: an inventory lookup (``--switch``, requires ``--config``) wins
    when given; otherwise ``--host``/``--model`` build a switch directly.
    Credential precedence for the SNMP read community is CLI flag ->
    ``NGSW_COMMUNITY`` env var -> inventory config value -> ``prompt`` (if
    supplied). The write community only ever comes from a CLI flag or
    ``NGSW_WRITE_COMMUNITY``/inventory spec, resolved lazily by ``SyncSwitch``.
    """
    env = os.environ if env is None else env
    if args.switch:
        return _from_inventory(args, env, prompt)
    if args.host and args.model:
        community = _read_community(args, env, None, prompt)
        return SyncSwitch(
            get_model(args.model),
            args.host,
            snmp_community=community,
            snmp_write_community=_write_community_override(args, env),
        )
    raise ConfigError(
        "specify --switch <name> (with --config) or both --host and --model"
    )
