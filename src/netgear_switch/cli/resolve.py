"""Resolve the target ``SyncSwitch`` from CLI args (inventory or host+model).

Credential precedence (design spec Sec5.1): CLI flag -> environment variable ->
config value -> interactive prompt.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from netgear_switch.config import load_inventory
from netgear_switch.errors import ConfigError
from netgear_switch.registry import Backend, get_model
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
    *,
    snmp_backend: bool,
) -> str | None:
    if args.community:
        return str(args.community)
    if env.get("NGSW_COMMUNITY"):
        return env["NGSW_COMMUNITY"]
    if config_value:
        return config_value
    # Only an SNMP-capable model needs a read community. A Plus (NSDP/HTTP-only)
    # switch has no SNMP backend, so prompting for one is both pointless and, in
    # a non-interactive context (piped stdin), a hard EOFError that blocks the
    # NSDP/HTTP reads entirely. Skip the prompt for such models.
    if snmp_backend and prompt is not None:
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


def _backend(args: argparse.Namespace) -> Backend | None:
    """``--backend snmp|nsdp|http|ssh|telnet|console`` -> the Backend, else None.

    Pins EVERY op of this invocation to one protocol. None leaves the model's
    default resolution in place (see ``SyncSwitch.resolve_backend``). A backend
    the model does not have, or one that cannot serve the requested op, is an
    error -- ngsw never quietly runs the op over a different protocol.
    """
    name = getattr(args, "backend", None)
    return None if name is None else Backend[name.upper()]


def _nsdp_interface(args: argparse.Namespace, config_value: str | None) -> str | None:
    """``--nsdp-interface`` wins when given; otherwise the inventory's
    ``nsdp.interface`` (``None`` on the ``--host``/``--model`` path, which
    has no inventory)."""
    if args.nsdp_interface:
        return str(args.nsdp_interface)
    return config_value


def _http_password_resolver(
    args: argparse.Namespace, config_resolver: Callable[[], str | None] | None
) -> Callable[[], str | None]:
    """``--http-password`` wins when given; otherwise falls back to the
    inventory's ``http.password`` spec resolver (``None`` on the
    ``--host``/``--model`` path). Lazy, like the inventory resolver it
    wraps: a read-only op on an SNMP switch never forces resolution of an
    absent web password."""

    def resolve() -> str | None:
        if args.http_password:
            return str(args.http_password)
        if config_resolver is not None:
            return config_resolver()
        return None

    return resolve


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
    community = _read_community(
        args,
        env,
        cfg.snmp_community,
        prompt,
        snmp_backend=Backend.SNMP in cfg.model.backends,
    )
    write_override = _write_community_override(args, env)
    # Pass the NSDP interface and web password through from the inventory: a
    # Plus switch (NSDP/HTTP) is unusable without them. The password specs are
    # resolved lazily (mirrors SyncSwitch.from_config) so a read-only op on an
    # SNMP switch never forces resolution of an absent web password. Plus
    # models share one web-admin secret across HTTP and NSDP, so http_password
    # feeds both resolvers. --nsdp-interface/--http-password (if given) win
    # over the inventory's own nsdp.interface/http.password.
    password_resolver = _http_password_resolver(
        args, lambda: cfg.http_password(env=env)
    )
    return SyncSwitch(
        cfg.model,
        cfg.host,
        snmp_community=community,
        snmp_write_community=write_override,
        snmp_write_community_resolver=lambda: cfg.snmp_write_community(env=env),
        nsdp_interface=_nsdp_interface(args, cfg.nsdp_interface),
        nsdp_password_resolver=password_resolver,
        http_password_resolver=password_resolver,
        protected_ports=cfg.protected_ports,
        backend=_backend(args),
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
        model = get_model(args.model)
        community = _read_community(
            args,
            env,
            None,
            prompt,
            snmp_backend=Backend.SNMP in model.backends,
        )
        # A Plus switch (NSDP/HTTP) reached via --host/--model (no inventory)
        # still needs --nsdp-interface/--http-password to be usable -- there
        # is no config value to fall back to on this path, only the CLI flags
        # themselves (see _nsdp_interface/_http_password_resolver above).
        password_resolver = _http_password_resolver(args, None)
        return SyncSwitch(
            model,
            args.host,
            snmp_community=community,
            snmp_write_community=_write_community_override(args, env),
            nsdp_interface=_nsdp_interface(args, None),
            nsdp_password_resolver=password_resolver,
            http_password_resolver=password_resolver,
            backend=_backend(args),
        )
    raise ConfigError(
        "specify --switch <name> (with --config) or both --host and --model"
    )
