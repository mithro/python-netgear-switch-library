"""TOML inventory loading and credential resolution."""

from __future__ import annotations

import os
import shlex
import subprocess
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .errors import ConfigError, CredentialError
from .registry import SwitchModel, get_model

Runner = Callable[..., subprocess.CompletedProcess]


def resolve_secret(
    spec: str | None,
    *,
    env: Mapping[str, str],
    runner: Runner = subprocess.run,
) -> str | None:
    """Resolve one secret spec to its value (or None)."""
    if spec is None:
        return None
    if spec.startswith("${") and spec.endswith("}"):
        name = spec[2:-1]
        try:
            return env[name]
        except KeyError:
            raise CredentialError(f"environment variable {name!r} is not set") from None
    if spec.startswith("!"):
        args = shlex.split(spec[1:])
        if not args:
            raise CredentialError("empty command in secret spec")
        result = runner(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise CredentialError(
                f"secret command {args!r} failed "
                f"(exit {result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout.strip()
    return spec


def _is_literal(spec: str | None) -> bool:
    if spec is None:
        return False
    return not (spec.startswith("${") and spec.endswith("}")) and not spec.startswith(
        "!"
    )


def ensure_secure_file(path: os.PathLike | str) -> None:
    """Raise if the file is readable/writable by group or other."""
    mode = os.stat(path).st_mode
    if mode & 0o077:
        raise ConfigError(
            f"{os.fspath(path)} has insecure permissions {oct(mode & 0o777)}; "
            "chmod 600 it (contains a literal secret)"
        )


@dataclass(frozen=True)
class SwitchConfig:
    name: str
    model: SwitchModel
    host: str
    snmp_community: str | None
    snmp_write_community_spec: str | None
    http_password_spec: str | None
    nsdp_interface: str | None
    protected_ports: frozenset[int]

    def snmp_write_community(
        self, *, env: Mapping[str, str], runner: Runner = subprocess.run
    ) -> str | None:
        return resolve_secret(self.snmp_write_community_spec, env=env, runner=runner)

    def http_password(
        self, *, env: Mapping[str, str], runner: Runner = subprocess.run
    ) -> str | None:
        return resolve_secret(self.http_password_spec, env=env, runner=runner)


def _switch_from_table(
    name: str, table: Mapping[str, object]
) -> tuple[SwitchConfig, list[str]]:
    try:
        model_key = table["model"]
        host = table["host"]
    except KeyError as exc:
        raise ConfigError(
            f"switch {name!r} is missing required key {exc.args[0]!r}"
        ) from None
    if not isinstance(model_key, str) or not isinstance(host, str):
        raise ConfigError(f"switch {name!r}: 'model' and 'host' must be strings")

    snmp = table.get("snmp", {})
    http = table.get("http", {})
    nsdp = table.get("nsdp", {})
    if (
        not isinstance(snmp, Mapping)
        or not isinstance(http, Mapping)
        or not isinstance(nsdp, Mapping)
    ):
        raise ConfigError(f"switch {name!r}: snmp/http/nsdp must be tables")

    ports = table.get("protected_ports", [])
    if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
        raise ConfigError(f"switch {name!r}: protected_ports must be a list of ints")

    secret_specs = [
        snmp.get("write_community"),
        http.get("password"),
    ]
    literals = [
        s for s in secret_specs if _is_literal(s if isinstance(s, str) else None)
    ]

    cfg = SwitchConfig(
        name=name,
        model=get_model(model_key),
        host=host,
        snmp_community=snmp.get("community"),
        snmp_write_community_spec=snmp.get("write_community"),
        http_password_spec=http.get("password"),
        nsdp_interface=nsdp.get("interface"),
        protected_ports=frozenset(ports),
    )
    return cfg, literals


def load_inventory(
    path: os.PathLike | str,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, SwitchConfig]:
    """Load a TOML inventory into a {name: SwitchConfig} dict."""
    if env is None:
        env = os.environ
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    switches = data.get("switches", {})
    if not isinstance(switches, Mapping):
        raise ConfigError("top-level [switches] must be a table")

    result: dict[str, SwitchConfig] = {}
    any_literal = False
    for name, table in switches.items():
        if not isinstance(table, Mapping):
            raise ConfigError(f"[switches.{name}] must be a table")
        cfg, literals = _switch_from_table(name, table)
        if literals:
            any_literal = True
        result[name] = cfg

    if any_literal:
        ensure_secure_file(path)
    return result
