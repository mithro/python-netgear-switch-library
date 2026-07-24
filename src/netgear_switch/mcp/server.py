"""FastMCP server over the python-netgear-switch-library read/write API.

Every tool resolves its target switch through the SAME path the ``ngsw`` CLI
uses (``cli.resolve.resolve_switch``): either a named switch in a TOML
inventory (``switch=`` + ``config=``/``$NGSW_INVENTORY``) or an ad-hoc
``host=`` + ``model=`` pair, with credentials layered from args/env/inventory.
Results are the library's own ``models`` dataclasses, serialized to plain JSON.

Honesty carries through unchanged: an op a given model's backends genuinely do
not expose returns a structured ``{"unsupported": true, ...}`` result (from the
reader's ``UnsupportedCapabilityError``), never fabricated data.

Writes are gated: the write tools are only registered when
``NGSW_MCP_ALLOW_WRITES`` is truthy, because an MCP tool call is
model-initiated and reconfiguring a live switch is destructive. Even then each
disruptive op requires the caller to pass ``force=true`` (the same rail the CLI
and library enforce).
"""
from __future__ import annotations

import argparse
import dataclasses
import enum
import os
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..cli.resolve import resolve_switch
from ..errors import (
    ConfigError,
    NetgearSwitchError,
    UnsupportedCapabilityError,
)
from ..models import VlanMode

if TYPE_CHECKING:
    from ..sync_api import SyncSwitch

_WRITE_ENV = "NGSW_MCP_ALLOW_WRITES"
_INVENTORY_ENV = "NGSW_INVENTORY"


def writes_enabled(env: dict[str, str] | None = None) -> bool:
    """True iff writes are opted in via ``$NGSW_MCP_ALLOW_WRITES``."""
    env = env if env is not None else dict(os.environ)
    return env.get(_WRITE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _jsonable(obj: Any) -> Any:
    """Recursively convert a models dataclass tree into plain JSON types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: _jsonable(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
        }
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted(_jsonable(v) for v in obj)
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, bytes):
        return obj.hex()
    return obj


def _no_prompt(_text: str) -> str:
    """Credential prompt for a non-interactive server: never blocks.

    Returns an empty string, which ``resolve_switch`` treats as "unresolved" --
    so a switch genuinely missing a required credential raises the library's
    lazy ``CredentialError`` at read time (surfaced as a tool error) rather
    than hanging the server on stdin.
    """
    return ""


def _resolve(
    *,
    switch: str | None,
    host: str | None,
    model: str | None,
    config: str | None,
    community: str | None,
    http_password: str | None,
    nsdp_interface: str | None,
    env: dict[str, str],
) -> SyncSwitch:
    """Build a ``SyncSwitch`` from a tool's selector args (inventory or ad-hoc)."""
    if switch is None and (host is None or model is None):
        raise ConfigError(
            "specify either `switch` (an inventory name, with `config` or "
            "$NGSW_INVENTORY) or both `host` and `model`"
        )
    ns = argparse.Namespace(
        config=config or env.get(_INVENTORY_ENV),
        switch=switch,
        host=host,
        model=model,
        community=community,
        write_community=None,
        nsdp_interface=nsdp_interface,
        http_password=http_password,
    )
    return resolve_switch(ns, env=env, prompt=_no_prompt)


def _read(op_name: str, run):  # type: ignore[no-untyped-def]
    """Run a read op, converting library errors into a structured result.

    UnsupportedCapabilityError -> ``{"unsupported": true, ...}`` (an honest
    "this model's backends don't expose that", not an empty fabricated result);
    other library errors -> ``{"error": ...}`` so the MCP client sees a clean
    message instead of a stack trace.
    """
    try:
        return _jsonable(run())
    except UnsupportedCapabilityError as exc:
        return {"unsupported": True, "op": op_name, "detail": str(exc)}
    except NetgearSwitchError as exc:
        return {"error": str(exc), "op": op_name}


def list_inventory_switches(
    config: str | None, env: dict[str, str]
) -> list[dict[str, Any]]:
    """The named switches in the TOML inventory (``[switches.<name>]``)."""
    path_str = config or env.get(_INVENTORY_ENV)
    if not path_str:
        raise ConfigError(
            "no inventory: pass `config` or set $NGSW_INVENTORY"
        )
    path = Path(path_str)
    if not path.is_file():
        raise ConfigError(f"inventory file not found: {path}")
    data = tomllib.loads(path.read_text())
    switches = data.get("switches", {})
    return [
        {"name": name, "model": spec.get("model"), "host": spec.get("host")}
        for name, spec in switches.items()
    ]


def build_server(env: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    """Construct the FastMCP server. Write tools are registered only when
    ``$NGSW_MCP_ALLOW_WRITES`` is set (see module docstring)."""
    from mcp.server.fastmcp import FastMCP

    env = env if env is not None else dict(os.environ)
    mcp = FastMCP("netgear-switch")

    def resolver(
        switch: str | None, host: str | None, model: str | None,
        config: str | None, community: str | None,
        http_password: str | None, nsdp_interface: str | None,
    ) -> SyncSwitch:
        return _resolve(
            switch=switch, host=host, model=model, config=config,
            community=community, http_password=http_password,
            nsdp_interface=nsdp_interface, env=env,
        )

    @mcp.tool()
    def list_switches(config: str | None = None) -> list[dict[str, Any]]:
        """List the named switches in the TOML inventory."""
        return list_inventory_switches(config, env)

    @mcp.tool()
    def identify(
        host: str, model: str, config: str | None = None,
        community: str | None = None,
    ) -> dict[str, Any]:
        """Detect a switch's model over SNMP (sysDescr matching)."""
        sw = resolver(None, host, model, config, community, None, None)
        return _read("identify", sw.identify)

    # --- read tools: one per op --------------------------------------------
    def _register_read(name: str, method: str, doc: str) -> None:
        @mcp.tool(name=name, description=doc)
        def _tool(  # type: ignore[no-untyped-def]
            switch: str | None = None, host: str | None = None,
            model: str | None = None, config: str | None = None,
            community: str | None = None, http_password: str | None = None,
            nsdp_interface: str | None = None,
        ):
            sw = resolver(
                switch, host, model, config, community,
                http_password, nsdp_interface,
            )
            return _read(name, lambda: getattr(sw, method)())

    _register_read("get_ports", "get_ports", "Per-port link status and speed.")
    _register_read("get_stats", "get_stats", "Per-port byte/packet counters.")
    _register_read("get_vlans", "get_vlans", "VLANs with member/tagged/untagged ports.")
    _register_read("get_pvids", "get_pvids", "Per-port PVID (native VLAN).")
    _register_read("get_macs", "get_macs", "The MAC/FDB table (SNMP models).")
    _register_read("get_lldp", "get_lldp", "LLDP neighbours (SNMP models).")
    _register_read("get_sensors", "get_sensors", "Fan/temperature/PSU sensors.")
    _register_read("get_poe", "get_poe", "Per-port PoE status and delivered power.")
    _register_read("get_mgmt_ip", "get_mgmt_ip", "Management IP config and base MAC.")
    _register_read(
        "snapshot",
        "snapshot",
        "Every read op at once (ports, stats, VLANs, PVIDs, mgmt-IP, PoE, LLDP, "
        "sensors), each routed to the first backend that serves it. Fields no "
        "backend can serve come back empty rather than failing the whole call.",
    )
    _register_read(
        "get_device",
        "nsdp_device",
        "The complete raw NSDP device record (model, MAC, firmware, DHCP mode, "
        "serial, per-port status/statistics, VLAN membership, PVIDs, QoS, "
        "mirroring, IGMP snooping). NSDP-capable models only.",
    )

    if writes_enabled(env):
        _register_write_tools(mcp, resolver)

    return mcp


def _write(op_name: str, run):  # type: ignore[no-untyped-def]
    try:
        run()
        return {"ok": True, "op": op_name}
    except UnsupportedCapabilityError as exc:
        return {"unsupported": True, "op": op_name, "detail": str(exc)}
    except NotImplementedError as exc:
        # A mechanism the hardware HAS but this library hasn't wired yet (e.g.
        # upload_certificate on m4300/gs728tpp). Reported distinctly from
        # "unsupported" so a client is not told the switch cannot do it.
        return {"not_implemented": True, "op": op_name, "detail": str(exc)}
    except NetgearSwitchError as exc:
        return {"error": str(exc), "op": op_name}


def _register_write_tools(mcp, resolver) -> None:  # type: ignore[no-untyped-def]
    """Register the WRITE tools (only reached when writes are enabled).

    Each disruptive op still requires ``force=true`` -- the same guard rail the
    library enforces -- so a model cannot, say, change a PVID on a
    member-guarded port without explicitly asking.
    """

    @mcp.tool()
    def set_pvid(
        port: int, vlan: int, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Set a port's PVID (native VLAN). Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("set_pvid", lambda: sw.set_pvid(port, vlan, force=force))

    @mcp.tool()
    def set_port_enabled(
        port: int, enabled: bool, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Administratively enable/disable a port. Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write(
            "set_port_enabled", lambda: sw.set_port_enabled(port, enabled, force=force)
        )

    @mcp.tool()
    def set_poe(
        port: int, on: bool, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Turn a port's PoE on/off. Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("set_poe", lambda: sw.set_poe(port, on, force=force))

    @mcp.tool()
    def set_vlan_membership(
        vlan: int, port: int, mode: str, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Set a port's membership in a VLAN (mode: tagged|untagged|excluded).
        Disruptive: needs force=true."""
        try:
            vlan_mode = VlanMode(mode)
        except ValueError:
            return {
                "error": f"invalid mode {mode!r}: use tagged|untagged|excluded",
                "op": "set_vlan_membership",
            }
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write(
            "set_vlan_membership",
            lambda: sw.set_vlan_membership(vlan, port, vlan_mode, force=force),
        )

    @mcp.tool()
    def create_vlan(
        vlan: int, name: str, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Create a VLAN. Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("create_vlan", lambda: sw.create_vlan(vlan, name, force=force))

    @mcp.tool()
    def delete_vlan(
        vlan: int, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Delete a VLAN. Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("delete_vlan", lambda: sw.delete_vlan(vlan, force=force))

    @mcp.tool()
    def cycle_poe(
        port: int, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Power-cycle a port's PoE (off, wait, on) -- reboots the attached
        powered device. Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("cycle_poe", lambda: sw.cycle_poe(port, force=force))

    @mcp.tool()
    def clear_poe_fault(
        port: int, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Clear a port's latched PoE fault by cycling its power.
        Disruptive: needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write("clear_poe_fault", lambda: sw.clear_poe_fault(port, force=force))

    @mcp.tool()
    def set_mgmt_ip(
        address: str, netmask: str, gateway: str, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Set the switch's static management IP, netmask and gateway.
        HIGHLY disruptive -- changing this can make the switch unreachable at
        its current address. Needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write(
            "set_mgmt_ip",
            lambda: sw.set_mgmt_ip(address, netmask, gateway, force=force),
        )

    @mcp.tool()
    def upload_certificate(
        cert_pem: str, key_pem: str, force: bool = False,
        switch: str | None = None, host: str | None = None,
        model: str | None = None, config: str | None = None,
        community: str | None = None, http_password: str | None = None,
        nsdp_interface: str | None = None,
    ) -> dict[str, Any]:
        """Upload an HTTPS SSL server certificate + private key (both PEM text)
        to the switch. Implemented for gsm7228ps/S3300; a model whose mechanism
        is known but not yet implemented reports that honestly. HIGHLY
        disruptive -- replaces the running certificate. Needs force=true."""
        sw = resolver(
            switch, host, model, config, community, http_password, nsdp_interface
        )
        return _write(
            "upload_certificate",
            lambda: sw.upload_certificate(cert_pem, key_pem, force=force),
        )


def main() -> None:
    """Entry point (``ngsw-mcp``): run the server over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
