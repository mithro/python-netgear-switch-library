"""Coverage guard: every read/write op on SyncSwitch must be reachable from a
``ngsw`` CLI subcommand. Mirrors ``test_mcp_server.py``'s MCP coverage guard so
that adding a new API method can never silently leave the CLI behind."""

from __future__ import annotations

import argparse
import inspect

from netgear_switch.cli.main import build_parser
from netgear_switch.sync_api import SyncSwitch

# Public SyncSwitch methods that deliberately get NO CLI command: connection
# lifecycle and construction helpers, none of which are switch operations.
# (These mirror ``test_mcp_server._NOT_MCP_EXPOSED``; names absent from
# SyncSwitch are simply never enumerated, which is harmless.)
_NOT_CLI_EXPOSED = {
    "login",
    "get_page",
    "post_form",
    "close",
    "from_config",
    # Introspection, not an operation. Backend CHOICE is exposed on ngsw as the
    # global ``--backend`` flag (see cli/resolve._backend), which every command
    # honours through the facade's default backend.
    "resolve_backend",
}

# SyncSwitch operation -> the ``ngsw`` subcommand that reaches it. Ops served by
# a subcommand-with-subcommands (``ip``/``vlan``) map to that top-level command.
_OP_TO_COMMAND = {
    "get_ports": "ports",
    "get_stats": "stats",
    "get_vlans": "vlans",
    "get_pvids": "pvids",
    "get_lldp": "lldp",
    "get_macs": "macs",
    "get_sensors": "sensors",
    "get_poe": "poe",
    "get_mgmt_ip": "ip",
    "snapshot": "show",
    "identify": "identify",
    "nsdp_device": "nsdp-device",
    "set_poe": "poe",
    "set_port_enabled": "port",
    "set_pvid": "pvid",
    "set_vlan_membership": "vlan",
    "create_vlan": "vlan",
    "delete_vlan": "vlan",
    "cycle_poe": "cycle-poe",
    "clear_poe_fault": "clear-poe-fault",
    "set_mgmt_ip": "ip",
    "upload_certificate": "upload-certificate",
    "upload_certificate_scp": "upload-certificate-scp",
}


def _switch_ops() -> set[str]:
    return {
        name
        for name, member in inspect.getmembers(SyncSwitch)
        if not name.startswith("_")
        and callable(member)
        and name not in _NOT_CLI_EXPOSED
    }


def _registered_commands() -> set[str]:
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("no subparsers registered on the ngsw parser")


def test_every_switch_operation_has_a_cli_command() -> None:
    """Fails if a future SyncSwitch op has no entry in ``_OP_TO_COMMAND`` -- the
    forcing function that keeps CLI coverage complete."""
    ops = _switch_ops()
    unmapped = ops - set(_OP_TO_COMMAND)
    assert not unmapped, (
        f"SyncSwitch ops with no CLI command mapping: {sorted(unmapped)}"
    )


def test_mapped_commands_are_actually_registered() -> None:
    """Every command the map points at must exist on the parser, so the map can
    never drift into naming a command that was renamed or never added."""
    commands = _registered_commands()
    ops = _switch_ops()
    missing = {
        op: _OP_TO_COMMAND[op] for op in ops if _OP_TO_COMMAND[op] not in commands
    }
    assert not missing, f"mapped commands not registered on the parser: {missing}"
