"""In-process mock FASTPATH CLI face (implements ``CliSession``).

Unlike the HTTP face (which binds a real ``ThreadingHTTPServer`` so httpx clients
hit a socket), the CLI face is an IN-PROCESS transport: it implements the same
``CliSession`` seam ``CliReader`` depends on and dispatches each ``show`` command
string straight to the ``cli_fastpath`` renderer over device state -- no SSH
server, no socket, no host keys. This is deliberate and honest: live SSH cannot
be exercised from CI (no network) and the real byte transports are documented as
transport-only, so the mock proves the command-dispatch + parser round trip (the
part that CAN be tested) rather than standing up a paramiko server whose value
would be untestable here anyway.

A ``VirtualSwitch`` exposes one via ``cli_session()``; the session setup commands
(``enable`` / ``terminal length 0``) are accepted as no-op success, matching a
real shell.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .. import cli_fastpath

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec
    from ..state import VirtualSwitchState

_SHOW_VLAN_ID_RE = re.compile(r"^show vlan (\d+)$")
_SHOW_IFACE_RE = re.compile(r"^show interface ethernet \d+/0/(\d+)$")
_SETUP_RE = re.compile(r"^(enable|terminal length \d+|disable|end|exit)$")


class VirtualCliFace:
    """An in-process CLI session serving a ``VirtualSwitchState``."""

    def __init__(self, state: VirtualSwitchState, spec: CliModelSpec) -> None:
        self.state = state
        self.spec = spec

    def run(self, command: str) -> str:
        c = command.strip()
        if _SETUP_RE.match(c):
            return ""
        if c == self.spec.version_cmd:
            return cli_fastpath.render_version(self.state)
        if c == self.spec.port_status_cmd:
            return cli_fastpath.render_ports(self.state)
        if c == self.spec.vlan_brief_cmd:
            return cli_fastpath.render_vlan_brief(self.state)
        if c == self.spec.pvid_cmd:
            return cli_fastpath.render_pvids(self.state)
        if c == self.spec.mac_table_cmd:
            return cli_fastpath.render_mac_table(self.state)
        if c == self.spec.lldp_cmd:
            return cli_fastpath.render_lldp(self.state)
        if c == self.spec.poe_cmd:
            return cli_fastpath.render_poe(self.state)
        if c == self.spec.environment_cmd:
            return cli_fastpath.render_environment(self.state)
        if c == self.spec.network_cmd:
            return cli_fastpath.render_network(self.state)
        m = _SHOW_VLAN_ID_RE.match(c)
        if m:
            return cli_fastpath.render_vlan_detail(self.state, int(m.group(1)))
        m = _SHOW_IFACE_RE.match(c)
        if m:
            return cli_fastpath.render_interface_counters(self.state, int(m.group(1)))
        return "Command not found / Incomplete command. Use ? to list commands."

    def close(self) -> None:
        pass
