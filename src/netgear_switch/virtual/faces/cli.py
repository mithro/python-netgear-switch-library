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
from ..state import ScpCertDeploy

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec
    from ..state import VirtualSwitchState

_SHOW_VLAN_ID_RE = re.compile(r"^show vlan (\d+)$")
_SHOW_IFACE_RE = re.compile(r"^show interface ethernet \d+/0/(\d+)$")
_SETUP_RE = re.compile(r"^(enable|terminal length \d+|disable|end|exit)$")
_COPY_RE = re.compile(r"^copy\s+(\S+)\s+(\S+)$")


class VirtualCliFace:
    """An in-process CLI session serving a ``VirtualSwitchState``."""

    def __init__(self, state: VirtualSwitchState, spec: CliModelSpec) -> None:
        self.state = state
        self.spec = spec

    def _deploy(self) -> ScpCertDeploy:
        """Lazily create + return the cert-deploy record for this switch."""
        if self.state.scp_cert_deploy is None:
            self.state.scp_cert_deploy = ScpCertDeploy()
        return self.state.scp_cert_deploy

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        """In-process stand-in for the interactive ``copy scp://...`` step.

        The real ``ShellDriver.run_scp_copy`` drives a byte-level prompt handshake
        (TOFU/password/(y/n)) -- exercised end-to-end by the byte-level fake-shell
        test. This in-process face has no byte stream, so it records the copy
        (source URL + ``nvram:`` destination) into ``ScpCertDeploy`` and reports
        success, letting a facade-level test assert the deploy driver issued the
        right commands + destinations against a seeded ``VirtualSwitch``.
        """
        m = _COPY_RE.match(command.strip())
        if m is None:
            return "% Invalid input: expected 'copy <src> <dest>'"
        source_url, dest = m.group(1), m.group(2)
        deploy = self._deploy()
        deploy.commands.append(command.strip())
        deploy.copies.append((source_url, dest))
        return f"Data transfer complete. bytes transferred to {dest}"

    def run_write_memory(
        self, command: str = "write memory", *, prestuff: bool
    ) -> str:
        """In-process stand-in for the ``write memory`` save-config confirm."""
        deploy = self._deploy()
        deploy.commands.append(command.strip())
        deploy.saved = True
        return ""

    def run(self, command: str) -> str:
        c = command.strip()
        if _SETUP_RE.match(c):
            return ""
        if c == "no ip http secure-server":
            self._deploy().https_disabled = True
            self._deploy().commands.append(c)
            return ""
        if c == "ip http secure-server":
            self._deploy().https_enabled = True
            self._deploy().commands.append(c)
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
