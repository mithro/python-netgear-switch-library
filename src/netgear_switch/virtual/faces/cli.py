"""In-process mock FASTPATH CLI face (implements ``CliSession``).

Unlike the HTTP face (which binds a real ``ThreadingHTTPServer`` so httpx clients
hit a socket), the CLI face is an IN-PROCESS transport: it implements the same
``CliSession`` seam ``CliReader``/``CliWriter`` depend on and dispatches each
command string straight to the ``cli_fastpath`` renderer (reads) or to a state
mutation (writes) -- no SSH server, no socket, no host keys. This is deliberate
and honest: live SSH cannot be exercised from CI (no network) and the real byte
transports are documented as transport-only, so the mock proves the
command-dispatch + parser round trip (the part that CAN be tested) rather than
standing up a paramiko server whose value would be untestable here anyway.

A ``VirtualSwitch`` exposes one via ``cli_session()``; the session setup commands
(``enable`` / ``terminal length 0``) are accepted as no-op success, matching a
real shell.

CONFIGURATION commands (the ``vlan database`` / ``configure`` trees that
``cli_write.CliWriter`` drives) mutate ``VirtualSwitchState`` itself, so the
change is immediately visible through EVERY face of the same virtual switch --
this CLI face's own ``show`` output, the SNMP ``oid_map()`` projection, the NSDP
TLVs and the web pages -- exactly as a write on real hardware is visible over
every protocol.

Two behaviours are modelled on purpose because the library's correctness depends
on them:

* An accepted configuration command returns EMPTY output; anything the switch
  would reject returns text. (The empty/non-empty CONTRACT is live-proven on an
  M4300-24X; the exact wording of the rejection strings below is NOT a
  transcription of any capture, and nothing in the library parses them.)
* ``vlan participation`` / ``vlan tagging`` / ``vlan pvid`` are accepted but
  completely INERT while the port is in ``switchport mode access`` -- the live
  finding (see ``cli_write.CliWriter``) that makes ``switchport mode general`` a
  mandatory step of every per-port CLI VLAN write. A mock that silently applied
  them in access mode would hide exactly the bug that finding exists to prevent.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ...models import syslog_severity
from ...registry import get_model
from .. import cli_fastpath
from ..state import ScpCertDeploy, SyslogCollectorSim, VlanSim

if TYPE_CHECKING:
    from ...protocols.cli.commands import CliModelSpec
    from ..state import VirtualSwitchState

_SHOW_VLAN_ID_RE = re.compile(r"^show vlan (\d+)$")
# Accept ANY interface-name shape the model prints ("1/0/7", "1/g7", "1/xg49")
# and resolve it through the renderer's own naming (cli_fastpath.port_for_iface),
# instead of the old hardcoded r"\d+/0/(\d+)" which could never match the
# Smart-firmware S3300-52X's real names.
_SHOW_IFACE_RE = re.compile(r"^show interface ethernet (\S+)$")
_SETUP_RE = re.compile(r"^(enable|terminal length \d+|disable)$")
_COPY_RE = re.compile(r"^copy\s+(\S+)\s+(\S+)$")

# --- configuration-mode commands -------------------------------------------
_CONFIGURE_RE = re.compile(r"^config(?:ure)?(?: terminal)?$")
_HOSTNAME_RE = re.compile(r'^hostname\s+("?[^"]+"?)$')
_VLAN_DATABASE_RE = re.compile(r"^vlan database$")
_VLAN_CREATE_RE = re.compile(r"^vlan (\d+)$")
_VLAN_NAME_RE = re.compile(r"^vlan name (\d+) (\S+)$")
_VLAN_DELETE_RE = re.compile(r"^no vlan (\d+)$")
_INTERFACE_RE = re.compile(r"^interface (\S+)$")
_SWITCHPORT_MODE_RE = re.compile(r"^switchport mode (access|general|trunk)$")
_PARTICIPATION_RE = re.compile(r"^vlan participation (include|exclude) (\d+)$")
_TAGGING_RE = re.compile(r"^(no )?vlan tagging (\d+)$")
_PVID_RE = re.compile(r"^vlan pvid (\d+)$")
# Per-port description. The single-quoted form is the firmware's OWN: a live
# GSM7252PS (10.1.5.22, 2026-08-03) renders its 38 labelled ports in
# ``show running-config`` as ``description 'eth0.rpi5-pmod'``, and the negation
# is the standard ``no description``. NOT mode-gated, unlike the VLAN commands:
# a label is cosmetic and does not depend on the port's switchport mode.
_DESCRIPTION_RE = re.compile(r"^description '([^']*)'$")
_NO_DESCRIPTION_RE = re.compile(r"^no description$")
_PORT_DESCRIPTION_SHOW_RE = re.compile(r"^show port description (\S+)$")
# Per-port speed/duplex. TWO grammars meaning opposite things, both executed on
# the real gsm7252ps (10.1.5.22 port 1/0/8, 2026-08-03) -- ``speed 100
# full-duplex`` moved Physical Mode to "100 Full", ``speed auto`` moved it back.
_SPEED_AUTO_RE = re.compile(r"^speed auto$")
_SPEED_FORCED_RE = re.compile(r"^speed (\d+G?) (full|half)-duplex$")
# MEASURED REFUSAL, and the reason this mock is not merely permissive: the same
# live port answered ``speed 1000 full-duplex`` with "% Invalid input detected
# at '^' marker." and left Physical Mode UNCHANGED. 1000BASE-T requires
# auto-negotiation, so the firmware keeps 1000 out of the forced grammar while
# offering it in ``speed auto [10] [100] [1000] [10G]``.
_NO_FORCED_RATE = 1000
# NOT modelled, and deliberately so: which OTHER rates a port will force is a
# property of its PHY, not of the firmware -- gsm7252ps 1/0/8 enumerated
# 10/100/10G while m4300-24x 1/0/15 enumerated 100/10G (no 10). Only those two
# ports were ever enumerated, on two of the four CLI models, so a per-model rate
# table here would be inventing three quarters of itself. The library does not
# pre-validate rates either (it sends, and raises whatever the device answers),
# so mock and library agree on exactly the rule that was measured.

# 802.3x flow control -- a bare toggle, round-tripped live on gsm7252ps
# 10.1.5.22 port 1/0/8 (2026-08-03): `flowcontrol` moved Flow Mode from Disable
# to Enable and added a running-config line, `no flowcontrol` undid both.
_FLOW_CONTROL_RE = re.compile(r"^(no )?flowcontrol$")
_POE_RE = re.compile(r"^(no )?poe$")
_POE_RESET_RE = re.compile(r"^poe reset$")
_SHUTDOWN_RE = re.compile(r"^(no )?shutdown$")
# Remote logging, in GLOBAL config mode. The add form is VERBATIM from every
# FASTPATH switch's own running-config (2026-08-05):
#     logging host "10.1.5.1" ipv4 514 info
# The removal addresses the 1-based INDEX from `show logging hosts`.
_LOGGING_HOST_ADD_RE = re.compile(
    r'^logging host "([^"]+)" (ipv4|ipv6|dns) (\d+) (\w+)$'
)
# REMOVAL IS A SUBCOMMAND, NOT A NEGATION. This mock used to accept
# `no logging host <index>` -- which the REAL gsm7252ps rejects outright
# ("% Invalid input detected at '^' marker.", measured 2026-08-05, and it left
# a throwaway collector stranded on the switch until the right verb was found).
# The device's own `logging host ?` lists `remove` and `reconfigure` as
# subcommands. Accepting the negation here is exactly the lenient-fake failure
# principle 5 exists to prevent, so the negation is now REJECTED too.
_LOGGING_HOST_REMOVE_RE = re.compile(r"^logging host remove (\d+)$")
#: The negation, MEASURED as rejected on 10.1.5.22 with the exact text below --
#: in every spelling tried (bare index, quoted address, unquoted address, and
#: both with a trailing `ipv4`). Matched explicitly so the mock answers it the
#: way the device does, rather than falling through to the generic
#: "Command not found" and being merely accidentally-not-wrong.
_LOGGING_HOST_NEGATION_RE = re.compile(r"^no logging host\b.*$")
_LOGGING_SYSLOG_RE = re.compile(r"^(no )?logging syslog$")
_IP = r"(\d+\.\d+\.\d+\.\d+)"
# Older images (gsm7252ps, gsm7228ps): ONE privileged-EXEC command.
_NETWORK_PARMS_RE = re.compile(rf"^network parms {_IP} {_IP}(?: {_IP})?$")
# M4300 12.0.x: two global-config commands instead.
_IP_MGMT_ADDR_RE = re.compile(rf"^ip management address {_IP} {_IP}$")
_IP_GATEWAY_RE = re.compile(rf"^ip default-gateway {_IP}$")

# Mode names for the mode stack (see VirtualCliFace._modes).
_VLAN_DB, _CONFIG, _INTERFACE = "vlan-db", "config", "interface"

# Rejection texts. This exact wording IS now ground truth for at least one
# case: a live gsm7252ps (10.1.5.22, 2026-08-03) answered ``speed 1000
# full-duplex`` with precisely "% Invalid input detected at '^' marker.". It is
# still not established that every other rejection here is worded the same way;
# what IS proven, and all the library relies on, is that a rejected command
# answers with SOMETHING and an accepted one answers with NOTHING.
_INVALID = "% Invalid input detected at '^' marker."
_ACCEPTED = ""


def _no_such_vlan(vlan: int) -> str:
    return f"ERROR: VLAN {vlan} does not exist"


class VirtualCliFace:
    """An in-process CLI session serving a ``VirtualSwitchState``."""

    def __init__(self, state: VirtualSwitchState, spec: CliModelSpec) -> None:
        self.state = state
        self.spec = spec
        # The command-mode stack, innermost last: [] is EXEC mode, ["vlan-db"] is
        # the VLAN database, ["config", "interface"] is interface config mode.
        # ``exit`` pops one level and ``end`` returns to EXEC, like a real shell.
        self._modes: list[str] = []
        # The port ``interface <iface>`` selected, while in interface mode.
        self._iface_port: int | None = None

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

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        """In-process stand-in for a command with a ``(y/n)`` confirm.

        Two commands use this transport path: ``write memory`` (save config) and
        ``reload`` (reboot). They are NOT interchangeable, so the mock keeps them
        apart -- a ``reload`` must never look like a config save. A real reload
        also tears the session down; the mock cannot restart itself, so it records
        the request (``state.reboots``) and returns, which is what lets a test
        prove the right command was issued.
        """
        c = command.strip()
        if c == "reload":
            self.state.reboots += 1
            return ""
        deploy = self._deploy()
        deploy.commands.append(c)
        deploy.saved = True
        return ""

    # --- write helpers ------------------------------------------------------

    @property
    def _mode(self) -> str:
        return self._modes[-1] if self._modes else "exec"

    def _general(self, port: int) -> bool:
        """True when ``port`` is in a switchport mode that HONOURS the per-port
        VLAN commands. Access mode accepts them and ignores them (live finding);
        trunk mode honours them like general mode does."""
        sim = self.state.ports.get(port)
        return sim is not None and sim.switchport_mode in ("general", "trunk")

    def _vlan_db_command(self, c: str) -> str | None:
        """Handle one command inside ``vlan database``, else None."""
        m = _VLAN_CREATE_RE.match(c)
        if m:
            vid = int(m.group(1))
            # Selecting an existing VLAN is accepted too (idempotent), matching
            # a real switch: "vlan 5" on an existing VLAN 5 is not an error.
            if vid not in self.state.vlans:
                self.state.vlans[vid] = VlanSim(name="")
            return _ACCEPTED
        m = _VLAN_NAME_RE.match(c)
        if m:
            vid, name = int(m.group(1)), m.group(2)
            if vid not in self.state.vlans:
                return _no_such_vlan(vid)
            self.state.vlans[vid].name = name
            return _ACCEPTED
        m = _VLAN_DELETE_RE.match(c)
        if m:
            vid = int(m.group(1))
            if vid == 1:
                return "ERROR: The default VLAN cannot be deleted"
            if vid not in self.state.vlans:
                return _no_such_vlan(vid)
            del self.state.vlans[vid]
            # Device coherence (a deliberate model of real behaviour, not a
            # transcription): no port can be left with its PVID pointing at a
            # VLAN that no longer exists, so those ports fall back to VLAN 1.
            for port, pvid in self.state.pvids.items():
                if pvid == vid:
                    self.state.pvids[port] = 1
            return _ACCEPTED
        return None

    def _has_switchport_modes(self) -> bool:
        """True unless this model's image has NO ``switchport mode`` command.

        Probed live 2026-07-30: the gsm7252ps (XE image) answers
        "% Unrecognized command" to ``switchport mode ?`` and offers only
        private-group/protected under ``switchport ?``, while the M4300 12.0.x
        images and the S3300 Smart image all offer access|general|trunk.
        Keyed on the MODEL rather than read out of ``CliModelSpec`` on purpose:
        the mock has to be an independent statement of what the device does, so
        that a wrong spec is caught here instead of being mirrored.
        """
        return self.state.model_key != "gsm7252ps"

    def _uses_ip_management_dialect(self) -> bool:
        """True for the images whose mgmt-IP write is global-config
        ``ip management address`` + ``ip default-gateway`` (M4300 12.0.x, which
        reject ``network parms`` outright); False for the older images that take
        privileged-EXEC ``network parms``. Live-probed 2026-07-30 on all four."""
        return self.state.model_key.startswith("m4300")

    def _poe_capable(self) -> bool:
        """True when this SKU has PSE hardware at all.

        The M4300-24X has none, and its firmware consequently has no ``poe``
        command whatsoever ("poe ?" -> "% Unrecognized command", probed live on
        10.1.5.13) -- so the mock must reject PoE commands there, not silently
        accept them.
        """
        return get_model(self.state.model_key).poe_port_count > 0

    def _interface_command(self, c: str, port: int) -> str | None:
        """Handle one command inside ``interface <iface>``, else None."""
        m = _SWITCHPORT_MODE_RE.match(c)
        if m:
            if not self._has_switchport_modes():
                return _INVALID  # this image has no switchport-mode concept
            self.state.ports[port].switchport_mode = m.group(1)
            return _ACCEPTED
        if _POE_RESET_RE.match(c):
            if not self._poe_capable():
                return _INVALID
            self.state.apply_poe_reset(port)
            return _ACCEPTED
        m = _POE_RE.match(c)
        if m:
            if not self._poe_capable():
                return _INVALID
            self.state.apply_poe_admin(port, on=m.group(1) is None)
            return _ACCEPTED
        m = _SHUTDOWN_RE.match(c)
        if m:
            enabled = m.group(1) is not None  # "no shutdown" enables
            sim = self.state.ports.get(port)
            if sim is None:
                return _INVALID
            sim.admin = enabled
            if not enabled:
                # A shut port cannot stay linked -- same coherence the SNMP
                # ifAdminStatus write applies (see VirtualSwitchState.apply_write).
                sim.link = False
            return _ACCEPTED
        m = _PARTICIPATION_RE.match(c)
        if m:
            include, vid = m.group(1) == "include", int(m.group(2))
            vsim = self.state.vlans.get(vid)
            if vsim is None:
                return _no_such_vlan(vid)
            # ACCEPTED-BUT-INERT in access mode -- the live-proven behaviour.
            if not self._general(port):
                return _ACCEPTED
            if include:
                vsim.member.add(port)
                # A newly included port is UNTAGGED until "vlan tagging" says
                # otherwise (that is why the writer always sends one of the two).
                vsim.untagged.add(port)
            else:
                vsim.member.discard(port)
                vsim.untagged.discard(port)
            return _ACCEPTED
        m = _TAGGING_RE.match(c)
        if m:
            tagged, vid = m.group(1) is None, int(m.group(2))
            vsim = self.state.vlans.get(vid)
            if vsim is None:
                return _no_such_vlan(vid)
            if not self._general(port):
                return _ACCEPTED  # accepted-but-inert, as above
            if tagged:
                vsim.untagged.discard(port)
            else:
                vsim.untagged.add(port)
            return _ACCEPTED
        m = _PVID_RE.match(c)
        if m:
            vid = int(m.group(1))
            if vid not in self.state.vlans:
                return _no_such_vlan(vid)
            if not self._general(port):
                return _ACCEPTED  # accepted-but-inert, as above
            self.state.pvids[port] = vid
            return _ACCEPTED
        m = _FLOW_CONTROL_RE.match(c)
        if m:
            # Configured state only: the link is not renegotiated, exactly as
            # observed on the live DOWN port whose Flow Mode still moved.
            self.state.ports[port].flow_control = m.group(1) is None
            return _ACCEPTED
        if _SPEED_AUTO_RE.match(c):
            self.state.ports[port].physical_mode = "Auto"
            return _ACCEPTED
        m = _SPEED_FORCED_RE.match(c)
        if m:
            rate, duplex = m.group(1), m.group(2)
            if rate == str(_NO_FORCED_RATE):
                return _INVALID  # measured: the switch has no forced 1000
            # Physical Mode ONLY. The negotiated rate (``speed``, rendered in
            # the Physical Status column) is untouched, because forcing the
            # configuration of a DOWN port negotiates nothing -- exactly what
            # the live port did.
            self.state.ports[port].physical_mode = f"{rate} {duplex.capitalize()}"
            return _ACCEPTED
        m = _DESCRIPTION_RE.match(c)
        if m:
            self.state.ports[port].description = m.group(1) or None
            return _ACCEPTED
        if _NO_DESCRIPTION_RE.match(c):
            self.state.ports[port].description = None
            return _ACCEPTED
        return None

    def _config_command(self, c: str) -> str | None:
        """Handle mode entry/exit and every configuration command, else None
        (meaning: not a config command, try the ``show`` dispatch)."""
        if c == "exit":
            if self._modes:
                self._modes.pop()
                if self._mode != _INTERFACE:
                    self._iface_port = None
            return _ACCEPTED
        if c == "end":
            self._modes.clear()
            self._iface_port = None
            return _ACCEPTED
        if _VLAN_DATABASE_RE.match(c):
            # Reachable from EXEC and from global config mode on real FASTPATH.
            if self._mode in ("exec", _CONFIG):
                self._modes.append(_VLAN_DB)
                return _ACCEPTED
            return _INVALID
        if _CONFIGURE_RE.match(c):
            if self._mode == "exec":
                self._modes.append(_CONFIG)
                return _ACCEPTED
            return _INVALID
        m = _NETWORK_PARMS_RE.match(c)
        if m:
            # Privileged EXEC only, and only on the images that HAVE it: the
            # M4300 12.0.x rejects "network parms" in every mode (probed live).
            if self._mode != "exec" or self._uses_ip_management_dialect():
                return _INVALID
            self.state.mgmt.address = m.group(1)
            self.state.mgmt.netmask = m.group(2)
            if m.group(3):
                self.state.mgmt.gateway = m.group(3)
            self.state.mgmt.mode = "static"
            return _ACCEPTED
        if self._mode == _VLAN_DB:
            return self._vlan_db_command(c)
        if self._mode == _CONFIG:
            m = _HOSTNAME_RE.match(c)
            if m:
                # The device stores the name unquoted; its running-config
                # renders it quoted, and `show hosts` reports it bare. Accept
                # either form on the wire so a caller that quotes is not
                # silently given a name with quotes embedded in it.
                self.state.hostname = m.group(1).strip().strip('"')
                return _ACCEPTED
            m = _LOGGING_SYSLOG_RE.match(c)
            if m:
                # admin_mode is the device's own enum, 1 = enabled / 2 = not.
                self.state.syslog.admin_mode = 1 if m.group(1) is None else 2
                return _ACCEPTED
            m = _LOGGING_HOST_ADD_RE.match(c)
            if m:
                address, _kind, port, word = m.groups()
                try:
                    severity = syslog_severity(word)
                except ValueError:
                    return _INVALID  # a word this firmware would not accept
                # A real switch appends a SECOND row for an address it already
                # has rather than replacing the first -- which is exactly why
                # CliWriter refuses a duplicate before sending anything. The
                # mock reproduces the append so that refusal has something real
                # to prevent.
                self.state.syslog.collectors.append(
                    SyslogCollectorSim(host=address, port=int(port), severity=severity)
                )
                return _ACCEPTED
            if _LOGGING_HOST_NEGATION_RE.match(c):
                return _INVALID  # removal is a subcommand, not a negation
            m = _LOGGING_HOST_REMOVE_RE.match(c)
            if m:
                index = int(m.group(1))
                collectors = self.state.syslog.collectors
                if not 1 <= index <= len(collectors):
                    return _INVALID  # no such row
                del collectors[index - 1]
                return _ACCEPTED
            m = _INTERFACE_RE.match(c)
            if m:
                port = cli_fastpath.port_for_iface(self.state, m.group(1))
                if port is None:
                    return _INVALID  # no such interface on this switch
                self._iface_port = port
                self._modes.append(_INTERFACE)
                return _ACCEPTED
            m = _IP_MGMT_ADDR_RE.match(c)
            if m:
                if not self._uses_ip_management_dialect():
                    return _INVALID  # older images have no "ip management"
                self.state.mgmt.address = m.group(1)
                self.state.mgmt.netmask = m.group(2)
                self.state.mgmt.mode = "static"
                return _ACCEPTED
            m = _IP_GATEWAY_RE.match(c)
            if m:
                if not self._uses_ip_management_dialect():
                    return _INVALID
                self.state.mgmt.gateway = m.group(1)
                return _ACCEPTED
            return None
        if self._mode == _INTERFACE and self._iface_port is not None:
            return self._interface_command(c, self._iface_port)
        return None

    # --- dispatch -----------------------------------------------------------

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
        # Configuration commands (and mode changes) first: a config command is
        # never also a "show" command, and a mis-moded one must be REJECTED
        # rather than silently applied -- that is what proves the writer really
        # entered "vlan database"/"configure" before issuing it.
        handled = self._config_command(c)
        if handled is not None:
            return handled
        # ``show`` commands answer in any mode, exactly as on real hardware.
        if c == self.spec.version_cmd:
            return cli_fastpath.render_version(self.state)
        if c == self.spec.port_status_cmd:
            return cli_fastpath.render_ports(self.state)
        m = _PORT_DESCRIPTION_SHOW_RE.match(c)
        if m:
            return cli_fastpath.render_port_description(self.state, m.group(1))
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
        if c == self.spec.hosts_cmd:
            return cli_fastpath.render_hosts(self.state)
        # Order matters: `show logging hosts` starts with `show logging`, so the
        # longer command must be tested first or it would never be reached.
        if c == self.spec.logging_hosts_cmd:
            return cli_fastpath.render_logging_hosts(self.state)
        if c == self.spec.logging_cmd:
            return cli_fastpath.render_logging(self.state)
        m = _SHOW_VLAN_ID_RE.match(c)
        if m:
            return cli_fastpath.render_vlan_detail(self.state, int(m.group(1)))
        m = _SHOW_IFACE_RE.match(c)
        if m:
            port = cli_fastpath.port_for_iface(self.state, m.group(1))
            if port is None:
                return _INVALID
            return cli_fastpath.render_interface_counters(self.state, port)
        return "Command not found / Incomplete command. Use ? to list commands."

    def close(self) -> None:
        pass
