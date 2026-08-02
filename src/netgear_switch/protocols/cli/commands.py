"""Per-model FASTPATH CLI command specs (pure data).

The CLI equivalent of ``protocols/http/endpoints.py``. Each ``CliModelSpec``
records the ``show`` command each read op issues, the config-mode commands each
VLAN WRITE op issues (see ``cli_write.CliWriter``), the per-model physical
interface-name template every per-port command is addressed by, plus the
session-setup commands (``enable`` + disable output paging), and two honesty
flags:

* ``captured`` -- True only for a model with a REAL captured CLI transcript
  backing its parsers: ``gsm7252ps`` (see ``tests/fixtures/cli/gsm7252ps_*.txt``),
  ``m4300-24x`` (``tests/fixtures/cli/m4300_24x_*.txt``, captured live from
  10.1.5.13 on 2026-07-29), ``m4300-16x`` (``tests/fixtures/cli/m4300_16x_*.txt``,
  captured live from 10.1.5.20 on 2026-07-29) and ``gsm7228ps`` (the S3300-52X;
  ``tests/fixtures/cli/gsm7228ps_*.txt``, captured live from 10.1.5.11 on
  2026-07-30 over telnet on port 60000).
* ``reads_verified`` -- True for gsm7252ps (live CLI-vs-SNMP cross-verified on
  10.1.5.22), m4300-24x (live CLI-verified on 10.1.5.13, 2026-07-29), m4300-16x
  (live CLI-verified on 10.1.5.20, 2026-07-29: ports/PVIDs/VLANs/MACs/LLDP/
  sensors/stats/mgmt-IP AND PoE all correct) and gsm7228ps (live telnet CLI
  captured on 10.1.5.11, 2026-07-30, and cross-verified against that model's SNMP
  capture ``tests/fixtures/captures/gsm7228ps.json``).

FASTPATH's ``show`` grammar is nearly identical across the Fully Managed
(M4300/GSM7252PS) and Smart Managed Pro (GSM7228PS/S3300) lines, but the exact
command set varies by firmware image:

* the newer M4300 firmware (12.0.13.8) renamed two commands -- see
  ``_M4300_OVERRIDES``;
* the Smart-firmware S3300 (gsm7228ps) rejects ``show vlan brief`` ("Invalid
  input") but accepts the bare ``show vlan`` (like the M4300s) while KEEPING the
  older ``show network`` (unlike the M4300s' ``show ip management``) -- see
  ``_GSM7228PS``.

Physical-port naming also differs: the Fully Managed line prints ``1/0/N`` while
the Smart-firmware S3300 prints ``1/gN`` (1-48) and ``1/xgN`` (uplinks 49-52).
Both are resolved by ``protocols.cli.parse._phys_port``.

Transports: SSH is the default network CLI transport, but a model may carry a
non-standard telnet port via ``CliModelSpec.telnet_port`` (the S3300's telnet CLI
listens on 60000, not 23) for models that expose TELNET but not SSH.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, TypedDict

from ...errors import UnsupportedCapabilityError
from ...registry import Backend

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ...registry import SwitchModel

# The three CLI transports all speak the same FASTPATH CLI; a model that has any
# of them uses this spec set.
CLI_BACKENDS = frozenset({Backend.SSH, Backend.TELNET, Backend.CONSOLE})


@dataclass(frozen=True)
class CliModelSpec:
    model_key: str
    captured: bool
    reads_verified: bool
    # True once this model's CLI WRITE path has been driven against the real
    # switch: VLAN create/delete, per-port membership (tagged/untagged/excluded),
    # PVID and port admin state applied and read back, then restored to a
    # byte-identical running-config. Done for all four CLI models on 2026-07-30
    # (see the per-model notes below); PoE additionally on the three PoE SKUs.
    # NOT covered by this flag, and deliberately never live-run: set_mgmt_ip
    # (would drop the very session issuing it) and reboot -- both documented as
    # unverified in ``cli_write.CliWriter``.
    writes_verified: bool = True
    # TCP port the telnet CLI transport dials for this model. Standard telnet is
    # 23, but the S3300-52X (gsm7228ps) FASTPATH telnet CLI listens on 60000.
    # Only consulted when a model's TELNET transport is built (see
    # ``_dispatch.build_sync_cli_client``); the SSH/console transports ignore it.
    telnet_port: int = 23
    # Session setup, run once after the shell opens.
    enable_cmd: str = "enable"
    paging_off_cmd: str = "terminal length 0"
    # Read-op commands. The two templated ones take a positional format arg.
    version_cmd: str = "show version"
    port_status_cmd: str = "show port all"
    vlan_brief_cmd: str = "show vlan brief"
    vlan_detail_cmd: str = "show vlan {vlan}"
    pvid_cmd: str = "show vlan port all"
    mac_table_cmd: str = "show mac-addr-table"
    lldp_cmd: str = "show lldp remote-device all"
    poe_cmd: str = "show poe port info all"
    environment_cmd: str = "show environment"
    network_cmd: str = "show network"
    interface_stats_cmd: str = "show interface ethernet {iface}"
    # Host name. `show hosts` and NOT `show running-config | include hostname`:
    # the two report DIFFERENT values, measured 2026-08-02. On m4300-16x
    # (10.1.5.20) `show hosts` gives "sw-netgear-m4300-16x-poe-s2" while
    # running-config gives "manage-sw-netgear-m4300-16x-poe-s2", and on
    # gsm7252ps (10.1.5.22) running-config carries no hostname line at all while
    # `show hosts` still reports one. `show hosts` is the one that agrees with
    # SNMP's sysName, so it is what keeps the two backends returning the same
    # answer for the same switch.
    hosts_cmd: str = "show hosts"
    # Local login accounts. Present on both FASTPATH images measured; the
    # ACCESS-MODE vocabulary differs between them (see parse.parse_users).
    users_cmd: str = "show users"
    # Management services. `show ip http` covers BOTH web servers; the inbound
    # telnet server is `show telnetcon` and NOT `show telnet`, which reports
    # the switch as an outbound telnet CLIENT (measured 2026-08-02).
    http_service_cmd: str = "show ip http"
    telnet_service_cmd: str = "show telnetcon"
    ssh_service_cmd: str = "show ip ssh"
    # Remote logging. `show syslog` does NOT exist -- all three FASTPATH
    # switches answered "% Invalid input detected" on 2026-08-02.
    logging_cmd: str = "show logging"
    logging_hosts_cmd: str = "show logging hosts"
    # Global-config directive. Quoted on the wire by the device's own
    # running-config output ('hostname "sw-netgear-m4300-24x"').
    hostname_config_cmd: str = "hostname {name}"

    # --- physical-interface naming -----------------------------------------
    # How this model's firmware ADDRESSES one physical port in a command
    # ("show interface ethernet <iface>", "interface <iface>"). The Fully
    # Managed FASTPATH line uses "1/0/<n>"; the Smart-firmware S3300-52X
    # (gsm7228ps) uses "1/g<n>" for its 48 1G ports and "1/xg<n>" for the four
    # 10G uplinks 49-52 -- both live-confirmed in that model's own captured
    # transcripts (tests/fixtures/cli/gsm7228ps_port_all.txt lists "1/g1"...,
    # gsm7228ps_vlan_port_all.txt lists "1/xg49"...). Reading these names back
    # is already handled by ``protocols.cli.parse._phys_port``; this is the
    # WRITE direction (and the per-port read commands), which previously
    # hardcoded "1/0/<port>" and would therefore have addressed a nonexistent
    # interface on the S3300.
    iface_template: str = "1/0/{port}"
    # Set together on a model whose uplinks carry a DIFFERENT prefix than its
    # access ports (the S3300-52X). None/None means "one template for all
    # ports", which is true of every Fully Managed model.
    uplink_iface_template: str | None = None
    first_uplink_port: int | None = None

    # --- write (config-mode) commands --------------------------------------
    # GROUNDED PER MODEL, not extrapolated from one SKU: the VLAN sequences were
    # driven BY HAND on an M4300-24X (FASTPATH 12.0.13.8, 10.1.5.13, 2026-07-30)
    # and every command below was then confirmed against each reachable switch's
    # OWN context-sensitive help ("<partial> ?", read-only -- the line is
    # abandoned, never submitted) on 2026-07-30:
    #   gsm7252ps  10.1.5.22 (SSH, XE image)
    #   m4300-24x  10.1.5.13 (12.0.13.8)
    #   m4300-16x  10.1.5.20 (12.0.19.15)
    #   gsm7228ps  10.1.5.11 (S3300-52X Smart image, telnet 60000)
    # The differences that came out of that sweep are recorded in the per-model
    # specs below -- they are exactly the kind of thing extrapolating from one
    # SKU gets wrong.
    vlan_database_cmd: str = "vlan database"
    vlan_create_cmd: str = "vlan {vlan}"
    vlan_name_cmd: str = "vlan name {vlan} {name}"
    vlan_delete_cmd: str = "no vlan {vlan}"
    configure_cmd: str = "configure"
    interface_cmd: str = "interface {iface}"
    # A port only HONOURS "vlan participation"/"vlan tagging" while it is in
    # general mode (proven live on the M4300: in access mode the commands are
    # accepted into running-config yet ``show vlan <id>`` keeps reporting
    # Exclude/Autodetect). None means this image has NO switchport-mode concept
    # at all and the participation commands act directly -- the case on the
    # gsm7252ps, whose "switchport mode ?" answers "% Unrecognized command"
    # (its "switchport ?" offers only private-group/protected).
    switchport_general_cmd: str | None = "switchport mode general"
    vlan_participation_cmd: str = "vlan participation {action} {vlan}"
    vlan_tagging_cmd: str = "vlan tagging {vlan}"
    vlan_no_tagging_cmd: str = "no vlan tagging {vlan}"
    vlan_pvid_cmd: str = "vlan pvid {vlan}"
    exit_cmd: str = "exit"
    # PoE, in interface config mode. Identical on every PoE-capable FASTPATH
    # image probed ("poe ?" -> <cr>/detection/high-power/power/priority/reset/
    # timer). "poe reset" is the device's OWN atomic PoE re-arm -- preferred over
    # off-then-on because no crash window can leave a port powered down.
    poe_enable_cmd: str = "poe"
    poe_disable_cmd: str = "no poe"
    poe_reset_cmd: str = "poe reset"
    # Port admin state, in interface config mode (identical on all four).
    port_enable_cmd: str = "no shutdown"
    port_disable_cmd: str = "shutdown"
    # Management IP. TWO DIALECTS, and the split is real:
    #  * older images (gsm7252ps, gsm7228ps) take ONE privileged-EXEC command,
    #    "network parms <ip> <mask> [<gateway>]" -- the write counterpart of
    #    their "show network" read;
    #  * the M4300 12.0.x images REJECT "network parms" outright ("%
    #    Unrecognized command", in both EXEC and Config mode) and instead use
    #    global-config "ip management address <ip> <mask>" plus
    #    "ip default-gateway <gw>" -- matching their "show ip management" read.
    # Exactly one of the two tuples is non-empty per model.
    mgmt_ip_exec_cmds: tuple[str, ...] = (
        "network parms {address} {netmask} {gateway}",
    )
    mgmt_ip_config_cmds: tuple[str, ...] = ()
    # Reboot, privileged EXEC ("reload ?" -> <cr>/<unit> on every model).
    reload_cmd: str = "reload"

    def vlan_detail(self, vlan: int) -> str:
        return self.vlan_detail_cmd.format(vlan=vlan)

    def iface(self, port: int) -> str:
        """The interface NAME this firmware addresses physical ``port`` by."""
        if (
            self.uplink_iface_template is not None
            and self.first_uplink_port is not None
            and port >= self.first_uplink_port
        ):
            return self.uplink_iface_template.format(port=port)
        return self.iface_template.format(port=port)

    def interface_stats(self, port: int) -> str:
        return self.interface_stats_cmd.format(iface=self.iface(port))

    def vlan_create(self, vlan: int) -> str:
        return self.vlan_create_cmd.format(vlan=vlan)

    def vlan_name(self, vlan: int, name: str) -> str:
        return self.vlan_name_cmd.format(vlan=vlan, name=name)

    def vlan_delete(self, vlan: int) -> str:
        return self.vlan_delete_cmd.format(vlan=vlan)

    def interface(self, port: int) -> str:
        return self.interface_cmd.format(iface=self.iface(port))

    def vlan_participation(self, vlan: int, *, include: bool) -> str:
        return self.vlan_participation_cmd.format(
            action="include" if include else "exclude", vlan=vlan
        )

    def vlan_tagging(self, vlan: int, *, tagged: bool) -> str:
        cmd = self.vlan_tagging_cmd if tagged else self.vlan_no_tagging_cmd
        return cmd.format(vlan=vlan)

    def vlan_pvid(self, vlan: int) -> str:
        return self.vlan_pvid_cmd.format(vlan=vlan)

    def poe_admin(self, *, on: bool) -> str:
        return self.poe_enable_cmd if on else self.poe_disable_cmd

    def port_admin(self, *, enabled: bool) -> str:
        return self.port_enable_cmd if enabled else self.port_disable_cmd

    def mgmt_ip(
        self, address: str, netmask: str, gateway: str
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """``(exec_commands, config_commands)`` for a management-IP write.

        Exactly one of the two is non-empty, per this model's dialect (see the
        ``mgmt_ip_*`` fields).
        """
        fmt = {"address": address, "netmask": netmask, "gateway": gateway}
        return (
            tuple(c.format(**fmt) for c in self.mgmt_ip_exec_cmds),
            tuple(c.format(**fmt) for c in self.mgmt_ip_config_cmds),
        )


class _CliCmdOverrides(TypedDict, total=False):
    """The subset of ``CliModelSpec`` command fields a model may override
    (typed so ``**`` splatting into ``CliModelSpec`` cannot touch
    ``telnet_port`` or any other int field)."""

    vlan_brief_cmd: str
    network_cmd: str
    mgmt_ip_exec_cmds: tuple[str, ...]
    mgmt_ip_config_cmds: tuple[str, ...]


# M4300 FASTPATH 12.0.13.8 renamed two read commands vs the older gsm7252ps
# image (live-confirmed on 10.1.5.13):
#   "show vlan brief" -> "show vlan"          ("show vlan brief" is Invalid input)
#   "show network"    -> "show ip management" ("show network" deprecated)
# The output formats are otherwise the same fixed-width tables/dotted-leader
# scalars, so the existing parse_vlan_brief/parse_mgmt_ip parsers apply unchanged.
# The management-IP WRITE moved with the read: this image has no "network parms"
# at all (verified 2026-07-30 -- "% Unrecognized command" in both privileged
# EXEC and global config on 10.1.5.20), and uses the global-config pair
# "ip management address <ip> <mask>" + "ip default-gateway <gw>" instead
# ("ip management address 10.1.5.20 ?" -> </prefix-length>|<subnet-mask>;
# "ip default-gateway ?" -> <gateway-addr>).
_M4300_OVERRIDES: _CliCmdOverrides = {
    "vlan_brief_cmd": "show vlan",
    "network_cmd": "show ip management",
    "mgmt_ip_exec_cmds": (),
    "mgmt_ip_config_cmds": (
        "ip management address {address} {netmask}",
        "ip default-gateway {gateway}",
    ),
}

# gsm7252ps: real captured transcript (SSH, 10.1.5.22).
# reads_verified=True: live CLI<->SNMP cross-verified 2026-07-25 on 10.1.5.22.
# switchport_general_cmd=None: this XE image has NO switchport-mode concept --
# probed live 2026-07-30 on 10.1.5.22, "switchport mode ?" answers
# "% Unrecognized command" and "switchport ?" offers only
# private-group/protected. Sending "switchport mode general" here would be
# REJECTED (non-empty output = failure), so the writer must not send it; its
# "vlan participation"/"vlan tagging" commands act on the port directly.
# writes_verified=True: full CLI write run on 10.1.5.22 2026-07-30 against
# link-down, undescribed port 1/0/6 -- create VLAN 4001, tag/untag/exclude the
# port, set + restore its PVID, shutdown + no shutdown, delete the VLAN; the
# port's running-config, PVID and (tagged) VLAN 1+5 membership all came back
# byte-identical, with NO switchport-mode command issued.
_GSM7252PS = CliModelSpec(
    model_key="gsm7252ps",
    captured=True,
    reads_verified=True,
    switchport_general_cmd=None,
)

# m4300-24x: real captured transcript (10.1.5.13, tests/fixtures/cli/m4300_24x_*).
# reads_verified=True: live CLI-verified 2026-07-29 on 10.1.5.13 (M4300-24X,
# FASTPATH 12.0.13.8) -- ports/pvids/vlans/macs/lldp/sensors/stats/mgmt-IP all
# correct with the two command overrides above.
# writes_verified=True: full CLI write run on 10.1.5.13 2026-07-30 against
# link-down port 1/0/8 (description 'empty') -- VLAN 4001 created, port tagged
# then untagged then excluded, PVID set and restored, shutdown/no shutdown, VLAN
# deleted; running-config, PVID and VLAN 1 untagged membership byte-identical
# afterwards. PoE is absent on this SKU (see cli_write._require_poe).
_M4300_24X = CliModelSpec(
    model_key="m4300-24x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
# m4300-16x: real captured transcript (tests/fixtures/cli/m4300_16x_*).
# reads_verified=True: live CLI-verified 2026-07-29 on 10.1.5.20 (M4300-16X-PoE,
# FASTPATH 12.0.19.15) -- ports/pvids/vlans/macs/lldp/sensors/stats/mgmt-IP AND
# `show poe port info all` (16 PoE ports; the M4300 image omits the Temperature
# column, handled by the header-name column lookup in parse_poe) all correct.
# writes_verified=True: full CLI write run on 10.1.5.20 2026-07-30 against
# link-down port 1/0/1 -- VLAN/membership/PVID/port-admin as above PLUS PoE
# ("no poe" then "poe", both verified) and cycle_poe honestly failing on a port
# with no powered device. This run is also where two hardware facts came from:
# the PoE status column LAGS an admin re-enable by a read, and "no switchport
# mode" (not "switchport mode access") is what restores a port's prior
# behaviour. Restored to a byte-identical running-config.
_M4300_16X = CliModelSpec(
    model_key="m4300-16x", captured=True, reads_verified=True, **_M4300_OVERRIDES
)
# gsm7228ps (the S3300-52X): real captured telnet transcript (10.1.5.11, port
# 60000, tests/fixtures/cli/gsm7228ps_*.txt). reads_verified=True: live telnet
# CLI captured 2026-07-30 and cross-verified against the model's SNMP capture.
# This SKU's Smart firmware needs the bare "show vlan" (the M4300-style override;
# "show vlan brief" is "Invalid input" here) but keeps the older "show network"
# (NOT the M4300's "show ip management"), so it takes exactly one of the two
# _M4300_OVERRIDES. Its telnet CLI listens on 60000, not 23 (SSH is genuinely
# absent -- no listener on any port; the registry declares TELNET but not SSH).
# Unlike the gsm7252ps (the other pre-12.0 image here) this Smart firmware DOES
# have switchport modes -- "switchport mode ?" -> access|general|trunk, probed
# live 2026-07-30 on 10.1.5.11 -- so it keeps the default general-mode step. Its
# management-IP write is the older privileged-EXEC "network parms <ip> <mask>
# [<gateway>]" (probed: "network parms 10.1.5.22 255.255.255.0 ?" -> <cr>|
# <gateway>), i.e. the default, matching its "show network" read.
# Its ports are ALSO named differently: "1/g1".."1/g48" for the 48 1G ports and
# "1/xg49".."1/xg52" for the four 10G uplinks (both shapes appear verbatim in
# this model's own captured transcripts), so every per-port command -- the
# read-side "show interface ethernet <iface>" as well as the write-side
# "interface <iface>" -- must be addressed that way, NOT as "1/0/<n>".
# writes_verified=True: full CLI write run on 10.1.5.11 2026-07-30 over telnet
# 60000 against link-down port 1/g1 -- VLAN 4001 create/tag/untag/exclude/delete,
# PVID 21 -> 4001 -> 21, shutdown/no shutdown, PoE off/on, cycle_poe honestly
# failing with no PD; the port's running-config (including its "vlan pvid 21 /
# vlan participation auto 1 / include 21 / green-mode" lines) came back
# byte-identical. This is the run that proves the "1/g<n>" write addressing.
_GSM7228PS = CliModelSpec(
    model_key="gsm7228ps",
    captured=True,
    reads_verified=True,
    telnet_port=60000,
    vlan_brief_cmd="show vlan",
    network_cmd="show network",
    iface_template="1/g{port}",
    uplink_iface_template="1/xg{port}",
    first_uplink_port=49,
)

_SPECS: dict[str, CliModelSpec] = {
    s.model_key: s for s in (_GSM7252PS, _M4300_24X, _M4300_16X, _GSM7228PS)
}

CLI_SPECS: Mapping[str, CliModelSpec] = MappingProxyType(_SPECS)


@dataclass(frozen=True)
class ScpCertProfile:
    """Per-model FASTPATH SSL-cert-over-SCP deploy profile (pure data).

    A TRANSCRIPTION of the working certbot-hook ``MODEL_PROFILES`` (see
    ``tmp/certbot_hook_prior_art.py`` -- grounded prior art). Only the Fully
    Managed FASTPATH models that take a certificate over ``copy scp://`` carry
    one; the Smart Managed Pro line (gsm7228ps/S3300) uses an HTTP multipart
    upload instead and is deliberately absent here.

    * ``crypto`` -- ``"modern"`` or ``"legacy"``: which SSH key-exchange /
      host-key algorithm set the switch's sshd needs. The library's SSH transport
      already re-inserts the legacy algorithms this old firmware requires (see
      ``transport/cli/ssh.py``); this flag is carried for the CALLER (e.g. the
      certbot hook) that stages the PEM and may open its own SCP source.
    * ``writemem_stuff`` -- True when ``write memory``'s confirm has a tiny
      timeout, so the ``y`` must be pre-stuffed in one write (GSM7252PS); False
      for the M4300s, which take a normal read-then-answer confirm.
    * ``verify_port`` -- the HTTPS port a post-deploy fingerprint check connects
      to. NOT used by the deploy itself (the library only SENDS the copy
      commands; verification is the caller's job), carried for parity with the
      prior art so a caller need not re-derive it.
    """

    model_key: str
    crypto: str
    writemem_stuff: bool
    verify_port: int


# GROUNDED: transcribed from certbot-hook MODEL_PROFILES. NOT live-verified in
# this library (a real SCP upload is a production write needing a staging SCP
# server) -- see ``cli_write.deploy_certificate_scp``.
_SCP_CERT_PROFILES: dict[str, ScpCertProfile] = {
    p.model_key: p
    for p in (
        ScpCertProfile(
            "m4300-24x", crypto="modern", writemem_stuff=False, verify_port=443
        ),
        ScpCertProfile(
            "m4300-16x", crypto="modern", writemem_stuff=False, verify_port=49152
        ),
        ScpCertProfile(
            "gsm7252ps", crypto="legacy", writemem_stuff=True, verify_port=443
        ),
    )
}

SCP_CERT_PROFILES: Mapping[str, ScpCertProfile] = MappingProxyType(_SCP_CERT_PROFILES)


def scp_cert_profile(model: SwitchModel) -> ScpCertProfile:
    """Return the FASTPATH SCP cert-deploy profile for ``model``.

    Raises ``UnsupportedCapabilityError`` for any model with no ``copy scp://``
    cert-deploy path -- i.e. every non-FASTPATH model, AND FASTPATH models whose
    cert upload uses a different mechanism (gsm7228ps: HTTP multipart). This is
    the gate the facade's ``upload_certificate_scp`` dispatches on.
    """
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no CLI backend for an SCP cert deploy"
        )
    try:
        return _SCP_CERT_PROFILES[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no known copy-scp SSL-certificate deploy profile"
        ) from None


def cli_spec(model: SwitchModel) -> CliModelSpec:
    """Return the CLI command spec for ``model`` or raise if it has no CLI backend."""
    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(f"model {model.key!r} has no CLI backend")
    try:
        return _SPECS[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has a CLI backend but no command spec"
        ) from None
