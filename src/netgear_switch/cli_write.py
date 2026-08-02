"""Model-driven FASTPATH CLI write/control over a ``CliSession``.

Two write paths live here:

* ``CliWriter`` -- the VLAN write backend (create/delete a VLAN, set a port's
  membership, set a port's PVID) over the config-mode CLI. The CLI analogue of
  ``snmp_write.SnmpWriter``/``http_write.HttpWriter``: every write is followed by
  a read-back through ``cli_read.CliReader`` and raises ``WriteVerificationError``
  (carrying before/after) on divergence, never a silent success.
* ``deploy_certificate_scp`` -- the SSL-certificate deploy over ``copy scp://``,
  for the Fully Managed FASTPATH line (M4300 / GSM7252PS) whose firmware takes an
  HTTPS server certificate over SCP rather than an HTTP form.

Both REUSE the library's existing CLI transport: plain commands go through
``CliSession.run``; the interactive ``copy`` and ``write memory`` steps go through
``CliSession.run_scp_copy`` / ``run_write_memory`` (the byte-level interactive
driving lives on the shared ``ShellDriver`` -- no new transport). There is no
async twin: all three CLI transports (paramiko SSH, telnet, pyserial console) are
synchronous, so ``AsyncSwitch`` has no CLI backend at all.

HONESTY, per path:

* ``CliWriter`` is LIVE-VERIFIED on all four CLI models (2026-07-30), each on a
  link-down, undescribed port and each restored to a byte-identical
  running-config with its PVID and VLAN membership unchanged and the throwaway
  VLAN 4001 deleted:

  =========== ========== ==============================================
  model       host       ops driven through this module
  =========== ========== ==============================================
  gsm7252ps   10.1.5.22  VLAN create/tag/untag/exclude/delete, PVID, port admin
  m4300-24x   10.1.5.13  same (no PoE hardware on this SKU)
  m4300-16x   10.1.5.20  same + PoE off/on + cycle_poe
  gsm7228ps   10.1.5.11  same + PoE off/on + cycle_poe (telnet 60000, "1/g<n>")
  =========== ========== ==============================================

  ``set_mgmt_ip`` and ``reboot`` are the two deliberate exceptions: their command
  syntax is confirmed from each device's own help output, but neither was
  executed -- a mgmt-IP change drops the very session issuing it and a reboot
  would interrupt production traffic. Both say so at the method.
* The cert deploy is GROUNDED in the working certbot-hook ``FastpathScpUpdater``
  (see ``tmp/certbot_hook_prior_art.py``) and MOCK-TESTED end-to-end, but NOT
  live-verified -- a real run is a production write that needs a staging SCP
  server to pull the PEM from, which CI has neither the hardware nor the network
  for. The library only SENDS the copy commands; the CALLER stages the PEM on the
  SCP source first (per the user's decision), exactly as the certbot hook's
  ``main`` does.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from .cli_read import CliReader
from .errors import (
    CliCommandError,
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .models import PoEDetect, VlanMode
from .protocols.cli.commands import cli_spec
from .snmp_write import PoeCycleTimeouts
from .transport.cli.session import CliTransportError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .models import PoEStatus, PortStatus, VLANInfo
    from .registry import SwitchModel
    from .transport.cli.session import CliSession

# Same PoE polling deadlines the SNMP writer uses (design spec §6); tests inject
# tiny values so a cycle finishes instantly against the mock.
_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()

# nvram: destinations FASTPATH loads the HTTPS material from (grounded prior art).
_SERVER_DEST = "nvram:sslpem-server"
_ROOT_DEST = "nvram:sslpem-root"
_SERVER_SUFFIX = "-server.pem"
_ROOT_SUFFIX = "-root.pem"
_WRITE_MEMORY = "write memory"
# FASTPATH refuses the sslpem upload while the HTTP secure-server is enabled
# ("HTTP Secure-server must be disabled prior to upgrade"), so disable -> copy ->
# re-enable. Re-enabling loads the new cert in place; NO reboot (backbone-safe).
_HTTPS_OFF = "no ip http secure-server"
_HTTPS_ON = "ip http secure-server"


def scp_source_url(scp_source: str, remote_dir: str, filename: str) -> str:
    """Build the ``scp://`` source URL for one staged PEM.

    Mirrors ``FastpathScpUpdater._source_url``: an ABSOLUTE staging path so
    FASTPATH's scp client requests the exact path the SCP source's ForceCommand
    wrapper authorises (no home-relative ambiguity). ``scp_source`` is the
    ``user@host[:port]`` the caller's staging server answers on.
    """
    return f"scp://{scp_source}{remote_dir}/{filename}"


def _copy_cmd(scp_source: str, remote_dir: str, filename: str, dest: str) -> str:
    return f"copy {scp_source_url(scp_source, remote_dir, filename)} {dest}"


def deploy_certificate_scp(
    session: CliSession,
    *,
    scp_source: str,
    scp_password: str,
    remote_dir: str,
    base: str,
    chain: bool,
    writemem_stuff: bool,
) -> None:
    """Run the 5-step FASTPATH cert-deploy EXEC sequence over ``session``.

    ``session`` must already be set up (enable + paging off -- the transport does
    this on connect). The staged PEMs are named ``<base>-server.pem`` (and, when
    ``chain`` is set, ``<base>-root.pem``) under ``remote_dir`` on the SCP source.

    Steps (grounded in ``FastpathScpUpdater.upload_certificate``):

    1. ``no ip http secure-server`` -- HTTPS must be off to accept the sslpem.
    2. ``copy scp://<src>/<base>-server.pem nvram:sslpem-server`` (interactive).
    3. optional ``copy scp://<src>/<base>-root.pem nvram:sslpem-root`` (CA chain).
    4. ``ip http secure-server`` -- re-enable; loads the new cert, no reboot.
    5. ``write memory`` -- persist, with the per-model confirm (``writemem_stuff``).
    """
    session.run(_HTTPS_OFF)
    session.run_scp_copy(
        _copy_cmd(scp_source, remote_dir, f"{base}{_SERVER_SUFFIX}", _SERVER_DEST),
        scp_password,
    )
    if chain:
        session.run_scp_copy(
            _copy_cmd(scp_source, remote_dir, f"{base}{_ROOT_SUFFIX}", _ROOT_DEST),
            scp_password,
        )
    session.run(_HTTPS_ON)
    session.run_write_memory(_WRITE_MEMORY, prestuff=writemem_stuff)


class CliWriter:
    """Synchronous FASTPATH-CLI write facade over one switch.

    Offers the SAME write surface as ``SnmpWriter``/``HttpWriter`` -- VLAN
    lifecycle, per-port membership and PVID, PoE admin/cycle/fault-clear, port
    admin state, the management IP and reboot -- because the point of several
    backends is that the CALLER chooses one (CLAUDE.md principle 2). Every
    command is carried per model in ``protocols.cli.commands.CliModelSpec`` and
    was confirmed against each reachable switch's own context-sensitive help on
    2026-07-30 (gsm7252ps 10.1.5.22, m4300-24x 10.1.5.13, m4300-16x 10.1.5.20,
    gsm7228ps/S3300 10.1.5.11), so the S3300's ``1/g<n>``/``1/xg<n>`` interface
    naming, the M4300's ``ip management address`` and the gsm7252ps's ABSENT
    ``switchport mode`` are each handled as that firmware really behaves.

    VLAN command sequences, PROVEN BY HAND on the M4300-24X before being encoded:

    * create -- ``vlan database`` / ``vlan <vid>`` / ``vlan name <vid> <name>`` /
      ``exit``
    * delete -- ``vlan database`` / ``no vlan <vid>`` / ``exit``
    * membership -- ``configure`` / ``interface <iface>`` / ``switchport mode general``
      then either ``vlan participation include <vid>`` plus
      ``vlan tagging <vid>`` (TAGGED) or ``no vlan tagging <vid>`` (UNTAGGED),
      or ``vlan participation exclude <vid>`` (EXCLUDED) / ``exit`` / ``exit``
    * PVID -- ``configure`` / ``interface <iface>`` / ``switchport mode general`` /
      ``vlan pvid <vid>`` / ``exit`` / ``exit``

    Other ops, per model (all four confirmed from the devices' own help):

    * PoE -- ``configure`` / ``interface <iface>`` / ``poe`` | ``no poe`` |
      ``poe reset`` / ``exit`` / ``exit``
    * port admin -- ``no shutdown`` | ``shutdown`` in interface config mode
    * management IP -- privileged-EXEC ``network parms <ip> <mask> <gw>``
      (gsm7252ps, gsm7228ps) or global-config ``ip management address <ip>
      <mask>`` + ``ip default-gateway <gw>`` (M4300 12.0.x, which has no
      ``network parms``)
    * reboot -- privileged-EXEC ``reload`` with its ``(y/n)`` confirm

    THE SWITCHPORT-MODE FINDING (why ``switchport mode general`` is sent first):
    on real hardware the ``vlan participation``/``vlan tagging`` commands are
    accepted into running-config while the port is in ``switchport mode access``
    but stay completely INERT -- ``show vlan <vid>`` keeps reporting
    ``Exclude/Autodetect`` for that port. They only take effect in
    ``switchport mode general``. This was proven by before/after
    ``show running-config interface 1/0/4`` + ``show vlan 4007`` on 10.1.5.13. So
    every per-port VLAN op ensures general mode first (idempotent: re-issuing it
    on an already-general port is a no-op). That is a deliberate, unavoidable
    side effect of a CLI membership write and is why the mock reproduces the
    inert behaviour too (``virtual.faces.cli``). The gsm7252ps XE image is the
    exception -- it has no ``switchport mode`` command at all, so the step is
    omitted there rather than being rejected (see ``_general_mode``).

    CONSEQUENCE WORTH KNOWING (measured on 10.1.5.20 while live-verifying this
    backend): a port moved to general mode stops honouring any
    ``switchport access vlan`` / ``switchport trunk native vlan`` lines that were
    sitting INERT in its config, and later sending ``switchport mode access``
    ACTIVATES them -- leaving the port in a different state than it started in
    (its PVID jumped from 1 to the configured access VLAN 10). The command that
    genuinely restores the prior behaviour is ``no switchport mode``, verified
    live: it removes the mode line and the port went back to PVID 1 / VLAN 1
    untagged with a byte-identical running-config.

    Two further deliberate behaviours:

    * FASTPATH answers an ACCEPTED configuration command with EMPTY output, so any
      text back (``% Invalid input``, ``ERROR: ...``) is treated as a failure and
      raised as ``CliCommandError`` -- never swallowed.
    * NOTHING is persisted: no ``write memory`` is issued, so these writes change
      the running config only, exactly like this library's SNMP/HTTP VLAN writes.
      A caller that wants them to survive a reboot must save separately.
    """

    def __init__(
        self,
        session: CliSession,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        # Raises UnsupportedCapabilityError for a model with no CLI backend, or
        # one with a CLI backend but no command spec -- exactly like CliReader.
        self._spec = cli_spec(model)
        self.session = session
        self.model = model
        self.protected_ports = protected_ports
        # Verification reads go back through the SAME session and the same
        # reader/parsers a plain read uses, so a write is only "done" once the
        # switch's own ``show`` output agrees.
        self._reader = CliReader(session, model)

    # --- helpers ------------------------------------------------------------

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    def _run(self, command: str) -> None:
        """Issue one configuration command, treating ANY output as failure."""
        out = self.session.run(command).strip()
        if out:
            raise CliCommandError(f"CLI rejected {command!r}: {out}")

    def _in_mode(self, enter: Sequence[str], body: Sequence[str]) -> None:
        """Run ``body`` inside the config mode ``enter`` descends into.

        Always unwinds with one ``exit`` per level actually entered, even when a
        body command is rejected -- otherwise a failed write would leave the
        shared session parked in ``(Config)(Interface 1/0/4)#`` and every
        subsequent read (including this write's own verification) would run in
        the wrong mode. The unwind uses the raw session, not ``_run``: an error
        while backing out must not mask the real failure.
        """
        entered = 0
        try:
            for command in enter:
                self._run(command)
                entered += 1
            for command in body:
                self._run(command)
        finally:
            for _ in range(entered):
                self.session.run(self._spec.exit_cmd)

    def _general_mode(self) -> list[str]:
        """The ``switchport mode general`` prelude, or nothing on an image that
        has no switchport modes.

        The M4300 (12.0.x) and the S3300 both need it -- their per-port VLAN
        commands are inert in access mode. The gsm7252ps XE image has no
        ``switchport mode`` command at all (proven live: "% Unrecognized
        command"), so sending it there would be REJECTED, not merely redundant.
        """
        cmd = self._spec.switchport_general_cmd
        return [] if cmd is None else [cmd]

    def _vlan(self, vlan: int) -> VLANInfo | None:
        """This VLAN as the CLI reader sees it, or None if the switch has no
        such VLAN (``show vlan brief`` does not list it)."""
        return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)

    def _port_mode(self, info: VLANInfo | None, port: int) -> VlanMode:
        """How ``port`` currently participates in the VLAN ``info`` describes."""
        if info is None or port not in info.member_ports:
            return VlanMode.EXCLUDED
        return VlanMode.TAGGED if port in info.tagged_ports else VlanMode.UNTAGGED

    # --- VLAN lifecycle -----------------------------------------------------

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        """Create VLAN ``vlan`` named ``name`` (``vlan database`` sequence).

        Creating an EMPTY VLAN adds no port membership, so it is non-disruptive
        and needs no ``force``; the parameter exists for signature symmetry with
        ``delete_vlan`` (mirroring ``SnmpWriter.create_vlan``). ``name`` goes on
        the wire as a bare token -- FASTPATH's ``vlan name`` takes no spaces, and
        a name it rejects surfaces as ``CliCommandError`` rather than being
        silently mangled.
        """
        del force
        before = self._vlan(vlan)
        self._in_mode(
            [self._spec.vlan_database_cmd],
            [self._spec.vlan_create(vlan), self._spec.vlan_name(vlan, name)],
        )
        after = self._vlan(vlan)
        if after is None or (after.name or "") != name:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created with name {name!r}",
                before=before,
                after=after,
            )

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        """Delete VLAN ``vlan`` (``vlan database`` / ``no vlan <vid>``).

        Refuses up front if the VLAN does not exist (a precondition failure, NOT
        a verification divergence -- no command has been sent yet, mirroring
        ``SnmpWriter.delete_vlan``), and refuses without ``force`` when the VLAN
        still carries a protected port, since deleting it strips that port's
        membership.
        """
        before = self._vlan(vlan)
        if before is None:
            raise CliCommandError(f"VLAN {vlan} does not exist")
        if not force:
            clash = before.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway"
                )
        self._in_mode([self._spec.vlan_database_cmd], [self._spec.vlan_delete(vlan)])
        after = self._vlan(vlan)
        if after is not None:
            raise WriteVerificationError(
                f"VLAN {vlan} still exists after {self._spec.vlan_delete(vlan)!r}",
                before=before,
                after=after,
            )

    # --- per-port VLAN ops --------------------------------------------------

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        """Set ``port``'s participation in ``vlan`` to ``mode``.

        Verifies the TARGET PORT's participation only, deliberately: unlike the
        SNMP writer -- which SETs whole egress/untagged PortList bitmaps and so
        must verify both bitmaps in full -- these commands address exactly one
        interface, and forcing general mode can legitimately move that port's
        membership in OTHER VLANs (its former access VLAN), which is not this
        VLAN's business.
        """
        self._guard(port, force)
        before = self._vlan(vlan)
        if before is None:
            # Precondition failure: no command sent yet, so this is not a
            # verification divergence (mirrors SnmpWriter.set_vlan_membership).
            raise CliCommandError(f"VLAN {vlan} does not exist")
        body = self._general_mode()
        if mode is VlanMode.EXCLUDED:
            body.append(self._spec.vlan_participation(vlan, include=False))
        else:
            body.append(self._spec.vlan_participation(vlan, include=True))
            body.append(self._spec.vlan_tagging(vlan, tagged=mode is VlanMode.TAGGED))
        self._in_mode([self._spec.configure_cmd, self._spec.interface(port)], body)
        after = self._vlan(vlan)
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before,
                after=after,
            )
        got = self._port_mode(after, port)
        if got is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value} "
                f"(got {got.value})",
                before=self._port_mode(before, port),
                after=got,
            )

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        """Set ``port``'s ingress PVID to ``vlan`` (``vlan pvid <vid>``).

        Changing a port's PVID re-homes its untagged traffic, so it is
        disruptive and honours ``protected_ports`` (mirroring
        ``SnmpWriter.set_pvid``). ``switchport mode general`` is sent first for
        the same reason as ``set_vlan_membership``: in access mode the port's
        PVID follows its access VLAN, so ``vlan pvid`` cannot take effect.

        Refuses up front if the VLAN does not exist, exactly as
        ``set_vlan_membership`` does -- a precondition failure, so no command is
        sent. This used to be left to the switch, on the assumption it would
        reject the command. That assumption does not hold generally: MEASURED on
        a GS728TPP (10.2.5.10, firmware 6.0.1.30), the equivalent write is
        ACCEPTED and reads back, leaving the port pointing at a VLAN that is not
        there -- which no amount of verify-after-write can catch.
        """
        self._guard(port, force)
        if not any(v.vlan_id == vlan for v in self._reader.get_vlans()):
            raise CliCommandError(f"VLAN {vlan} does not exist")
        before = dict(self._reader.get_pvids())
        self._in_mode(
            [self._spec.configure_cmd, self._spec.interface(port)],
            [*self._general_mode(), self._spec.vlan_pvid(vlan)],
        )
        after = dict(self._reader.get_pvids())
        if after.get(port) != vlan:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan} "
                f"(got {after.get(port)})",
                before=before.get(port),
                after=after.get(port),
            )

    # --- PoE ----------------------------------------------------------------

    def _poe_status(self, port: int) -> PoEStatus | None:
        return next((p for p in self._reader.get_poe() if p.port == port), None)

    def _require_poe(self) -> None:
        """Refuse PoE ops on a model with NO PSE hardware.

        Not a CLI limitation and not an unimplemented op: the M4300-24X has no
        PoE ports (registry ``poe_port_count`` 0) and its firmware therefore
        does not carry the command at all -- probed live 2026-07-30 on 10.1.5.13,
        where ``poe ?`` in interface config mode answers::

            poe ?
            % Unrecognized command

        while the PoE-equipped M4300-16X on 10.1.5.20 answers with the full
        ``<cr>/detection/high-power/power/priority/reset/timer`` help. Same
        carve-out ``CliReader.get_poe`` already makes for reads.
        """
        if self.model.poe_port_count == 0:
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} has no PSE ports, so its firmware has "
                "no 'poe' command (verified live: 'poe ?' -> '% Unrecognized "
                "command')"
            )

    def set_poe(
        self,
        port: int,
        on: bool,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Enable/disable PoE on ``port`` (``poe`` / ``no poe``).

        Verified through ``show poe port info all``, whose Status column reads
        ``Disabled`` for an admin-off port -- that command has NO admin column, so
        admin state is read from Status (see ``parse.parse_poe``).

        The read-back POLLS, and that is not defensive padding: Status is a
        DETECTION state, so it lags the admin write. Measured on the real
        M4300-16X (10.1.5.20, FASTPATH 12.0.19.15, 2026-07-30): immediately after
        ``poe`` re-enabled port 1/0/1 the table still said ``Disabled``, and the
        same port read ``Searching`` (admin enabled) moments later. A single
        immediate read therefore reported a WORKING write as a verification
        failure. Disabling is observable at once, but the same polled check
        covers both directions. ``sleep``/``clock`` are injectable so tests do
        not wait.
        """
        self._require_poe()
        if not on:
            self._guard(port, force)  # turning PoE off is disruptive
        limits = timeouts or _DEFAULT_POE_TIMEOUTS
        before = self._poe_status(port)
        self._in_mode(
            [self._spec.configure_cmd, self._spec.interface(port)],
            [self._spec.poe_admin(on=on)],
        )
        deadline = clock() + (limits.off_timeout if not on else limits.on_timeout)
        while True:
            after = self._poe_status(port)
            if after is not None and after.admin_enabled == on:
                return
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE admin for port {port} did not read back as {on}",
                    before=before,
                    after=after,
                )
            sleep(limits.poll_interval)

    def _poe_reset(
        self,
        port: int,
        *,
        timeouts: PoeCycleTimeouts,
        sleep: Callable[[float], None],
        clock: Callable[[], float],
        recovered: Callable[[PoEStatus | None], bool],
        timeout_message: str,
    ) -> None:
        """Issue the device's own ``poe reset`` and POLL until ``recovered``.

        One command, not off-then-on: FASTPATH exposes ``poe reset`` precisely to
        re-arm a PSE port atomically (it is what the web UI's reset button does),
        so no failure between two commands can leave the port powered down. The
        polling contract matches ``SnmpWriter._poe_rearm``: detect transitions
        take seconds on real hardware, so an immediate re-read would
        false-negative; a port that never recovers raises WriteVerificationError.
        """
        self._require_poe()
        before = self._poe_status(port)
        self._in_mode(
            [self._spec.configure_cmd, self._spec.interface(port)],
            [self._spec.poe_reset_cmd],
        )
        deadline = clock() + timeouts.on_timeout
        while not recovered(self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    timeout_message.format(timeout=timeouts.on_timeout),
                    before=before,
                    after=self._poe_status(port),
                )
            sleep(timeouts.poll_interval)

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Power-cycle PoE on ``port`` and wait for it to deliver again."""
        self._guard(port, force)
        self._poe_reset(
            port,
            timeouts=timeouts or _DEFAULT_POE_TIMEOUTS,
            sleep=sleep,
            clock=clock,
            recovered=lambda st: bool(st and st.delivering),
            timeout_message=(
                f"PoE port {port} did not return to delivering within {{timeout}}s"
            ),
        )

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Clear a PoE fault on ``port``: re-arm detection, then poll until the
        port has LEFT the fault state (delivering or searching), exactly the
        recovery predicate ``SnmpWriter.clear_poe_fault`` uses."""
        self._guard(port, force)
        self._poe_reset(
            port,
            timeouts=timeouts or _DEFAULT_POE_TIMEOUTS,
            sleep=sleep,
            clock=clock,
            recovered=lambda st: (
                st is not None
                and st.detect in (PoEDetect.DELIVERING, PoEDetect.SEARCHING)
            ),
            timeout_message=(
                f"PoE port {port} still in FAULT after clear within {{timeout}}s"
            ),
        )

    # --- port admin state ---------------------------------------------------

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        """Enable/disable ``port`` (``no shutdown`` / ``shutdown``).

        Command form confirmed on all four CLI models ("shutdown ?" -> <cr>).
        Verified through ``show port all``'s Admin Mode column.
        """
        if not enabled:
            self._guard(port, force)  # disabling a port is disruptive
        before = self._port_status(port)
        self._in_mode(
            [self._spec.configure_cmd, self._spec.interface(port)],
            [self._spec.port_admin(enabled=enabled)],
        )
        after = self._port_status(port)
        if after is None or after.admin_enabled != enabled:
            raise WriteVerificationError(
                f"admin state for port {port} did not read back as {enabled}",
                before=before,
                after=after,
            )

    def _port_status(self, port: int) -> PortStatus | None:
        return next((p for p in self._reader.get_ports() if p.port == port), None)

    # --- host name -----------------------------------------------------------

    def set_hostname(self, name: str, *, force: bool = False) -> None:
        """Set the switch's host name, via global-config ``hostname <name>``.

        Not force-gated: renaming cannot strand the switch and is reversible by
        writing the old name back, unlike ``set_mgmt_ip`` below which drops the
        session that issues it. ``force`` is accepted so the signature matches
        every other writer.

        Verified by re-reading ``show hosts``. That command, rather than
        ``show running-config``, is deliberate and load-bearing here: the two
        report different values on real hardware (see
        ``protocols.cli.parse.parse_hostname``), and ``show hosts`` is the one
        that agrees with SNMP, so a CLI write verified this way is also
        observable over SNMP.

        Nothing is persisted -- no ``write memory`` -- exactly like every other
        write in this module.
        """
        del force  # accepted for a uniform writer signature; nothing to gate
        if not name.strip():
            # `hostname` with no argument is rejected by the device itself
            # ("Command not found / Incomplete command"), so sending it would
            # surface as a confusing CliCommandError from deep in _in_mode.
            # CLEARING a host name is a different operation -- FASTPATH spells
            # it `no hostname` -- and that has not been driven against real
            # hardware here, so it is not offered rather than guessed at.
            raise ValueError(
                "hostname must not be empty; clearing a switch's host name is "
                "`no hostname` on FASTPATH, which this library does not "
                "implement because it has not been verified on a device"
            )
        before = self._reader.get_hostname()
        self._in_mode(
            [self._spec.configure_cmd],
            [self._spec.hostname_config_cmd.format(name=name)],
        )
        after = self._reader.get_hostname()
        if after != name:
            raise WriteVerificationError(
                f"`show hosts` reports {after!r} after setting hostname {name!r}",
                before=before,
                after=after,
            )

    # --- management IP + reboot --------------------------------------------

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Set the switch's own management IP.

        Per-model dialect (both confirmed against the devices' own help on
        2026-07-30 -- see ``CliModelSpec.mgmt_ip_*``):

        * gsm7252ps / gsm7228ps -- privileged EXEC
          ``network parms <ip> <mask> <gateway>``
        * m4300-24x / -16x -- global config ``ip management address <ip> <mask>``
          then ``ip default-gateway <gw>`` (these images have no
          ``network parms`` at all)

        ``force=True`` is required: unlike the SNMP path (whose write OIDs are
        placeholders), these commands are the switch's real documented ones --
        but the op can still strand the switch, and it will normally drop the
        very CLI session issuing it (the session is reached over the address
        being changed), so the read-back may itself fail. Deliberately NOT
        live-tested for that reason.
        """
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch (and drops the CLI session "
                "it is issued over); pass force=True to proceed"
            )
        exec_cmds, config_cmds = self._spec.mgmt_ip(address, netmask, gateway)
        before = self._reader.get_mgmt_ip()
        for command in exec_cmds:
            self._run(command)
        if config_cmds:
            self._in_mode([self._spec.configure_cmd], config_cmds)
        after = self._reader.get_mgmt_ip()
        for field, want, got in (
            ("address", address, after.address),
            ("netmask", netmask, after.netmask),
            ("gateway", gateway, after.gateway),
        ):
            if got != want:
                raise WriteVerificationError(
                    f"management {field} did not read back as {want!r} (got {got!r})",
                    before=before,
                    after=after,
                )

    def reboot(self, *, force: bool = False) -> None:
        """Reboot the switch (``reload``, privileged EXEC).

        Command confirmed on all four models ("reload ?" -> ``<cr>`` /
        ``<unit>``). ``reload`` asks a ``(y/n)`` confirm, so it is issued through
        the same confirm-answering transport path ``write memory`` uses.

        HONESTY: this is the one write here that CANNOT be verified -- the switch
        stops answering by definition, and the CLI session dies with it (a
        dropped session IS the success signal, which is why
        ``CliTransportError`` is not treated as a failure). It is also the one
        write deliberately NOT exercised on live hardware: these switches carry
        production traffic. Callers must re-poll the switch themselves.
        """
        if not force:
            raise ProtectedPortError("reboot is disruptive; pass force=True")
        try:
            self.session.run_write_memory(self._spec.reload_cmd, prestuff=True)
        except CliTransportError:
            # Expected: the switch tore the session down while rebooting.
            return

    def set_syslog_enabled(self, enabled: bool, *, force: bool = False) -> None:
        """This backend does not serve a remote-logging toggle.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "a remote-logging toggle"
        )
