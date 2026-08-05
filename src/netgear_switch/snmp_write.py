"""Model-driven SNMP write/control over a write-capable sync or async client.

Parallel to ``snmp_read.py``. Every write performs the SET then re-reads and
verifies (``WriteVerificationError`` with before/after on mismatch — a real
``commitFailed`` surfaces as an ``SnmpError`` from the transport first).
Disruptive writes to a ``protected_ports`` port are refused unless ``force=True``
(design spec §6).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .models import PoEDetect, VlanMode, poe_cycle_complete
from .protocols.snmp import oids
from .protocols.snmp.client import SnmpError
from .protocols.snmp.parse import decode_port_bitmap, physical_ports
from .protocols.snmp.write import (
    SetVarbind,
    encode_port_bitmap,
    membership_bitmaps,
    vlan_bitmap_width,
)
from .registry import Backend
from .snmp_read import AsyncSnmpReader, SnmpReader

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable, Sequence

    from .models import PoEStatus, PortSpeed, PortStatus, VLANInfo
    from .protocols.snmp.client import AsyncSnmpWriteClient, SnmpWriteClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


def _poe_admin_oid(port: int) -> str:
    return f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"


# The 802.1Q default VLAN a port falls back to when the requested change would
# otherwise leave it untagged in NO VLAN. That state is simply not expressible on
# this hardware: an access port always has an access VLAN, and a trunk always has
# a native VLAN -- VERIFIED live on the M4300-24X (10.1.5.13, FASTPATH 12.0.13.8)
# where SET switchport-native-vlan.1/0/8 := 0 and := 4094 BOTH answered
# commitFailed, as did := a VLAN id that does not exist.
_DEFAULT_VLAN = 1

#: SMI RowStatus ``destroy``. The one row-status value the FASTPATH syslog host
#: table honours: creation is refused through every mechanism (see
#: ``SnmpWriter.add_syslog_collector``) while destroy works, LIVE-VERIFIED on
#: m4300-24x 10.1.5.13 2026-08-05.
_ROW_DESTROY = "6"


def _vlan_bitmap(vlans: Iterable[int]) -> bytes:
    """Encode VLAN ids into a switchport VLAN bitmap (512 B, 4096 VLANs).

    Same MSB-first convention as a PortList (VLAN 1 = bit 7 of byte 0) but
    indexed by VLAN id.
    """
    data = bytearray(oids.SWITCHPORT_VLAN_BITMAP_BYTES)
    for vlan in vlans:
        data[(vlan - 1) // 8] |= 0x80 >> ((vlan - 1) % 8)
    return bytes(data)


def decode_vlan_bitmap(bitmap: bytes) -> frozenset[int]:
    """Inverse of ``_vlan_bitmap``: which VLAN ids a switchport bitmap names."""
    return frozenset(
        i * 8 + off + 1
        for i, byte in enumerate(bitmap)
        for off in range(8)
        if byte & (0x80 >> off)
    )


def _edit_vlan_bits(
    bitmap: bytes, *, add: Iterable[int] = (), remove: Iterable[int] = ()
) -> bytes:
    """READ-MODIFY-WRITE a switchport VLAN bitmap: flip ONLY the named bits.

    Never a blanket overwrite. This matters because the allowed-VLAN column
    routinely permits VLANs that do not exist yet (a factory-default M4300 port
    allows all 4093 of them), and only the bits for VLANs that exist contribute
    to membership -- so rebuilding the map from the port's *current* membership
    would silently revoke the operator's "allow future VLANs too" intent.
    Preserves the device's own byte width, growing only if a named VLAN needs it.
    """
    data = bytearray(bitmap)
    highest = max([*add, *remove], default=1)
    need = max((highest - 1) // 8 + 1, oids.SWITCHPORT_VLAN_BITMAP_BYTES)
    if len(data) < need:
        data.extend(bytes(need - len(data)))
    for vlan in add:
        data[(vlan - 1) // 8] |= 0x80 >> ((vlan - 1) % 8)
    for vlan in remove:
        data[(vlan - 1) // 8] &= ~(0x80 >> ((vlan - 1) % 8)) & 0xFF
    return bytes(data)


def _port_membership(
    vlans: Sequence[VLANInfo], port: int
) -> tuple[frozenset[int], frozenset[int]]:
    """``port``'s CURRENT (tagged, untagged) VLAN ids across every VLAN row.

    Read from the standard Q-BRIDGE mirrors, which report the truth on FASTPATH
    regardless of which switchport mode produced it -- so this works whether the
    port is access, trunk or general.
    """
    return (
        frozenset(v.vlan_id for v in vlans if port in v.tagged_ports),
        frozenset(v.vlan_id for v in vlans if port in v.untagged_ports),
    )


@dataclass(frozen=True)
class _SwitchportPlan:
    """The exact membership a switchport write intends, plus the SETs to get it."""

    untagged_vlan: int
    tagged_vlans: frozenset[int]
    varbinds: tuple[SetVarbind, ...]


def _plan_switchport_membership(
    *,
    vlan: int,
    port: int,
    mode: VlanMode,
    current_mode: int | None,
    current_allowed: bytes,
    current_tagged: frozenset[int],
    current_untagged: frozenset[int],
    existing_vlans: frozenset[int],
) -> _SwitchportPlan:
    """Plan a PRECISE, NON-DESTRUCTIVE membership change on the FASTPATH
    switchport control plane.

    How membership is actually derived on FASTPATH 12.x -- established live on
    2026-07-30 against BOTH M4300 SKUs (m4300-24x @10.1.5.13 fw 12.0.13.8 port
    1/0/8; m4300-16x @10.1.5.20 fw 12.0.19.15 port 1/0/1), by writing the vendor
    columns and re-reading the Q-BRIDGE mirrors after every step:

    * ``access(1)``  -> untagged member of the access VLAN (col3) and NOTHING
      else; col4/col6 are stored but not in force.
    * ``trunk(2)``   -> untagged member of the native VLAN (col4) plus a TAGGED
      member of ``(allowed(col6) INTERSECT existing VLANs) - {native}``. The
      native VLAN is an untagged member even when it is NOT in the allowed list
      (proved by removing VLAN 1 from col6 while native stayed 1).
    * ``general(3)`` -> membership comes from col7/col8, which answer
      notWritable, so this mode cannot be driven over SNMP.

    So trunk mode is a precise control plane for "exactly one untagged VLAN plus
    an arbitrary tagged set", and that is what this plans:

    * ``TAGGED``   V -> tagged = current tagged + V, untagged unchanged (minus V)
    * ``UNTAGGED`` V -> untagged = V, tagged = current tagged - V
    * ``EXCLUDED`` V -> BOTH sets minus V, every other VLAN left alone

    then expresses the result minimally: access mode when nothing is tagged (the
    idiomatic form, and what the switch's own CLI produces), else trunk mode with
    col4 = the untagged VLAN and col6 read-modify-written.

    Two requests cannot be honoured and are REFUSED rather than approximated
    (precondition failure -- no SET is attempted):

    * a desired state with MORE THAN ONE untagged VLAN. Reachable in practice: a
      general-mode port can be untagged in several VLANs (observed live on
      m4300-16x port 1/0/1, untagged in both 1 and 4007), and trunk/access mode
      can only hold one.
    * excluding a port from its ONLY untagged VLAN while it is a TAGGED member of
      the default VLAN, because the fallback below would then have to demote that
      VLAN from tagged to untagged -- a change to a VLAN the caller never named.

    Excluding a port from its only untagged VLAN otherwise falls back to
    ``_DEFAULT_VLAN`` (see its comment: the hardware has no "untagged nowhere"
    state), which is the ONE unrequested membership this plan can produce. Unlike
    the implementation it replaces, it never discards the port's tagged VLANs and
    never grants membership in a VLAN that was not asked for.
    """
    if mode is VlanMode.TAGGED:
        want_tagged = current_tagged | {vlan}
        want_untagged = current_untagged - {vlan}
    elif mode is VlanMode.UNTAGGED:
        want_tagged = current_tagged - {vlan}
        want_untagged = frozenset({vlan})
    else:  # VlanMode.EXCLUDED
        want_tagged = current_tagged - {vlan}
        want_untagged = current_untagged - {vlan}

    if len(want_untagged) > 1:
        raise UnsupportedCapabilityError(
            f"port {port} is currently an untagged member of VLANs "
            f"{sorted(current_untagged)}; the FASTPATH switchport control plane "
            f"holds at most ONE untagged VLAN per port (access VLAN / trunk "
            f"native VLAN), and the per-VLAN participation columns that could "
            f"express several answer notWritable. Refusing rather than silently "
            f"dropping {sorted(want_untagged)[1:]}"
        )
    if want_untagged:
        untagged_vlan = next(iter(want_untagged))
    elif _DEFAULT_VLAN in want_tagged:
        raise UnsupportedCapabilityError(
            f"excluding port {port} from VLAN {vlan} would leave it untagged in "
            f"no VLAN, which this hardware cannot express, and the fallback "
            f"(VLAN {_DEFAULT_VLAN}) is a TAGGED member here -- honouring the "
            f"request would silently demote VLAN {_DEFAULT_VLAN} from tagged to "
            f"untagged. Give the port an explicit untagged VLAN first"
        )
    else:
        untagged_vlan = _DEFAULT_VLAN

    varbinds: list[SetVarbind] = []
    if want_tagged:
        if current_mode == oids.SWITCHPORT_MODE_TRUNK:
            # Already trunk: col6 IS this port's membership definition, so
            # read-modify-write it. Because trunk membership is
            # (allowed INTERSECT existing) - {native}, the bits that must be right
            # are exactly those of EXISTING VLANs; bits for VLANs that do not
            # exist yet are left ALONE, preserving an operator's "allow future
            # VLANs too" intent (a factory-default port allows all 4093, and only
            # ~14 of them exist on these switches).
            allowed = _edit_vlan_bits(
                current_allowed,
                add={untagged_vlan, *want_tagged},
                remove=existing_vlans - want_tagged - {untagged_vlan},
            )
        else:
            # Coming FROM access/general, col6 is stale and not in force (it is
            # all 4093 VLANs on a factory-default port). Carrying it into trunk
            # mode is what used to hand the port every VLAN on the switch, so
            # rebuild it from the membership the port actually has.
            allowed = _vlan_bitmap({untagged_vlan, *want_tagged})
        varbinds.append(
            SetVarbind(f"{oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS}.{port}", allowed, "x")
        )
        varbinds.append(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_NATIVE_VLAN}.{port}", untagged_vlan, "u"
            )
        )
        varbinds.append(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}",
                oids.SWITCHPORT_MODE_TRUNK,
                "i",
            )
        )
    else:
        # Nothing tagged: one untagged VLAN is exactly what access mode is.
        # col6/col4 are deliberately left untouched -- access mode ignores them.
        varbinds.append(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_ACCESS_VLAN}.{port}", untagged_vlan, "u"
            )
        )
        varbinds.append(
            SetVarbind(
                f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}",
                oids.SWITCHPORT_MODE_ACCESS,
                "i",
            )
        )
    return _SwitchportPlan(
        untagged_vlan=untagged_vlan,
        tagged_vlans=frozenset(want_tagged),
        varbinds=tuple(varbinds),
    )


def _switchport_divergence(
    plan: _SwitchportPlan, vlan: int, port: int, after: Sequence[VLANInfo]
) -> str | None:
    """Compare the port's FULL membership against ``plan``; message or None.

    Verification deliberately covers EVERY VLAN, not just the requested one: the
    whole point of the plan is that VLANs the caller never named keep their
    membership, and a per-VLAN check cannot see that being violated. Reads the
    standard Q-BRIDGE mirrors, so a device that ACKs the vendor SETs without
    changing membership still fails.
    """
    if not any(v.vlan_id == vlan for v in after):
        return f"VLAN {vlan} disappeared while setting membership for port {port}"
    got_tagged, got_untagged = _port_membership(after, port)
    if got_untagged != frozenset({plan.untagged_vlan}):
        return (
            f"port {port} should be an untagged member of VLAN "
            f"{plan.untagged_vlan} only, but reads back untagged in "
            f"{sorted(got_untagged)}"
        )
    if got_tagged != plan.tagged_vlans:
        gained = sorted(got_tagged - plan.tagged_vlans)
        lost = sorted(plan.tagged_vlans - got_tagged)
        return (
            f"port {port} tagged membership did not verify: wanted "
            f"{sorted(plan.tagged_vlans)}, got {sorted(got_tagged)}"
            + (f"; UNREQUESTED membership gained in {gained}" if gained else "")
            + (f"; membership LOST in {lost}" if lost else "")
        )
    return None


@dataclass(frozen=True)
class PoeCycleTimeouts:
    """Injectable PoE-cycle deadlines (seconds). Defaults match design spec §6;
    tests pass tiny values so cycles run fast against the coherent mock."""

    off_timeout: float = 30.0
    on_timeout: float = 60.0
    poll_interval: float = 2.0


_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()


def _poe_is_off(status: PoEStatus | None, port_up: bool) -> bool:
    return (
        status is not None
        and status.detect in (PoEDetect.DISABLED, PoEDetect.SEARCHING)
        and not port_up
    )


#: Why an SNMP VLAN create is refused on a model whose agent cannot do it. A
#: capability refusal, so it is raised BEFORE any SET is attempted and the
#: caller can route the operation to a backend that works.
_NO_VLAN_CREATE = (
    "this model's SNMP agent cannot create a VLAN: every RowStatus mechanism "
    "(createAndGo, createAndGo+name in one PDU, createAndWait->name->active, "
    "the name column alone, and createAndGo carrying an egress PortList) is "
    "answered inconsistentValue -- measured on the device. Membership, PVID "
    "and delete DO work over SNMP; create a VLAN over the HTTP backend"
)


def _require_snmp_vlan_creation(model: SwitchModel) -> None:
    if not model.snmp_can_create_vlan:
        raise UnsupportedCapabilityError(f"model {model.key!r}: {_NO_VLAN_CREATE}")


def _poe_recovered(before: PoEStatus | None, status: PoEStatus | None) -> bool:
    """True once detect has left FAULT and settled to delivering/searching.

    ``before`` is unused: clearing a fault succeeds when the port has left
    FAULT, whatever it was doing beforehand. It is in the signature so both
    recovery predicates share one shape (see ``_poe_cycled_back``).
    """
    del before
    return status is not None and status.detect in (
        PoEDetect.DELIVERING,
        PoEDetect.SEARCHING,
    )


#: See ``models.poe_cycle_complete`` -- shared with the HTTP writer, because
#: what counts as a port having come back is a property of the port rather than
#: of the protocol that asked.
_poe_cycled_back = poe_cycle_complete


class SnmpWriter:
    """Synchronous SNMP write facade over one switch."""

    def __init__(
        self,
        client: SnmpWriteClient,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_snmp(model)
        self.client = client
        self.model = model
        self.protected_ports = protected_ports
        self._reader = SnmpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    def _poe_status(self, port: int) -> PoEStatus | None:
        return next((p for p in self._reader.get_poe() if p.port == port), None)

    def _port_status(self, port: int) -> PortStatus | None:
        return next((p for p in self._reader.get_ports() if p.port == port), None)

    def _vlan(self, vlan: int) -> VLANInfo | None:
        return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)

    def _raw_bitmap(self, base_oid: str, vlan: int) -> bytes | None:
        """The device's own PortList octets for ``vlan``, width intact.

        VLANInfo carries decoded port sets, so re-encoding from it would size
        the bitmap to the highest port in use rather than to the width the
        device actually uses. Netgear switches report a PortList covering LAG
        and CPU pseudo-ports: measured live, 131 bytes on a 28-port M4300-24X
        and 79 bytes on a GSM7252PS. Returns None if the device did not report
        this VLAN as octets, so callers can fall back.
        """
        suffix = f".{vlan}"
        for row in self.client.walk(base_oid):
            if row.oid.endswith(suffix) and isinstance(row.value, bytes):
                return row.value
        return None

    def _physical(self) -> set[int] | None:
        """The switch's physical ports, or None when it does not publish ifType.

        A membership write is verified by decoding the bitmap it SENT and
        comparing it with what ``get_vlans`` reads back -- and get_vlans drops
        LAG bridge-ports (parse.parse_vlans). Without the same filter here the
        two sides disagree by exactly those bits and every write on a switch
        with a LAG in the VLAN would raise a bogus WriteVerificationError.
        Measured on the GS728TPP: bit 1000 (``po 1``) is set in 11 of its 13
        VLANs, so this is the normal case there, not an edge case.
        """
        return physical_ports(self.client.walk(oids.IF_TYPE))

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        if not on:
            self._guard(port, force)  # turning PoE off is disruptive
        before = self._poe_status(port)
        self.client.set(SetVarbind(_poe_admin_oid(port), 1 if on else 2, "i"))
        after = self._poe_status(port)
        if after is None or after.admin_enabled != on:
            raise WriteVerificationError(
                f"PoE admin for port {port} did not read back as {on}",
                before=before,
                after=after,
            )

    def _poe_rearm(
        self,
        port: int,
        *,
        timeouts: PoeCycleTimeouts,
        sleep: Callable[[float], None],
        clock: Callable[[], float],
        on_recovered: Callable[[PoEStatus | None, PoEStatus | None], bool],
        on_timeout_message: str,
    ) -> None:
        """Re-arm PoE on ``port``: TWO SEPARATE sequential SETs (off, then on)
        each polled to completion -- never a single duplicate-OID ``set_many``
        PDU. Per-varbind ordering within one PDU carrying the same OID twice
        is undefined on real hardware (RFC 3416); a real agent may reject it
        or collapse it (last-wins), silently defeating the off->on re-arm.
        Shared by ``cycle_poe`` (recovery = delivering) and ``clear_poe_fault``
        (recovery = delivering OR searching, i.e. detect has left FAULT)."""
        before = self._poe_status(port)
        # Phase 1: off, poll until unused/searching + link down.
        self.client.set(SetVarbind(_poe_admin_oid(port), 2, "i"))
        deadline = clock() + timeouts.off_timeout
        while not _poe_is_off(self._poe_status(port), self._port_up(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not turn off within {timeouts.off_timeout}s",
                    before=before,
                    after=self._poe_status(port),
                )
            sleep(timeouts.poll_interval)
        # Phase 2: on, poll until the caller's recovery predicate is met.
        self.client.set(SetVarbind(_poe_admin_oid(port), 1, "i"))
        deadline = clock() + timeouts.on_timeout
        while not on_recovered(before, self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    on_timeout_message.format(timeout=timeouts.on_timeout),
                    before=before,
                    after=self._poe_status(port),
                )
            sleep(timeouts.poll_interval)

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        self._poe_rearm(
            port,
            timeouts=timeouts,
            sleep=sleep,
            clock=clock,
            on_recovered=_poe_cycled_back,
            on_timeout_message=(
                f"PoE port {port} did not come back after the power cycle "
                "within {timeout}s"
            ),
        )

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        # Re-arm detection: disable then enable as TWO SEPARATE SETs (never a
        # single duplicate-OID set_many -- see _poe_rearm), then POLL for
        # detect to leave FAULT. An immediate single re-read false-negatives
        # on real hardware because detect transitions take seconds (review
        # item 5); tests inject tiny timeouts so this is fast against the
        # coherent mock.
        self._poe_rearm(
            port,
            timeouts=timeouts,
            sleep=sleep,
            clock=clock,
            on_recovered=_poe_recovered,
            on_timeout_message=(
                f"PoE port {port} still in FAULT after clear within {{timeout}}s"
            ),
        )

    def _port_up(self, port: int) -> bool:
        status = self._port_status(port)
        return bool(status and status.link_up)

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        if not enabled:
            self._guard(port, force)  # disabling a port is disruptive
        before = self._port_status(port)
        self.client.set(
            SetVarbind(f"{oids.IF_ADMIN_STATUS}.{port}", 1 if enabled else 2, "i")
        )
        after = self._port_status(port)
        if after is None or after.admin_enabled != enabled:
            raise WriteVerificationError(
                f"admin state for port {port} did not read back as {enabled}",
                before=before,
                after=after,
            )

    def set_port_description(
        self, port: int, description: str, *, force: bool = False
    ) -> None:
        """Set a port's ``ifAlias``, the standard per-port description column.

        WRITABILITY MEASURED 2026-08-03 on a GS728TPP (10.2.5.10, firmware
        6.0.1.30): a SET of ifAlias.17 was accepted and read straight back
        through ``get_ports``.

        Clearing it (``description=""``) is the case that needed transport work
        rather than a new OID: ``snmpset ... s ""`` is refused by the net-snmp
        CLI itself, so the transport sends an empty OCTET STRING as an empty hex
        string instead (see ``_set_argv``). Without that, a description could be
        set and never removed.
        """
        self._guard(port, force)
        before = self._port_status(port)
        self.client.set(SetVarbind(f"{oids.IF_ALIAS}.{port}", description, "s"))
        after = self._port_status(port)
        # The reader maps an empty alias to None, so compare on that footing.
        want = description or None
        if after is None or after.description != want:
            raise WriteVerificationError(
                f"description for port {port} did not read back as {want!r}",
                before=before.description if before else None,
                after=after.description if after else None,
            )

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)  # changing a port's PVID is disruptive
        # Precondition, like set_vlan_membership's: no SET is attempted, so
        # this is not a verification divergence.
        #
        # The device will NOT catch this. MEASURED on the GS728TPP (10.2.5.10,
        # firmware 6.0.1.30, 2026-08-03): dot1qPvid := a VLAN that does not
        # exist is ACCEPTED, reads back as that id, and creates no VLAN -- so
        # verify-after-write passes and the port is left with a PVID for a VLAN
        # that is not there. Only a precondition check can catch it.
        if not any(v.vlan_id == vlan for v in self._reader.get_vlans()):
            raise SnmpError(f"VLAN {vlan} does not exist")
        before = self._reader.get_pvids()
        self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before,
                after=after,
            )

    def _set_vlan_switchport(
        self,
        vlan: int,
        port: int,
        mode: VlanMode,
        before: VLANInfo,
        vlans: Sequence[VLANInfo],
    ) -> None:
        """Set VLAN membership through the FASTPATH vendor SWITCHPORT table.

        All of the reasoning, the live evidence and the refusal cases live in
        ``_plan_switchport_membership``; this just reads the port's current state,
        applies the plan and verifies it. Verification reads the standard
        Q-BRIDGE mirrors back (``_switchport_divergence``), so a switch that
        accepted the vendor SETs without actually changing membership -- or that
        changed a VLAN nobody asked about -- still raises WriteVerificationError.
        """
        current_tagged, current_untagged = _port_membership(vlans, port)
        plan = _plan_switchport_membership(
            vlan=vlan,
            port=port,
            mode=mode,
            current_mode=self._switchport_mode(port),
            current_allowed=self._switchport_vlan_bitmap(
                oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS, port
            ),
            current_tagged=current_tagged,
            current_untagged=current_untagged,
            existing_vlans=frozenset(v.vlan_id for v in vlans),
        )
        for vb in plan.varbinds:
            # One PDU per varbind, DATA columns before the MODE selector: the mode
            # decides which columns are in force, so landing col6/col4/col3 first
            # means membership never passes through a wrong intermediate state
            # (a stale all-4093 allowed list plus an early mode:=trunk is exactly
            # the over-grant this rewrite removes). Verified live in this order.
            self.client.set(vb)
        problem = _switchport_divergence(plan, vlan, port, self._reader.get_vlans())
        if problem is not None:
            raise WriteVerificationError(problem, before=before, after=self._vlan(vlan))

    def _switchport_vlan_bitmap(self, base_oid: str, port: int) -> bytes:
        """A switchport VLAN-list column's octets, or an all-zero 512-byte map."""
        rows = self.client.get([f"{base_oid}.{port}"])
        for row in rows:
            if isinstance(row.value, bytes):
                return row.value
        return bytes(oids.SWITCHPORT_VLAN_BITMAP_BYTES)

    def _switchport_mode(self, port: int) -> int | None:
        """The port's switchport mode column, or None if the device has no row."""
        for row in self.client.get([f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"]):
            if isinstance(row.value, int):
                return row.value
        return None

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        vlans = self._reader.get_vlans()
        before = next((v for v in vlans if v.vlan_id == vlan), None)
        if before is None:
            # Precondition failure: no SET has been attempted, so this is NOT a
            # verification divergence (review item 9).
            raise SnmpError(f"VLAN {vlan} does not exist")
        if self.model.snmp_vlan_write == "fastpath_switchport":
            self._set_vlan_switchport(vlan, port, mode, before, vlans)
            return
        # Feed set_port_bit the device's OWN bitmaps so it preserves their exact
        # wire width (that is what it is for); fall back to a re-encode of the
        # decoded sets only if the device did not report octets.
        raw_egress = self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_EGRESS, vlan)
        raw_untagged = self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_UNTAGGED, vlan)
        new_egress, new_untagged = membership_bitmaps(
            mode=mode,
            port=port,
            egress=(
                raw_egress
                if raw_egress is not None
                else encode_port_bitmap(before.member_ports)
            ),
            untagged=(
                raw_untagged
                if raw_untagged is not None
                else encode_port_bitmap(before.untagged_ports)
            ),
            width_bytes=vlan_bitmap_width(self.model),
        )
        egress_vb = SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"
        )
        untagged_vb = SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"
        )
        if self.model.snmp_vlan_split_membership_writes:
            # Egress FIRST, then untagged, in separate PDUs: this firmware
            # auto-untags a port when its egress bit is set, and that side effect
            # overrides an untagged varbind in the same PDU (see the field's
            # docstring for the live before/after evidence).
            self.client.set(egress_vb)
            self.client.set(untagged_vb)
        else:
            # One atomic PDU everywhere else -- the device applies both or neither.
            self.client.set_many([egress_vb, untagged_vb])
        after = self._vlan(vlan)
        # Verify BOTH columns this op wrote: egress membership AND the untagged
        # set. A mock/device that accepts the egress SET but silently drops the
        # untagged SET must be caught (review item 1). Compare on the same
        # footing get_vlans reports -- physical ports only (see _physical).
        keep = self._physical()
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if keep is not None:
            want_egress &= keep
            want_untagged &= keep
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before,
                after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, "
                f"got {sorted(after.member_ports)}",
                before=before,
                after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before,
                after=after,
            )

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        # Creating an EMPTY VLAN adds no port membership, so it is
        # non-disruptive and does NOT require force. ``force`` exists only for
        # signature symmetry with delete_vlan (review item 3).
        _require_snmp_vlan_creation(self.model)
        before = self._vlan(vlan)
        self.client.set_many(
            [
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                    oids.ROW_STATUS_CREATE_AND_GO,
                    "i",
                ),
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vlan}", name, "s"),
            ]
        )
        after = self._vlan(vlan)
        if after is None or (after.name or "") != name:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created with name {name!r}",
                before=before,
                after=after,
            )

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        before = self._vlan(vlan)
        if before is None:
            # Precondition failure: no SET has been attempted, so this is NOT a
            # verification divergence (review item 9, mirrors
            # set_vlan_membership's missing-VLAN precondition). The mock
            # accepts destroy(6) on an absent row as a silent no-op, so
            # skipping this check would let a delete of a non-existent VLAN
            # pass verification vacuously instead of surfacing as an error.
            raise SnmpError(f"VLAN {vlan} does not exist")
        # Destroying a VLAN strips membership from EVERY member port; if any is a
        # protected (uplink/mgmt) port, refuse without force (review item 3).
        if not force:
            clash = before.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway"
                )
        self.client.set(
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                oids.ROW_STATUS_DESTROY,
                "i",
            )
        )
        after = self._vlan(vlan)
        if after is not None:
            raise WriteVerificationError(
                f"VLAN {vlan} still exists after destroy",
                before=before,
                after=after,
            )

    def set_port_speed(
        self, port: int, speed: PortSpeed, *, force: bool = False
    ) -> None:
        """This backend cannot configure a port's speed.

        Refused by name rather than approximated. What SNMP offers here is
        ``ifSpeed``/``ifHighSpeed``, and those report the rate the link
        NEGOTIATED -- writing one would be writing a counter, not a
        setting. The column that would genuinely serve this is MAU-MIB's
        ``ifMauDefaultType``/``ifMauAutoNegAdminStatus`` (mib-2.26); no
        switch here has been walked for it, so its presence is UNKNOWN
        rather than absent, and the 2026-08-03 OID sweep does not settle it
        (that sweep covered the 4526 VENDOR subtree only). Use a CLI
        backend, or establish the MAU subtree first.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: SNMP exposes only the NEGOTIATED port "
            "rate (ifSpeed); no configured speed/duplex column has been located"
        )

    def set_flow_control(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        """This backend cannot configure flow control.

        Refused by name. EtherLike-MIB's ``dot3PauseAdminMode`` is the
        column that would serve this, and it is READ on the one model that
        publishes it (the GS728TPP) -- but no SET has ever been issued
        against it here, so whether the agent accepts one is unknown. This
        library does not offer a write it has never seen succeed.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: no SNMP flow-control write has been "
            "established (dot3PauseAdminMode is read-only in this library)"
        )

    def add_syslog_collector(
        self, host: str, *, port: int = 514, severity: int = 6, force: bool = False
    ) -> None:
        """This agent will not CREATE a syslog host row. MEASURED, not assumed.

        Probed on m4300-24x 10.1.5.13 (FASTPATH 12.0.13.8, 2026-08-05) with the
        Read/Write community, against a free index. Five mechanisms, five
        refusals, with the agent's own SMI error-status::

            createAndGo(4) + every column, one PDU -> inconsistentValue
            createAndWait(5) alone                 -> inconsistentValue
            createAndGo(4) alone                   -> inconsistentValue
            the value columns alone (auto-create?) -> commitFailed
            active(1) at a row that does not exist -> commitFailed

        The same agent ACCEPTS a SET of every column of an EXISTING row, and
        accepts ``destroy`` -- see ``remove_syslog_collector`` -- so this is the
        agent declining row creation specifically, not a permissions problem.
        (The first run of that probe used the READ community and "refused"
        everything, which is CLAUDE.md principle 4's own example. Ask the switch
        with ``show snmpcommunity``.)

        Same shape as the GS728TPP's refusal to create a VLAN row. Add over a
        CLI backend, where the command is the device's own running-config line.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this agent refuses to create a syslog "
            "host row (measured: createAndGo/createAndWait -> inconsistentValue, "
            "value-columns-only -> commitFailed); add it over a CLI backend"
        )

    def remove_syslog_collector(self, host: str, *, force: bool = False) -> None:
        """Remove a collector by writing RowStatus ``destroy(6)`` to its row.

        LIVE-VERIFIED on m4300-24x 10.1.5.13 (2026-08-05): a throwaway
        collector added over the CLI was destroyed with a single SET of
        ``<base>.14.1.4.5.1.7.<index> = 6``, and the switch's own
        ``show logging hosts`` confirmed the row was gone.

        Note the asymmetry, which is the agent's and not this library's: it
        DESTROYS rows but refuses to CREATE them (see ``add_syslog_collector``).

        ``<index>`` is the table's own row index -- the OID instance, which
        ``get_syslog`` surfaces as ``SyslogServer.index``. It is SPARSE, so it
        is read fresh here and never derived from a row's position; deriving it
        addresses the wrong row, and the agent accepts that as a silent no-op.
        """
        del force  # redirecting logs cannot strand a switch
        _require_snmp(self.model)
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only"
            )
        before = self._reader.get_syslog()
        row = next((s for s in before.servers if s.host == host), None)
        if row is None:
            raise UnsupportedCapabilityError(
                f"no syslog collector for {host!r} to remove"
            )
        if row.index is None:  # pragma: no cover -- the SNMP reader always fills it
            raise UnsupportedCapabilityError(
                f"the syslog collector for {host!r} carries no table index"
            )
        vo = oids.vendor_oids(self.model)
        self.client.set(
            SetVarbind(f"{vo.syslog_host_status}.{row.index}", _ROW_DESTROY, "i")
        )
        after = self._reader.get_syslog()
        if any(s.host == host for s in after.servers):
            raise WriteVerificationError(
                f"syslog collector {host!r} is still configured after destroy",
                before=before.servers,
                after=after.servers,
            )

    def set_syslog_enabled(self, enabled: bool, *, force: bool = False) -> None:
        """Turn remote syslog on or off.

        Writes the vendor logging admin-mode column (``<base>.14.1.4.1.0``),
        whose enum is ``1 = enabled, 2 = disabled`` -- established from captured
        CLI rather than assumed, see ``oids.VendorOids.syslog_admin_mode``.

        WRITABILITY MEASURED 2026-08-02 by SETting each switch the value it
        already held, which cannot change device state but still distinguishes a
        writable column from a read-only one: m4300-24x (10.1.5.13), gsm7252ps
        (10.1.5.22) and gsm7228ps (10.1.5.11) all accepted it.

        Deliberately narrower than ``get_syslog`` reads. Adding or removing a
        COLLECTOR means creating a row in the host table, which needs a
        row-status write that has not been driven against hardware; offering it
        here on the strength of the read alone would be the inference this
        project refuses.

        Not force-gated: toggling log delivery cannot strand a switch and is
        reversible by writing the old value back.
        """
        del force  # accepted for a uniform writer signature; nothing to gate
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only"
            )
        vo = oids.vendor_oids(self.model)
        before = self._reader.get_syslog()
        self.client.set_many(
            [SetVarbind(vo.syslog_admin_mode, 1 if enabled else 2, "i")]
        )
        after = self._reader.get_syslog()
        if after.enabled != enabled:
            raise WriteVerificationError(
                f"syslog enabled is {after.enabled} after writing {enabled}",
                before=before,
                after=after,
            )

    def set_hostname(self, name: str, *, force: bool = False) -> None:
        """Set the switch's host name via the standard MIB-II ``sysName``.

        GROUNDED, unlike ``set_mgmt_ip`` below: ``sysName`` was confirmed
        writable on every SNMP model in this fleet on 2026-08-02, by SETting
        each switch the value it already held. See ``oids.SYS_NAME`` for the
        hosts and communities, and for why this is NOT the same value as the
        FASTPATH ``hostname`` running-config directive.

        Not force-gated: renaming a switch cannot strand it the way a mgmt-IP
        write can, and it is trivially reversible by writing the old name back.
        ``force`` is accepted so the signature matches every other writer.
        """
        del force  # accepted for a uniform writer signature; nothing to gate
        before = self._reader.get_hostname()
        self.client.set_many([SetVarbind(oids.SYS_NAME, name, "s")])
        after = self._reader.get_hostname()
        if after != name:
            raise WriteVerificationError(
                f"sysName is {after!r} after writing {name!r}",
                before=before,
                after=after,
            )

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Set the switch's own management IP (address/netmask/gateway).

        UNVERIFIED write path (see oids.VendorOids mgmt_write_* fields): the
        exact writable OIDs are placeholders pending Slice 7 hardware capture,
        so this is force-gated (a wrong mgmt-IP write can strand the switch —
        design spec §11.1). DHCP-mode switching is intentionally NOT offered
        here because even its read OID is unverified; do not fabricate it.
        """
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
                "pass force=True to proceed"
            )
        vo = oids.vendor_oids(self.model)
        before = self._reader.get_mgmt_ip()
        self.client.set_many(
            [
                SetVarbind(vo.mgmt_write_addr_unverified, address, "a"),
                SetVarbind(vo.mgmt_write_netmask_unverified, netmask, "a"),
                SetVarbind(vo.mgmt_write_gateway_unverified, gateway, "a"),
            ]
        )
        after = self._reader.get_mgmt_ip()
        # Highest strand-risk op: verify EVERY field written (address, netmask,
        # AND gateway), naming whichever diverged (review item 2).
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


class AsyncSnmpWriter:
    """Asynchronous SNMP write facade (mirror of SnmpWriter)."""

    def __init__(
        self,
        client: AsyncSnmpWriteClient,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_snmp(model)
        self.client = client
        self.model = model
        self.protected_ports = protected_ports
        self._reader = AsyncSnmpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    async def _poe_status(self, port: int) -> PoEStatus | None:
        return next((p for p in await self._reader.get_poe() if p.port == port), None)

    async def _port_status(self, port: int) -> PortStatus | None:
        return next((p for p in await self._reader.get_ports() if p.port == port), None)

    async def _vlan(self, vlan: int) -> VLANInfo | None:
        vlans = await self._reader.get_vlans()
        return next((v for v in vlans if v.vlan_id == vlan), None)

    async def _raw_bitmap(self, base_oid: str, vlan: int) -> bytes | None:
        """Async twin of ``SnmpWriter._raw_bitmap`` -- see it for why."""
        suffix = f".{vlan}"
        for row in await self.client.walk(base_oid):
            if row.oid.endswith(suffix) and isinstance(row.value, bytes):
                return row.value
        return None

    async def _physical(self) -> set[int] | None:
        """Async twin of ``SnmpWriter._physical`` -- see it for why."""
        return physical_ports(await self.client.walk(oids.IF_TYPE))

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        if not on:
            self._guard(port, force)
        before = await self._poe_status(port)
        await self.client.set(SetVarbind(_poe_admin_oid(port), 1 if on else 2, "i"))
        after = await self._poe_status(port)
        if after is None or after.admin_enabled != on:
            raise WriteVerificationError(
                f"PoE admin for port {port} did not read back as {on}",
                before=before,
                after=after,
            )

    async def _port_up(self, port: int) -> bool:
        status = await self._port_status(port)
        return bool(status and status.link_up)

    async def _poe_rearm(
        self,
        port: int,
        *,
        timeouts: PoeCycleTimeouts,
        sleep: Callable[[float], Awaitable[None]],
        clock: Callable[[], float],
        on_recovered: Callable[[PoEStatus | None, PoEStatus | None], bool],
        on_timeout_message: str,
    ) -> None:
        """Async twin of ``SnmpWriter._poe_rearm``: TWO SEPARATE sequential
        SETs (off, then on) each polled to completion -- never a single
        duplicate-OID ``set_many`` PDU (RFC 3416 per-varbind ordering is
        undefined for a repeated OID, so a real agent may reject it or
        collapse it and silently defeat the off->on re-arm)."""
        before = await self._poe_status(port)
        # Phase 1: off, poll until unused/searching + link down.
        await self.client.set(SetVarbind(_poe_admin_oid(port), 2, "i"))
        deadline = clock() + timeouts.off_timeout
        while not _poe_is_off(await self._poe_status(port), await self._port_up(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not turn off within {timeouts.off_timeout}s",
                    before=before,
                    after=await self._poe_status(port),
                )
            await sleep(timeouts.poll_interval)
        # Phase 2: on, poll until the caller's recovery predicate is met.
        await self.client.set(SetVarbind(_poe_admin_oid(port), 1, "i"))
        deadline = clock() + timeouts.on_timeout
        while not on_recovered(before, await self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    on_timeout_message.format(timeout=timeouts.on_timeout),
                    before=before,
                    after=await self._poe_status(port),
                )
            await sleep(timeouts.poll_interval)

    async def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        await self._poe_rearm(
            port,
            timeouts=timeouts,
            sleep=sleep,
            clock=clock,
            on_recovered=_poe_cycled_back,
            on_timeout_message=(
                f"PoE port {port} did not come back after the power cycle "
                "within {timeout}s"
            ),
        )

    async def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._guard(port, force)
        # Re-arm as TWO SEPARATE SETs (never a single duplicate-OID set_many
        # -- see _poe_rearm), then poll for detect to leave FAULT (review item
        # 5); tiny timeouts in tests.
        await self._poe_rearm(
            port,
            timeouts=timeouts,
            sleep=sleep,
            clock=clock,
            on_recovered=_poe_recovered,
            on_timeout_message=(
                f"PoE port {port} still in FAULT after clear within {{timeout}}s"
            ),
        )

    async def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        if not enabled:
            self._guard(port, force)
        before = await self._port_status(port)
        await self.client.set(
            SetVarbind(f"{oids.IF_ADMIN_STATUS}.{port}", 1 if enabled else 2, "i")
        )
        after = await self._port_status(port)
        if after is None or after.admin_enabled != enabled:
            raise WriteVerificationError(
                f"admin state for port {port} did not read back as {enabled}",
                before=before,
                after=after,
            )

    async def set_port_description(
        self, port: int, description: str, *, force: bool = False
    ) -> None:
        """Async twin of ``SnmpWriter.set_port_description`` -- see it."""
        self._guard(port, force)
        before = await self._port_status(port)
        await self.client.set(SetVarbind(f"{oids.IF_ALIAS}.{port}", description, "s"))
        after = await self._port_status(port)
        want = description or None
        if after is None or after.description != want:
            raise WriteVerificationError(
                f"description for port {port} did not read back as {want!r}",
                before=before.description if before else None,
                after=after.description if after else None,
            )

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        # Precondition -- see SnmpWriter.set_pvid: the device accepts a PVID for
        # a VLAN that does not exist, so verify-after-write cannot catch it.
        if not any(v.vlan_id == vlan for v in await self._reader.get_vlans()):
            raise SnmpError(f"VLAN {vlan} does not exist")
        before = await self._reader.get_pvids()
        await self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = await self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before,
                after=after,
            )

    async def _switchport_vlan_bitmap(self, base_oid: str, port: int) -> bytes:
        """Async twin of SnmpWriter._switchport_vlan_bitmap."""
        for row in await self.client.get([f"{base_oid}.{port}"]):
            if isinstance(row.value, bytes):
                return row.value
        return bytes(oids.SWITCHPORT_VLAN_BITMAP_BYTES)

    async def _switchport_mode(self, port: int) -> int | None:
        """Async twin of SnmpWriter._switchport_mode."""
        for row in await self.client.get([f"{oids.FASTPATH_SWITCHPORT_MODE}.{port}"]):
            if isinstance(row.value, int):
                return row.value
        return None

    async def _set_vlan_switchport(
        self,
        vlan: int,
        port: int,
        mode: VlanMode,
        before: VLANInfo,
        vlans: Sequence[VLANInfo],
    ) -> None:
        """Async twin of SnmpWriter._set_vlan_switchport. The plan itself is the
        shared pure ``_plan_switchport_membership`` (so sync and async cannot
        drift) -- see it for the FASTPATH switchport derivation, the live evidence
        and the two requests it refuses instead of approximating."""
        current_tagged, current_untagged = _port_membership(vlans, port)
        plan = _plan_switchport_membership(
            vlan=vlan,
            port=port,
            mode=mode,
            current_mode=await self._switchport_mode(port),
            current_allowed=await self._switchport_vlan_bitmap(
                oids.FASTPATH_SWITCHPORT_ALLOWED_VLANS, port
            ),
            current_tagged=current_tagged,
            current_untagged=current_untagged,
            existing_vlans=frozenset(v.vlan_id for v in vlans),
        )
        for vb in plan.varbinds:
            # Data columns before the mode selector, one PDU each -- see the sync
            # twin for why the order matters.
            await self.client.set(vb)
        problem = _switchport_divergence(
            plan, vlan, port, await self._reader.get_vlans()
        )
        if problem is not None:
            raise WriteVerificationError(
                problem, before=before, after=await self._vlan(vlan)
            )

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        vlans = await self._reader.get_vlans()
        before = next((v for v in vlans if v.vlan_id == vlan), None)
        if before is None:
            # Precondition failure (review item 9): no SET attempted.
            raise SnmpError(f"VLAN {vlan} does not exist")
        if self.model.snmp_vlan_write == "fastpath_switchport":
            await self._set_vlan_switchport(vlan, port, mode, before, vlans)
            return
        # Preserve the device's own bitmap width -- see SnmpWriter._raw_bitmap.
        raw_egress = await self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_EGRESS, vlan)
        raw_untagged = await self._raw_bitmap(oids.DOT1Q_VLAN_STATIC_UNTAGGED, vlan)
        new_egress, new_untagged = membership_bitmaps(
            mode=mode,
            port=port,
            egress=(
                raw_egress
                if raw_egress is not None
                else encode_port_bitmap(before.member_ports)
            ),
            untagged=(
                raw_untagged
                if raw_untagged is not None
                else encode_port_bitmap(before.untagged_ports)
            ),
            width_bytes=vlan_bitmap_width(self.model),
        )
        egress_vb = SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"
        )
        untagged_vb = SetVarbind(
            f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"
        )
        if self.model.snmp_vlan_split_membership_writes:
            # See SnmpWriter.set_vlan_membership: egress first, separate PDUs.
            await self.client.set(egress_vb)
            await self.client.set(untagged_vb)
        else:
            await self.client.set_many([egress_vb, untagged_vb])
        after = await self._vlan(vlan)
        # Verify BOTH written columns (egress AND untagged) — review item 1 —
        # on the same physical-port footing get_vlans reports (see _physical).
        keep = await self._physical()
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if keep is not None:
            want_egress &= keep
            want_untagged &= keep
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before,
                after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, "
                f"got {sorted(after.member_ports)}",
                before=before,
                after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before,
                after=after,
            )

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        # Empty VLAN creation is non-disruptive; force is for symmetry only.
        _require_snmp_vlan_creation(self.model)
        before = await self._vlan(vlan)
        await self.client.set_many(
            [
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                    oids.ROW_STATUS_CREATE_AND_GO,
                    "i",
                ),
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_NAME}.{vlan}", name, "s"),
            ]
        )
        after = await self._vlan(vlan)
        if after is None or (after.name or "") != name:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created with name {name!r}",
                before=before,
                after=after,
            )

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        before = await self._vlan(vlan)
        if before is None:
            # Precondition failure (review item 9): no SET attempted. Mirrors
            # the sync path -- destroy(6) on an absent row is a silent no-op
            # in the mock, so this must be raised before issuing any SET.
            raise SnmpError(f"VLAN {vlan} does not exist")
        # Refuse if a member port is protected, unless force (review item 3).
        if not force:
            clash = before.member_ports & self.protected_ports
            if clash:
                raise ProtectedPortError(
                    f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                    f"pass force=True to delete it anyway"
                )
        await self.client.set(
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{vlan}",
                oids.ROW_STATUS_DESTROY,
                "i",
            )
        )
        after = await self._vlan(vlan)
        if after is not None:
            raise WriteVerificationError(
                f"VLAN {vlan} still exists after destroy",
                before=before,
                after=after,
            )

    async def set_port_speed(
        self, port: int, speed: PortSpeed, *, force: bool = False
    ) -> None:
        """This backend cannot configure a port's speed.

        Refused by name rather than approximated. What SNMP offers here is
        ``ifSpeed``/``ifHighSpeed``, and those report the rate the link
        NEGOTIATED -- writing one would be writing a counter, not a
        setting. The column that would genuinely serve this is MAU-MIB's
        ``ifMauDefaultType``/``ifMauAutoNegAdminStatus`` (mib-2.26); no
        switch here has been walked for it, so its presence is UNKNOWN
        rather than absent, and the 2026-08-03 OID sweep does not settle it
        (that sweep covered the 4526 VENDOR subtree only). Use a CLI
        backend, or establish the MAU subtree first.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: SNMP exposes only the NEGOTIATED port "
            "rate (ifSpeed); no configured speed/duplex column has been located"
        )

    async def set_flow_control(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        """This backend cannot configure flow control.

        Refused by name. EtherLike-MIB's ``dot3PauseAdminMode`` is the
        column that would serve this, and it is READ on the one model that
        publishes it (the GS728TPP) -- but no SET has ever been issued
        against it here, so whether the agent accepts one is unknown. This
        library does not offer a write it has never seen succeed.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: no SNMP flow-control write has been "
            "established (dot3PauseAdminMode is read-only in this library)"
        )

    async def add_syslog_collector(
        self, host: str, *, port: int = 514, severity: int = 6, force: bool = False
    ) -> None:
        """Async twin of ``SnmpWriter.add_syslog_collector`` -- see it for the
        five measured refusals."""
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this agent refuses to create a syslog "
            "host row (measured: createAndGo/createAndWait -> inconsistentValue, "
            "value-columns-only -> commitFailed); add it over a CLI backend"
        )

    async def remove_syslog_collector(self, host: str, *, force: bool = False) -> None:
        """Async twin of ``SnmpWriter.remove_syslog_collector`` -- see it."""
        del force
        _require_snmp(self.model)
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only"
            )
        before = await self._reader.get_syslog()
        row = next((s for s in before.servers if s.host == host), None)
        if row is None:
            raise UnsupportedCapabilityError(
                f"no syslog collector for {host!r} to remove"
            )
        if row.index is None:  # pragma: no cover -- the reader always fills it
            raise UnsupportedCapabilityError(
                f"the syslog collector for {host!r} carries no table index"
            )
        vo = oids.vendor_oids(self.model)
        await self.client.set(
            SetVarbind(f"{vo.syslog_host_status}.{row.index}", _ROW_DESTROY, "i")
        )
        after = await self._reader.get_syslog()
        if any(s.host == host for s in after.servers):
            raise WriteVerificationError(
                f"syslog collector {host!r} is still configured after destroy",
                before=before.servers,
                after=after.servers,
            )

    async def set_syslog_enabled(self, enabled: bool, *, force: bool = False) -> None:
        """Async twin of ``SnmpWriter.set_syslog_enabled`` -- see there."""
        del force  # accepted for a uniform writer signature; nothing to gate
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only"
            )
        vo = oids.vendor_oids(self.model)
        before = await self._reader.get_syslog()
        await self.client.set_many(
            [SetVarbind(vo.syslog_admin_mode, 1 if enabled else 2, "i")]
        )
        after = await self._reader.get_syslog()
        if after.enabled != enabled:
            raise WriteVerificationError(
                f"syslog enabled is {after.enabled} after writing {enabled}",
                before=before,
                after=after,
            )

    async def set_hostname(self, name: str, *, force: bool = False) -> None:
        """Async twin of ``SnmpWriter.set_hostname`` -- see there."""
        del force  # accepted for a uniform writer signature; nothing to gate
        before = await self._reader.get_hostname()
        await self.client.set_many([SetVarbind(oids.SYS_NAME, name, "s")])
        after = await self._reader.get_hostname()
        if after != name:
            raise WriteVerificationError(
                f"sysName is {after!r} after writing {name!r}",
                before=before,
                after=after,
            )

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Set the switch's own management IP (address/netmask/gateway).

        UNVERIFIED write path (see oids.VendorOids mgmt_write_* fields): the
        exact writable OIDs are placeholders pending Slice 7 hardware capture,
        so this is force-gated (a wrong mgmt-IP write can strand the switch —
        design spec §11.1). DHCP-mode switching is intentionally NOT offered
        here because even its read OID is unverified; do not fabricate it.
        """
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; "
                "pass force=True to proceed"
            )
        vo = oids.vendor_oids(self.model)
        before = await self._reader.get_mgmt_ip()
        await self.client.set_many(
            [
                SetVarbind(vo.mgmt_write_addr_unverified, address, "a"),
                SetVarbind(vo.mgmt_write_netmask_unverified, netmask, "a"),
                SetVarbind(vo.mgmt_write_gateway_unverified, gateway, "a"),
            ]
        )
        after = await self._reader.get_mgmt_ip()
        # Verify EVERY field written (address, netmask, AND gateway) — item 2.
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
