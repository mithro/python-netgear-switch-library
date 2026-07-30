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
from .models import PoEDetect
from .protocols.snmp import oids
from .protocols.snmp.client import SnmpError
from .protocols.snmp.parse import decode_port_bitmap
from .protocols.snmp.write import (
    SetVarbind,
    encode_port_bitmap,
    membership_bitmaps,
    vlan_bitmap_width,
)
from .registry import Backend
from .snmp_read import AsyncSnmpReader, SnmpReader

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from .models import PoEStatus, PortStatus, VLANInfo, VlanMode
    from .protocols.snmp.client import AsyncSnmpWriteClient, SnmpWriteClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


def _poe_admin_oid(port: int) -> str:
    return f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"


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


def _poe_recovered(status: PoEStatus | None) -> bool:
    """True once detect has left FAULT and settled to delivering/searching."""
    return status is not None and status.detect in (
        PoEDetect.DELIVERING,
        PoEDetect.SEARCHING,
    )


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
        on_recovered: Callable[[PoEStatus | None], bool],
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
        while not on_recovered(self._poe_status(port)):
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
            on_recovered=lambda st: bool(st and st.delivering),
            on_timeout_message=(
                f"PoE port {port} did not return to delivering within {{timeout}}s"
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

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)  # changing a port's PVID is disruptive
        before = self._reader.get_pvids()
        self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before,
                after=after,
            )

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        before = self._vlan(vlan)
        if before is None:
            # Precondition failure: no SET has been attempted, so this is NOT a
            # verification divergence (review item 9).
            raise SnmpError(f"VLAN {vlan} does not exist")
        new_egress, new_untagged = membership_bitmaps(
            mode=mode,
            port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
            width_bytes=vlan_bitmap_width(self.model),
        )
        self.client.set_many(
            [
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"
                ),
            ]
        )
        after = self._vlan(vlan)
        # Verify BOTH columns this op wrote: egress membership AND the untagged
        # set. A mock/device that accepts the egress SET but silently drops the
        # untagged SET must be caught (review item 1).
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
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
        on_recovered: Callable[[PoEStatus | None], bool],
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
        while not on_recovered(await self._poe_status(port)):
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
            on_recovered=lambda st: bool(st and st.delivering),
            on_timeout_message=(
                f"PoE port {port} did not return to delivering within {{timeout}}s"
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

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        before = await self._reader.get_pvids()
        await self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = await self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before,
                after=after,
            )

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        before = await self._vlan(vlan)
        if before is None:
            # Precondition failure (review item 9): no SET attempted.
            raise SnmpError(f"VLAN {vlan} does not exist")
        new_egress, new_untagged = membership_bitmaps(
            mode=mode,
            port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
            width_bytes=vlan_bitmap_width(self.model),
        )
        await self.client.set_many(
            [
                SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
                SetVarbind(
                    f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"
                ),
            ]
        )
        after = await self._vlan(vlan)
        # Verify BOTH written columns (egress AND untagged) — review item 1.
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
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
