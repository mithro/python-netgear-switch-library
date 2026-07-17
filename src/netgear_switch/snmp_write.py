"""Model-driven SNMP write/control over a write-capable sync or async client.

Parallel to ``snmp_read.py``. Every write performs the SET then re-reads and
verifies (``WriteVerificationError`` with before/after on mismatch — a real
``commitFailed`` surfaces as an ``SnmpError`` from the transport first).
Disruptive writes to a ``protected_ports`` port are refused unless ``force=True``
(design spec §6).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
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
    from .models import PoEStatus, PortStatus, VLANInfo, VlanMode
    from .protocols.snmp.client import AsyncSnmpWriteClient, SnmpWriteClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


def _poe_admin_oid(port: int) -> str:
    return f"{oids.PETH_PSE_PORT_TABLE}.3.1.{port}"


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
                before=before, after=after,
            )

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
                before=before, after=after,
            )

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)  # changing a port's PVID is disruptive
        before = self._reader.get_pvids()
        self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before, after=after,
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
            mode=mode, port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
            width_bytes=vlan_bitmap_width(self.model),
        )
        self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"),
        ])
        after = self._vlan(vlan)
        # Verify BOTH columns this op wrote: egress membership AND the untagged
        # set. A mock/device that accepts the egress SET but silently drops the
        # untagged SET must be caught (review item 1).
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before, after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, "
                f"got {sorted(after.member_ports)}",
                before=before, after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before, after=after,
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
                before=before, after=after,
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
                before=before, after=after,
            )

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        before = await self._reader.get_pvids()
        await self.client.set(SetVarbind(f"{oids.DOT1Q_PVID}.{port}", vlan, "u"))
        after = await self._reader.get_pvids()
        if (port, vlan) not in after:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before, after=after,
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
            mode=mode, port=port,
            egress=encode_port_bitmap(before.member_ports),
            untagged=encode_port_bitmap(before.untagged_ports),
            width_bytes=vlan_bitmap_width(self.model),
        )
        await self.client.set_many([
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{vlan}", new_egress, "x"),
            SetVarbind(f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{vlan}", new_untagged, "x"),
        ])
        after = await self._vlan(vlan)
        # Verify BOTH written columns (egress AND untagged) — review item 1.
        want_egress = frozenset(decode_port_bitmap(new_egress))
        want_untagged = frozenset(decode_port_bitmap(new_untagged))
        if after is None:
            raise WriteVerificationError(
                f"VLAN {vlan} disappeared while setting membership for port {port}",
                before=before, after=after,
            )
        if after.member_ports != want_egress:
            raise WriteVerificationError(
                f"VLAN {vlan} egress (member_ports) for port {port} did not "
                f"verify: wanted {sorted(want_egress)}, "
                f"got {sorted(after.member_ports)}",
                before=before, after=after,
            )
        if after.untagged_ports != want_untagged:
            raise WriteVerificationError(
                f"VLAN {vlan} untagged_ports for port {port} did not verify: "
                f"wanted {sorted(want_untagged)}, got {sorted(after.untagged_ports)}",
                before=before, after=after,
            )
