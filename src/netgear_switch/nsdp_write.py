"""Model-driven NSDP write/control over a write-capable sync or async client.

Parallel to ``snmp_write.py``. Every write performs the NSDP WRITE_REQUEST
(v1-authenticated) then re-reads to verify (``WriteVerificationError`` with
before/after on mismatch; a bad password / transport error surfaces as
``NsdpError`` from the client first). Disruptive per-port writes to a
``protected_ports`` port are refused unless ``force=True``. Writes NSDP has no
tag for (PoE, per-port admin, VLAN create/delete) raise
``UnsupportedCapabilityError`` — never a silent no-op.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import (
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .models import VlanMode
from .nsdp_read import AsyncNsdpReader, NsdpReader
from .protocols.nsdp.protocol import Tag
from .protocols.nsdp.write import ipv4_tlv, pvid_tlv, vlan_members_tlv
from .registry import Backend

if TYPE_CHECKING:
    from .models import VLANInfo
    from .protocols.nsdp.client import AsyncNsdpWriteClient, NsdpWriteClient
    from .registry import SwitchModel
    from .snmp_write import PoeCycleTimeouts

_NO_POE = "NSDP has no PoE control tag; use the HTTP backend (Slice 6) for PoE"
_NO_PORT_ADMIN = (
    "no per-port admin-enable is available on these Plus models: NSDP has no "
    "admin-enable tag, and the web UI has no grounded port-enable endpoint "
    "(UNVERIFIED-pending-capture)"
)
_NO_VLAN_LIFECYCLE = (
    "NSDP has no VLAN create/destroy tag on these Plus models; only VLAN "
    "membership/PVID are writable over NSDP"
)


def _require_nsdp(model: SwitchModel) -> None:
    if Backend.NSDP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no NSDP backend")


def _members_after(
    current: VLANInfo | None, port: int, mode: VlanMode
) -> tuple[set[int], set[int]]:
    """Read-modify-write the (members, tagged) sets for one membership change."""
    members = set(current.member_ports) if current is not None else set()
    tagged = set(current.tagged_ports) if current is not None else set()
    if mode is VlanMode.EXCLUDED:
        members.discard(port)
        tagged.discard(port)
    else:
        members.add(port)
        tagged.add(port) if mode is VlanMode.TAGGED else tagged.discard(port)
    return members, tagged


def _membership_ok(after: VLANInfo | None, port: int, mode: VlanMode) -> bool:
    if after is None:
        return mode is VlanMode.EXCLUDED
    in_members = port in after.member_ports
    in_tagged = port in after.tagged_ports
    if mode is VlanMode.EXCLUDED:
        return not in_members
    return in_members and (in_tagged == (mode is VlanMode.TAGGED))


class NsdpWriter:
    """Synchronous NSDP write facade over one switch."""

    def __init__(
        self,
        client: NsdpWriteClient,
        model: SwitchModel,
        *,
        password: str,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_nsdp(model)
        self.client = client
        self.model = model
        self._password = password
        self.protected_ports = protected_ports
        self._reader = NsdpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    def _vlan(self, vlan: int) -> VLANInfo | None:
        return next((v for v in self._reader.get_vlans() if v.vlan_id == vlan), None)

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        # UNVERIFIED pending a hardware capture: PORT_PVID (0x3000) is documented
        # READ-ONLY in the reference spec, so a real switch may reject this write
        # (verify-after-write below is the guard). Same house style as
        # snmp_write.py:set_mgmt_ip's unverified-OID note.
        self._guard(port, force)
        before = dict(self._reader.get_pvids())
        self.client.write([pvid_tlv(port, vlan)], password=self._password)
        after = dict(self._reader.get_pvids())
        if after.get(port) != vlan:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before.get(port),
                after=after.get(port),
            )

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        # UNVERIFIED pending a hardware capture: VLAN_MEMBERS (0x2800) is
        # documented READ-ONLY in the reference spec, so a real switch may reject
        # this write (verify-after-write below is the guard). Same house style as
        # snmp_write.py:set_mgmt_ip's unverified-OID note.
        self._guard(port, force)
        before = self._vlan(vlan)
        members, tagged = _members_after(before, port, mode)
        self.client.write(
            [vlan_members_tlv(vlan, members, tagged, self.model.port_count)],
            password=self._password,
        )
        after = self._vlan(vlan)
        if not _membership_ok(after, port, mode):
            raise WriteVerificationError(
                f"VLAN {vlan} membership for port {port} did not read back as {mode}",
                before=before,
                after=after,
            )

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        # Force-gated: a wrong management-IP write can strand the switch.
        # UNVERIFIED pending a hardware capture: the NSDP write path + v1 auth are
        # unconfirmed against real hardware (verify-after-write below is the
        # guard), same house style as snmp_write.py:set_mgmt_ip. (IP/netmask/
        # gateway are R/W in the reference spec, unlike PVID/VLAN_MEMBERS.)
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch; pass force=True to override"
            )
        before = self._reader.get_mgmt_ip()
        self.client.write(
            [
                ipv4_tlv(Tag.IP_ADDRESS, address),
                ipv4_tlv(Tag.NETMASK, netmask),
                ipv4_tlv(Tag.GATEWAY, gateway),
            ],
            password=self._password,
        )
        after = self._reader.get_mgmt_ip()
        if (after.address, after.netmask, after.gateway) != (address, netmask, gateway):
            raise WriteVerificationError(
                "management IP did not read back as written",
                before=before,
                after=after,
            )

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_POE)

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        # timeouts accepted-but-unused: matches SnmpWriter's signature so the
        # facade's SnmpWriter | NsdpWriter union call site typechecks; NSDP has
        # no PoE control tag at all, so there is nothing to time.
        raise UnsupportedCapabilityError(_NO_POE)

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        raise UnsupportedCapabilityError(_NO_POE)

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        raise UnsupportedCapabilityError(_NO_PORT_ADMIN)

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_VLAN_LIFECYCLE)

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_VLAN_LIFECYCLE)


class AsyncNsdpWriter:
    """Asynchronous NSDP write facade (mirror of NsdpWriter)."""

    def __init__(
        self,
        client: AsyncNsdpWriteClient,
        model: SwitchModel,
        *,
        password: str,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        _require_nsdp(model)
        self.client = client
        self.model = model
        self._password = password
        self.protected_ports = protected_ports
        self._reader = AsyncNsdpReader(client, model)

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected; pass force=True to override"
            )

    async def _vlan(self, vlan: int) -> VLANInfo | None:
        vlans = await self._reader.get_vlans()
        return next((v for v in vlans if v.vlan_id == vlan), None)

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        # UNVERIFIED pending a hardware capture: PORT_PVID (0x3000) is documented
        # READ-ONLY in the reference spec, so a real switch may reject this write
        # (verify-after-write below is the guard). Same house style as
        # snmp_write.py:set_mgmt_ip's unverified-OID note.
        self._guard(port, force)
        before = dict(await self._reader.get_pvids())
        await self.client.write([pvid_tlv(port, vlan)], password=self._password)
        after = dict(await self._reader.get_pvids())
        if after.get(port) != vlan:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=before.get(port),
                after=after.get(port),
            )

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        # UNVERIFIED pending a hardware capture: VLAN_MEMBERS (0x2800) is
        # documented READ-ONLY in the reference spec, so a real switch may reject
        # this write (verify-after-write below is the guard). Same house style as
        # snmp_write.py:set_mgmt_ip's unverified-OID note.
        self._guard(port, force)
        before = await self._vlan(vlan)
        members, tagged = _members_after(before, port, mode)
        await self.client.write(
            [vlan_members_tlv(vlan, members, tagged, self.model.port_count)],
            password=self._password,
        )
        after = await self._vlan(vlan)
        if not _membership_ok(after, port, mode):
            raise WriteVerificationError(
                f"VLAN {vlan} membership for port {port} did not read back as {mode}",
                before=before,
                after=after,
            )

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        # Force-gated: a wrong management-IP write can strand the switch.
        # UNVERIFIED pending a hardware capture: the NSDP write path + v1 auth are
        # unconfirmed against real hardware (verify-after-write below is the
        # guard), same house style as snmp_write.py:set_mgmt_ip. (IP/netmask/
        # gateway are R/W in the reference spec, unlike PVID/VLAN_MEMBERS.)
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip can strand the switch; pass force=True to override"
            )
        before = await self._reader.get_mgmt_ip()
        await self.client.write(
            [
                ipv4_tlv(Tag.IP_ADDRESS, address),
                ipv4_tlv(Tag.NETMASK, netmask),
                ipv4_tlv(Tag.GATEWAY, gateway),
            ],
            password=self._password,
        )
        after = await self._reader.get_mgmt_ip()
        if (after.address, after.netmask, after.gateway) != (address, netmask, gateway):
            raise WriteVerificationError(
                "management IP did not read back as written",
                before=before,
                after=after,
            )

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_POE)

    async def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        # timeouts accepted-but-unused: matches AsyncSnmpWriter's signature so
        # the facade's AsyncSnmpWriter | AsyncNsdpWriter union call site
        # typechecks; NSDP has no PoE control tag at all, so there is nothing
        # to time.
        raise UnsupportedCapabilityError(_NO_POE)

    async def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        raise UnsupportedCapabilityError(_NO_POE)

    async def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        raise UnsupportedCapabilityError(_NO_PORT_ADMIN)

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_VLAN_LIFECYCLE)

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        raise UnsupportedCapabilityError(_NO_VLAN_LIFECYCLE)
