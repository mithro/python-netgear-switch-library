"""Model-driven NSDP write/control over a write-capable sync or async client.

Parallel to ``snmp_write.py``. Every write performs the NSDP WRITE_REQUEST
(v1-authenticated) then re-reads to verify (``WriteVerificationError`` with
before/after on mismatch; a bad password / transport error surfaces as
``NsdpError`` from the client first). Disruptive per-port writes to a
``protected_ports`` port are refused unless ``force=True``.

VLAN create/delete ARE implemented here (create = write the VLAN_MEMBERS tag
for a not-yet-existing VLAN id; delete = the VLAN_DESTROY action tag 0x2C00),
replacing a previous unproven "NSDP has no VLAN create/destroy tag" refusal --
see ``protocols/nsdp/write.py::vlan_destroy_tlv`` for the ngadmin evidence.

FIRMWARE CAVEAT, measured 2026-07-30: the whole NSDP write path (these two, and
the pre-existing PVID / VLAN-membership / mgmt-IP writes) is rejected outright
by GS110EMX firmware 1.0.2.8, which answers a WRITE_REQUEST error=13/14 on
ATTR_PASSWORD because it wants the undocumented v2 salted auth. That is a
transport-level refusal that ``check_result`` now names explicitly; it is not
specific to any one op.
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
from .protocols.nsdp.write import (
    ipv4_tlv,
    pvid_tlv,
    vlan_destroy_tlv,
    vlan_members_tlv,
)
from .registry import Backend

if TYPE_CHECKING:
    from .models import VLANInfo
    from .protocols.nsdp.client import AsyncNsdpWriteClient, NsdpWriteClient
    from .registry import SwitchModel
    from .snmp_write import PoeCycleTimeouts

# MEASURED, not assumed -- the exhaustive tag sweep behind ``nsdp_read._SWEEP``
# (real GS110EMX 10.1.5.25, fw 1.0.2.8, 2026-07-30) found no PoE tag anywhere in
# the 16-bit tag space, and that firmware's own web-UI nav (``GET /frame.js``,
# 37 pages) has no PoE page either. Of the three NSDP-class models, only gs305ep
# is a PSE at all, and it reads/writes PoE over its HTTP backend.
_NO_POE = (
    "NSDP has no PoE control tag (measured by an exhaustive tag sweep of a "
    "real GS110EMX, 10.1.5.25 fw 1.0.2.8, 2026-07-30 -- see nsdp_read._SWEEP); "
    "use the HTTP backend for PoE"
)
# NOT PROVEN EITHER WAY, and this says so rather than claiming a device limit.
# The sweep DID find two undocumented per-port 3-byte config tags, 0x0800 and
# 0x9400, shaped (port, 0x01, flow_control) -- byte 1 is a strong candidate for
# the web UI's PHYSICAL_MODE knob (1=Auto, 6=Disable, 2..5 fixed speeds), which
# is how that UI disables a port. It could not be settled, because this firmware
# rejects EVERY NSDP write: an empty WRITE_REQUEST carrying a v1-XOR (or
# plaintext) PASSWORD TLV is answered error=13 then error=14 with the error
# attribute set to 0x000A/ATTR_PASSWORD, after which the switch stops answering
# write requests at all. It wants the v2 salted auth (AUTH_V2_SALT 0x0017 reads
# back a rotating 4-byte salt; AUTH_V2_PASSWORD 0x001A is write-only), whose
# algorithm is undocumented -- deriving it means brute-forcing a live device's
# admin credential, which risks locking the operator out.
_NO_PORT_ADMIN = (
    "per-port admin-enable over NSDP is UNPROVEN on these Plus models: the "
    "measured tag inventory has two candidate per-port config tags (0x0800, "
    "0x9400) but their semantics could not be settled -- the only reachable "
    "NSDP switch (GS110EMX fw 1.0.2.8) rejects every WRITE_REQUEST with "
    "error 13/14 on ATTR_PASSWORD, wanting the undocumented v2 salted auth. "
    "Use the HTTP backend, whose port-settings page IS grounded"
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
        """Create ``vlan`` by writing an EMPTY VLAN_MEMBERS record for it.

        NSDP has no separate "add VLAN" action: the 802.1Q VLAN table is the
        set of VLAN ids that have a VLAN_MEMBERS (0x2800) record, so writing one
        for an id the switch does not yet list is the create. (ngadmin does the
        same thing -- ``ngadmin_setVLANDotConf`` only ever writes the membership
        attribute, and its VLAN list is whatever comes back from reading it.)
        ``name`` is accepted and ignored: the tag carries a VLAN id and two port
        bitmaps and no name field, and there is no name tag in the measured
        inventory -- so a name is silently unstorable here rather than pretended.
        """
        del force  # creating an empty VLAN moves no port; nothing to protect.
        del name
        if any(v.vlan_id == vlan for v in self._reader.get_vlans()):
            return  # already present: creating it again is a no-op, not an error
        self.client.write(
            [vlan_members_tlv(vlan, (), (), self.model.port_count)],
            password=self._password,
        )
        after = self._reader.get_vlans()
        if not any(v.vlan_id == vlan for v in after):
            raise WriteVerificationError(
                f"VLAN {vlan} was not created over NSDP",
                before=None,
                after=[v.vlan_id for v in after],
            )

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        """Delete ``vlan`` with the VLAN_DESTROY action tag (0x2C00).

        Grounded in ngadmin's ``ngadmin_VLANDestroy`` -- see
        ``protocols/nsdp/write.py::vlan_destroy_tlv``. Deleting a VLAN drops
        every member port out of it, so it is force-gated exactly like the other
        disruptive writes.
        """
        if not force:
            raise ProtectedPortError(
                f"deleting VLAN {vlan} removes every member port from it; "
                "pass force=True to override"
            )
        before = [v.vlan_id for v in self._reader.get_vlans()]
        self.client.write([vlan_destroy_tlv(vlan)], password=self._password)
        after = [v.vlan_id for v in self._reader.get_vlans()]
        if vlan in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not deleted over NSDP",
                before=before,
                after=after,
            )


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
        """Async twin of ``NsdpWriter.create_vlan`` -- see there."""
        del force, name
        if any(v.vlan_id == vlan for v in await self._reader.get_vlans()):
            return
        await self.client.write(
            [vlan_members_tlv(vlan, (), (), self.model.port_count)],
            password=self._password,
        )
        after = await self._reader.get_vlans()
        if not any(v.vlan_id == vlan for v in after):
            raise WriteVerificationError(
                f"VLAN {vlan} was not created over NSDP",
                before=None,
                after=[v.vlan_id for v in after],
            )

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        """Async twin of ``NsdpWriter.delete_vlan`` -- see there."""
        if not force:
            raise ProtectedPortError(
                f"deleting VLAN {vlan} removes every member port from it; "
                "pass force=True to override"
            )
        before = [v.vlan_id for v in await self._reader.get_vlans()]
        await self.client.write([vlan_destroy_tlv(vlan)], password=self._password)
        after = [v.vlan_id for v in await self._reader.get_vlans()]
        if vlan in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not deleted over NSDP",
                before=before,
                after=after,
            )
