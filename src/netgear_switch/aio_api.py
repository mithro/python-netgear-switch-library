"""Public asynchronous read/write facade: AsyncSwitch (mirror of SyncSwitch)."""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from ._dispatch import (
    build_async_nsdp_client,
    build_async_snmp_client,
    build_async_snmp_write_client,
    require_mac_table,
    require_nsdp_backend,
)
from .errors import CredentialError, UnsupportedCapabilityError
from .models import SwitchData
from .nsdp_read import AsyncNsdpReader
from .nsdp_write import AsyncNsdpWriter
from .registry import Backend
from .snmp_read import AsyncSnmpReader
from .snmp_write import AsyncSnmpWriter, PoeCycleTimeouts

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()


class _Unset:
    """Sentinel type for "write community not yet resolved" (see
    AsyncSwitch._resolved_write_community): a resolved value of None (no
    community configured) must stay distinguishable from "never resolved"."""


_UNSET = _Unset()

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from .config import SwitchConfig
    from .models import (
        LLDPNeighbor,
        MacEntry,
        MgmtIpConfig,
        PoEStatus,
        PortStats,
        PortStatus,
        Sensor,
        VLANInfo,
        VlanMode,
    )
    from .nsdp_read import AsyncNsdpReader as _AsyncNsdpReaderT  # noqa: F401
    from .protocols.nsdp.client import AsyncNsdpClient, AsyncNsdpWriteClient
    from .protocols.snmp.client import AsyncSnmpClient, AsyncSnmpWriteClient
    from .registry import SwitchModel


class AsyncSwitch:
    """Asynchronous, model-driven read/write facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: AsyncSnmpClient | None = None,
        snmp_write_community: str | None = None,
        snmp_write_client: AsyncSnmpWriteClient | None = None,
        snmp_write_community_resolver: Callable[[], str | None] | None = None,
        nsdp_interface: str | None = None,
        nsdp_client: AsyncNsdpClient | None = None,
        nsdp_write_client: AsyncNsdpWriteClient | None = None,
        nsdp_password: str | None = None,
        nsdp_password_resolver: Callable[[], str | None] | None = None,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client
        self._snmp_write_community = snmp_write_community
        self._snmp_write_client = snmp_write_client
        # Deferred write-community resolution: from_config stashes a closure here
        # instead of resolving eagerly, so read-only construction never raises a
        # CredentialError for an unresolvable write-community spec (review item 4).
        self._snmp_write_community_resolver = snmp_write_community_resolver
        # Sentinel meaning "not yet resolved"; distinct from a resolved value
        # of None (no community configured) so we only ever resolve once.
        self._resolved_write_community: str | None | _Unset = _UNSET
        self._nsdp_interface = nsdp_interface
        self._nsdp_client = nsdp_client
        self._nsdp_write_client = nsdp_write_client
        self._nsdp_password = nsdp_password
        self._nsdp_password_resolver = nsdp_password_resolver
        self._resolved_nsdp_password: str | None | _Unset = _UNSET
        self.protected_ports = protected_ports

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> AsyncSwitch:
        # Resolve the SNMP write community LAZILY (on first write), never here
        # (mirrors SyncSwitch.from_config -- review item 4).
        _env = env if env is not None else os.environ

        def _resolve_write_community() -> str | None:
            return cfg.snmp_write_community(env=_env)

        def _resolve_nsdp_password() -> str | None:
            # Plus switches share ONE web-admin password across HTTP + NSDP, so
            # reusing the http_password spec as the NSDP v1 auth password is
            # intentional and correct. A dedicated ``nsdp.password`` config key is
            # a trivial future follow-up (the facade already accepts a distinct
            # nsdp_password/nsdp_password_resolver) if a deployment ever needs to
            # split them; do NOT add a separate key now.
            return cfg.http_password(env=_env)

        return cls(
            cfg.model, cfg.host,
            snmp_community=cfg.snmp_community,
            snmp_write_community_resolver=_resolve_write_community,
            nsdp_interface=cfg.nsdp_interface,
            nsdp_password_resolver=_resolve_nsdp_password,
            protected_ports=cfg.protected_ports,
        )

    def _reader(self) -> AsyncSnmpReader | AsyncNsdpReader:
        if Backend.SNMP in self.model.backends:
            # Condition guarantees an SNMP backend; no require_snmp_backend guard.
            snmp = self._snmp_client
            if snmp is None:
                snmp = build_async_snmp_client(self.host, self._snmp_community)
            return AsyncSnmpReader(snmp, self.model)
        require_nsdp_backend(self.model)
        nsdp = self._nsdp_client
        if nsdp is None:
            nsdp = build_async_nsdp_client(self.host, self._nsdp_interface)
        return AsyncNsdpReader(nsdp, self.model)

    async def get_ports(self) -> list[PortStatus]:
        return await self._reader().get_ports()

    async def get_stats(self) -> list[PortStats]:
        return await self._reader().get_stats()

    async def get_vlans(self) -> list[VLANInfo]:
        return await self._reader().get_vlans()

    async def get_pvids(self) -> list[tuple[int, int]]:
        return await self._reader().get_pvids()

    async def get_lldp(self) -> list[LLDPNeighbor]:
        return await self._reader().get_lldp()

    async def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return await self._reader().get_macs()

    async def get_poe(self) -> list[PoEStatus]:
        return await self._reader().get_poe()

    async def get_sensors(self) -> list[Sensor]:
        return await self._reader().get_sensors()

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        return await self._reader().get_mgmt_ip()

    async def snapshot(self) -> SwitchData:
        """Aggregate every read op the model's backend supports into one SwitchData."""
        reader = self._reader()

        async def _opt(coro_fn: Callable[[], Awaitable[list[Any]]]) -> tuple[Any, ...]:
            try:
                return tuple(await coro_fn())
            except UnsupportedCapabilityError:
                return ()

        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=tuple(await reader.get_ports()),
            stats=tuple(await reader.get_stats()),
            vlans=tuple(await reader.get_vlans()),
            pvids=tuple(await reader.get_pvids()),
            mgmt_ip=await reader.get_mgmt_ip(),
            poe=await _opt(reader.get_poe),
            lldp=await _opt(reader.get_lldp),
            sensors=await _opt(reader.get_sensors),
            macs=await _opt(reader.get_macs),
        )

    def _resolve_write_community(self) -> str | None:
        # Resolved once on first write, then cached: an explicit community
        # wins, else the stashed from_config resolver runs now (may raise),
        # else None. Every subsequent write reuses the cached result instead
        # of re-invoking the resolver (e.g. a ``!command`` spec must not
        # re-exec its subprocess on every single write).
        if not isinstance(self._resolved_write_community, _Unset):
            return self._resolved_write_community
        resolved: str | None
        if self._snmp_write_community is not None:
            resolved = self._snmp_write_community
        elif self._snmp_write_community_resolver is not None:
            resolved = self._snmp_write_community_resolver()
        else:
            resolved = None
        self._resolved_write_community = resolved
        return resolved

    def _resolve_nsdp_password(self) -> str | None:
        if not isinstance(self._resolved_nsdp_password, _Unset):
            return self._resolved_nsdp_password
        resolved: str | None
        if self._nsdp_password is not None:
            resolved = self._nsdp_password
        elif self._nsdp_password_resolver is not None:
            resolved = self._nsdp_password_resolver()
        else:
            resolved = None
        self._resolved_nsdp_password = resolved
        return resolved

    def _writer(self) -> AsyncSnmpWriter | AsyncNsdpWriter:
        if Backend.SNMP in self.model.backends:
            # Condition guarantees an SNMP backend; no require_snmp_backend guard.
            client = self._snmp_write_client
            if client is None:
                community = self._resolve_write_community()
                client = build_async_snmp_write_client(self.host, community)
            return AsyncSnmpWriter(
                client, self.model, protected_ports=self.protected_ports
            )
        require_nsdp_backend(self.model)
        # Mirror the SNMP _writer() exactly: use the injected write client if
        # given, else build a fresh write client. NEVER fall back to the
        # read-only _nsdp_client (which would produce an AsyncNsdpClient | None
        # union not assignable to AsyncNsdpWriter's AsyncNsdpWriteClient under
        # mypy --strict).
        nsdp = self._nsdp_write_client
        if nsdp is None:
            nsdp = build_async_nsdp_client(self.host, self._nsdp_interface)
        password = self._resolve_nsdp_password()
        if password is None:
            raise CredentialError(
                f"no NSDP admin password configured for {self.host!r}"
            )
        return AsyncNsdpWriter(
            nsdp, self.model, password=password, protected_ports=self.protected_ports
        )

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        await self._writer().set_poe(port, on, force=force)

    async def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        await self._writer().set_port_enabled(port, enabled, force=force)

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        await self._writer().set_pvid(port, vlan, force=force)

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        await self._writer().set_vlan_membership(vlan, port, mode, force=force)

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        await self._writer().create_vlan(vlan, name, force=force)

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        await self._writer().delete_vlan(vlan, force=force)

    async def cycle_poe(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        await self._writer().cycle_poe(port, force=force, timeouts=timeouts)

    async def clear_poe_fault(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        await self._writer().clear_poe_fault(port, force=force, timeouts=timeouts)

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        await self._writer().set_mgmt_ip(address, netmask, gateway, force=force)
