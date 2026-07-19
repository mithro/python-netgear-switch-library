"""Public asynchronous read/write facade: AsyncSwitch (mirror of SyncSwitch)."""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, TypeVar

from ._dispatch import (
    build_async_http_client,
    build_async_nsdp_client,
    build_async_snmp_client,
    build_async_snmp_write_client,
    http_reads_supported,
    require_mac_table,
)
from .errors import CredentialError, ProtectedPortError, UnsupportedCapabilityError
from .http_read import AsyncHttpReader
from .http_write import AsyncHttpWriter
from .models import SwitchData
from .nsdp_read import AsyncNsdpReader
from .nsdp_write import AsyncNsdpWriter
from .registry import Backend
from .snmp_read import AsyncSnmpReader, async_read_system_info
from .snmp_write import AsyncSnmpWriter, PoeCycleTimeouts

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()

_R = TypeVar("_R")
# Per-op backend preference: try SNMP, then NSDP, then HTTP; the first backend
# whose reader/writer serves an op wins. HTTP only ever fills the gaps the
# higher-priority backends raise UnsupportedCapabilityError for.
_BACKEND_PREFERENCE = (Backend.SNMP, Backend.NSDP, Backend.HTTP)


class _Unset:
    """Sentinel type for "write community not yet resolved" (see
    AsyncSwitch._resolved_write_community): a resolved value of None (no
    community configured) must stay distinguishable from "never resolved"."""


_UNSET = _Unset()


class _LazyAsyncHttpSession:
    """Async mirror of ``sync_api._LazyHttpSession``: defers building the real
    AsyncHttpSession (which needs a resolved password) until an op that
    genuinely reaches the wire (``login``/``get_page``/``post_form``) is
    called. Ops an AsyncHttpReader/AsyncHttpWriter refuses honestly WITHOUT
    ever touching the session (e.g. ``get_macs``, ``set_mgmt_ip``) must never
    trigger HTTP password resolution or a live connection."""

    def __init__(self, resolve: Callable[[], AsyncHttpSession]) -> None:
        self._resolve = resolve

    async def login(self) -> None:
        await self._resolve().login()

    async def get_page(self, path: str) -> str:
        return await self._resolve().get_page(path)

    async def post_form(self, path: str, data: dict[str, str]) -> str:
        return await self._resolve().post_form(path, data)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from types import TracebackType
    from typing import Self

    from .config import SwitchConfig
    from .models import (
        DetectedModel,
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
    from .protocols.http.session import AsyncHttpSession
    from .protocols.nsdp.client import AsyncNsdpClient, AsyncNsdpWriteClient
    from .protocols.snmp.client import AsyncSnmpClient, AsyncSnmpWriteClient
    from .registry import SwitchModel
    from .transport.http.client import AsyncHttpClient


async def async_detect_model(
    host: str, *, community: str | None = None, client: AsyncSnmpClient | None = None
) -> DetectedModel:
    """Async twin of ``sync_api.detect_model`` -- see there."""
    if client is None:
        client = build_async_snmp_client(host, community)
    return await async_read_system_info(client)


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
        http_client: AsyncHttpSession | None = None,
        http_password: str | None = None,
        http_password_resolver: Callable[[], str | None] | None = None,
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
        self._http_client = http_client
        self._http_password = http_password
        self._http_password_resolver = http_password_resolver
        self._resolved_http_password: str | None | _Unset = _UNSET
        # A self-built AsyncHttpClient is the ONLY backend that holds a
        # persistent connection worth closing (SNMP/NSDP clients are built
        # fresh per call and need no equivalent teardown). Tracked separately
        # from `_http_client` so `aclose()` only ever tears down a client THIS
        # facade built -- never one the caller injected and therefore owns.
        self._built_http_client: AsyncHttpClient | None = None
        self._reader_cache: dict[
            Backend, AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader
        ] = {}
        self._writer_cache: dict[
            Backend, AsyncSnmpWriter | AsyncNsdpWriter | AsyncHttpWriter
        ] = {}
        self.protected_ports = protected_ports

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release the HTTP client THIS facade built (never one injected by
        the caller). Safe to call even when no HTTP op was ever dispatched."""
        if self._built_http_client is not None:
            await self._built_http_client.aclose()
            self._built_http_client = None

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

        def _resolve_http_password() -> str | None:
            return cfg.http_password(env=_env)

        return cls(
            cfg.model, cfg.host,
            snmp_community=cfg.snmp_community,
            snmp_write_community_resolver=_resolve_write_community,
            nsdp_interface=cfg.nsdp_interface,
            nsdp_password_resolver=_resolve_nsdp_password,
            http_password_resolver=_resolve_http_password,
            protected_ports=cfg.protected_ports,
        )

    def _http_session(self) -> AsyncHttpSession:
        if self._http_client is not None:
            return self._http_client
        if self._built_http_client is None:
            self._built_http_client = build_async_http_client(
                self.host, self._resolve_http_password(), self.model
            )
        return self._built_http_client

    def _resolve_http_password(self) -> str | None:
        if not isinstance(self._resolved_http_password, _Unset):
            return self._resolved_http_password
        resolved: str | None
        if self._http_password is not None:
            resolved = self._http_password
        elif self._http_password_resolver is not None:
            resolved = self._http_password_resolver()
        else:
            resolved = None
        self._resolved_http_password = resolved
        return resolved

    def _reader_for(
        self, backend: Backend
    ) -> AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader:
        cached = self._reader_cache.get(backend)
        if cached is not None:
            return cached
        reader: AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader
        if backend is Backend.SNMP:
            client = self._snmp_client
            if client is None:
                client = build_async_snmp_client(self.host, self._snmp_community)
            reader = AsyncSnmpReader(client, self.model)
        elif backend is Backend.NSDP:
            nsdp = self._nsdp_client
            if nsdp is None:
                nsdp = build_async_nsdp_client(self.host, self._nsdp_interface)
            reader = AsyncNsdpReader(nsdp, self.model)
        else:  # Backend.HTTP
            if not http_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} HTTP reads are "
                    "UNVERIFIED-pending-capture"
                )
            reader = AsyncHttpReader(
                _LazyAsyncHttpSession(self._http_session), self.model
            )
        self._reader_cache[backend] = reader
        return reader

    def _writer_for(
        self, backend: Backend
    ) -> AsyncSnmpWriter | AsyncNsdpWriter | AsyncHttpWriter:
        cached = self._writer_cache.get(backend)
        if cached is not None:
            return cached
        writer: AsyncSnmpWriter | AsyncNsdpWriter | AsyncHttpWriter
        if backend is Backend.SNMP:
            client = self._snmp_write_client
            if client is None:
                client = build_async_snmp_write_client(
                    self.host, self._resolve_write_community()
                )
            writer = AsyncSnmpWriter(
                client, self.model, protected_ports=self.protected_ports
            )
        elif backend is Backend.NSDP:
            nsdp = self._nsdp_write_client
            if nsdp is None:
                nsdp = build_async_nsdp_client(self.host, self._nsdp_interface)
            password = self._resolve_nsdp_password()
            if password is None:
                raise CredentialError(
                    f"no NSDP admin password configured for {self.host!r}"
                )
            writer = AsyncNsdpWriter(
                nsdp, self.model, password=password,
                protected_ports=self.protected_ports,
            )
        else:  # Backend.HTTP
            if not http_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} HTTP writes are "
                    "UNVERIFIED-pending-capture"
                )
            writer = AsyncHttpWriter(
                _LazyAsyncHttpSession(self._http_session), self.model,
                protected_ports=self.protected_ports,
            )
        self._writer_cache[backend] = writer
        return writer

    async def _read(
        self,
        op: Callable[
            [AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader], Awaitable[_R]
        ],
    ) -> _R:
        last: UnsupportedCapabilityError | None = None
        for backend in _BACKEND_PREFERENCE:
            if backend not in self.model.backends:
                continue
            try:
                reader = self._reader_for(backend)
            except UnsupportedCapabilityError as exc:
                last = exc
                continue
            try:
                return await op(reader)
            except UnsupportedCapabilityError as exc:
                last = exc
        if last is not None:
            raise last
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} has no backend supporting this operation"
        )

    async def _write(
        self,
        op: Callable[
            [AsyncSnmpWriter | AsyncNsdpWriter | AsyncHttpWriter], Awaitable[None]
        ],
    ) -> None:
        last: UnsupportedCapabilityError | None = None
        for backend in _BACKEND_PREFERENCE:
            if backend not in self.model.backends:
                continue
            try:
                writer = self._writer_for(backend)
            except UnsupportedCapabilityError as exc:
                last = exc
                continue
            try:
                await op(writer)
                return
            except UnsupportedCapabilityError as exc:
                last = exc
        if last is not None:
            raise last
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} has no backend supporting this operation"
        )

    async def get_ports(self) -> list[PortStatus]:
        return await self._read(lambda r: r.get_ports())

    async def get_stats(self) -> list[PortStats]:
        return await self._read(lambda r: r.get_stats())

    async def get_vlans(self) -> list[VLANInfo]:
        return await self._read(lambda r: r.get_vlans())

    async def get_pvids(self) -> list[tuple[int, int]]:
        return await self._read(lambda r: r.get_pvids())

    async def get_lldp(self) -> list[LLDPNeighbor]:
        return await self._read(lambda r: r.get_lldp())

    async def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return await self._read(lambda r: r.get_macs())

    async def get_poe(self) -> list[PoEStatus]:
        return await self._read(lambda r: r.get_poe())

    async def get_sensors(self) -> list[Sensor]:
        return await self._read(lambda r: r.get_sensors())

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        return await self._read(lambda r: r.get_mgmt_ip())

    async def identify(self) -> DetectedModel:
        """Async twin of ``SyncSwitch.identify`` -- see there."""
        client = self._snmp_client
        if client is None:
            client = build_async_snmp_client(self.host, self._snmp_community)
        return await async_read_system_info(client)

    async def snapshot(self) -> SwitchData:
        """Aggregate every read op, routing each field to the first backend
        that supports it (SNMP > NSDP > HTTP). A field NO backend can serve
        degrades to ()/None; a field a backend DOES serve stays populated
        (gs305ep: ports/stats/vlans/pvids/mgmt via NSDP, poe via HTTP)."""

        async def _opt(
            op: Callable[
                [AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader],
                Awaitable[list[Any]],
            ],
        ) -> tuple[Any, ...]:
            try:
                return tuple(await self._read(op))
            except UnsupportedCapabilityError:
                return ()

        try:
            mgmt: MgmtIpConfig | None = await self._read(lambda r: r.get_mgmt_ip())
        except UnsupportedCapabilityError:
            mgmt = None

        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=await _opt(lambda r: r.get_ports()),
            stats=await _opt(lambda r: r.get_stats()),
            vlans=await _opt(lambda r: r.get_vlans()),
            pvids=await _opt(lambda r: r.get_pvids()),
            mgmt_ip=mgmt,
            poe=await _opt(lambda r: r.get_poe()),
            lldp=await _opt(lambda r: r.get_lldp()),
            sensors=await _opt(lambda r: r.get_sensors()),
            macs=await _opt(lambda r: r.get_macs()),
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

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        await self._write(lambda w: w.set_poe(port, on, force=force))

    async def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        await self._write(lambda w: w.set_port_enabled(port, enabled, force=force))

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        await self._write(lambda w: w.set_pvid(port, vlan, force=force))

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        await self._write(
            lambda w: w.set_vlan_membership(vlan, port, mode, force=force)
        )

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        await self._write(lambda w: w.create_vlan(vlan, name, force=force))

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        # SAFETY RAIL: mirrors SyncSwitch.delete_vlan (see its docstring).
        # HttpWriter.delete_vlan does NOT itself guard protected member ports,
        # and NsdpWriter.delete_vlan ALWAYS raises UnsupportedCapabilityError
        # (NSDP has no VLAN lifecycle ops), so any {NSDP, HTTP} model falls
        # straight through to HTTP -- guard here so every backend gets the
        # same protected-port safety rail.
        await self._guard_vlan_delete_members(vlan, force=force)
        await self._write(lambda w: w.delete_vlan(vlan, force=force))

    async def _guard_vlan_delete_members(self, vlan: int, *, force: bool) -> None:
        if force:
            return
        try:
            vlans = await self._read(lambda r: r.get_vlans())
        except UnsupportedCapabilityError:
            return
        for v in vlans:
            if v.vlan_id == vlan:
                clash = v.member_ports & self.protected_ports
                if clash:
                    raise ProtectedPortError(
                        f"VLAN {vlan} includes protected port(s) {sorted(clash)}; "
                        f"pass force=True to delete it anyway"
                    )
                return

    async def cycle_poe(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        await self._write(lambda w: w.cycle_poe(port, force=force, timeouts=timeouts))

    async def clear_poe_fault(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        await self._write(
            lambda w: w.clear_poe_fault(port, force=force, timeouts=timeouts)
        )

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        await self._write(
            lambda w: w.set_mgmt_ip(address, netmask, gateway, force=force)
        )
