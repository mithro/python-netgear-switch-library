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
    require_http_backend,
    require_mac_table,
    resolve_backend,
)
from .errors import CredentialError, ProtectedPortError, UnsupportedCapabilityError
from .http_read import AsyncHttpReader
from .http_write import AsyncHttpWriter, _reject_known_unimplemented_cert_upload
from .models import SwitchData
from .nsdp_read import AsyncNsdpReader
from .nsdp_write import AsyncNsdpWriter
from .registry import Backend
from .snmp_read import AsyncSnmpReader, async_read_system_info
from .snmp_write import AsyncSnmpWriter, PoeCycleTimeouts

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()

_R = TypeVar("_R")
# DEFAULT backend resolution order, used ONLY when the caller does not name a
# backend -- identical to sync_api._BACKEND_PREFERENCE, and with the same NO
# SILENT FALLBACK contract: exactly one backend runs and an op it cannot serve
# raises instead of being re-routed. See sync_api for the full rationale.
_BACKEND_PREFERENCE = (
    Backend.SNMP,
    Backend.NSDP,
    Backend.HTTP,
    Backend.SSH,
    Backend.TELNET,
    Backend.CONSOLE,
)


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

    async def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        return await self._resolve().post_multipart(path, data, file)

    async def post_xml(self, path: str, body: str) -> str:
        return await self._resolve().post_xml(path, body)


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
        PortSpeed,
        PortStats,
        PortStatus,
        Sensor,
        ServiceStatus,
        SwitchUser,
        SyslogConfig,
        VLANInfo,
        VlanMode,
    )
    from .protocols.http.session import AsyncHttpSession, MultipartFile
    from .protocols.nsdp.client import AsyncNsdpClient, AsyncNsdpWriteClient
    from .protocols.nsdp.types import NsdpDevice
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
        backend: Backend | None = None,
    ) -> None:
        self.model = model
        self.host = host
        # Default backend for every op on this facade -- see SyncSwitch.
        self.backend = backend
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
            cfg.model,
            cfg.host,
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
        elif backend is Backend.HTTP:
            if not http_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} HTTP reads are "
                    "UNVERIFIED-pending-capture"
                )
            reader = AsyncHttpReader(
                _LazyAsyncHttpSession(self._http_session), self.model
            )
        else:  # a CLI backend (SSH/telnet/console)
            # All three CLI transports are synchronous (paramiko / telnetlib /
            # pyserial) and none has an async twin, so the async facade cannot
            # serve a CLI read without blocking the event loop. Refuse honestly
            # instead; SyncSwitch has the full CLI surface, and a caller who
            # wants it from async code can wrap that in asyncio.to_thread.
            #
            # NOTE: this is now the ONLY reason. The message used to also cite
            # reads_verified=False, which stopped being true once all four
            # FASTPATH CLI specs were cross-verified -- saying it here made the
            # error blame a gate that no longer applies.
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} CLI reads are not available via the "
                "async facade: the CLI transports are synchronous -- use "
                "SyncSwitch, or asyncio.to_thread"
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
                nsdp,
                self.model,
                password=password,
                protected_ports=self.protected_ports,
            )
        elif backend is Backend.HTTP:
            if not http_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} HTTP writes are "
                    "UNVERIFIED-pending-capture"
                )
            writer = AsyncHttpWriter(
                _LazyAsyncHttpSession(self._http_session),
                self.model,
                protected_ports=self.protected_ports,
            )
        else:  # a CLI backend (SSH/telnet/console)
            # A CLI VLAN write backend DOES exist (cli_write.CliWriter, wired
            # into SyncSwitch), but only synchronously: all three CLI transports
            # (paramiko SSH, telnetlib, pyserial console) are blocking and have
            # no async twin, so the async facade has no CLI backend at all --
            # exactly like async CLI reads and upload_certificate_scp. Honest
            # UnsupportedCapabilityError naming the real reason; SNMP remains the
            # async write path for every FASTPATH model.
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} CLI writes are not available via the "
                "async facade (the CLI transports are synchronous) -- use "
                "SyncSwitch for CLI writes"
            )
        self._writer_cache[backend] = writer
        return writer

    def resolve_backend(self, backend: Backend | None = None) -> Backend:
        """Async twin of ``SyncSwitch.resolve_backend`` -- see there."""
        return resolve_backend(self.model, backend or self.backend, _BACKEND_PREFERENCE)

    def _cannot_serve(
        self,
        chosen: Backend,
        requested: Backend | None,
        exc: UnsupportedCapabilityError,
    ) -> UnsupportedCapabilityError:
        """Async twin of ``SyncSwitch._cannot_serve`` -- see there."""
        if requested is None:
            others = sorted(b.name for b in self.model.backends if b is not chosen)
            hint = (
                f"; pass backend=Backend.<{'|'.join(others)}> to use another backend"
                if others
                else ""
            )
            return UnsupportedCapabilityError(
                f"model {self.model.key!r}: the default backend {chosen.name} "
                f"cannot serve this operation: {exc}{hint}"
            )
        return UnsupportedCapabilityError(
            f"model {self.model.key!r}: the requested backend {chosen.name} "
            f"cannot serve this operation: {exc}"
        )

    async def _read(
        self,
        op: Callable[
            [AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader], Awaitable[_R]
        ],
        backend: Backend | None,
    ) -> _R:
        # ONE backend, no fallback -- see sync_api._read.
        requested = backend or self.backend
        chosen = self.resolve_backend(requested)
        reader = self._reader_for(chosen)
        try:
            return await op(reader)
        except UnsupportedCapabilityError as exc:
            raise self._cannot_serve(chosen, requested, exc) from exc

    async def _write(
        self,
        op: Callable[
            [AsyncSnmpWriter | AsyncNsdpWriter | AsyncHttpWriter], Awaitable[None]
        ],
        backend: Backend | None,
    ) -> None:
        requested = backend or self.backend
        chosen = self.resolve_backend(requested)
        writer = self._writer_for(chosen)
        try:
            await op(writer)
        except UnsupportedCapabilityError as exc:
            raise self._cannot_serve(chosen, requested, exc) from exc

    # Every read/write op takes an optional keyword-only ``backend`` -- see the
    # equivalent note on SyncSwitch: one backend runs, named or defaulted, and an
    # op it cannot serve raises instead of being silently re-routed.

    async def get_ports(self, *, backend: Backend | None = None) -> list[PortStatus]:
        return await self._read(lambda r: r.get_ports(), backend)

    async def get_stats(self, *, backend: Backend | None = None) -> list[PortStats]:
        return await self._read(lambda r: r.get_stats(), backend)

    async def get_vlans(self, *, backend: Backend | None = None) -> list[VLANInfo]:
        return await self._read(lambda r: r.get_vlans(), backend)

    async def get_pvids(
        self, *, backend: Backend | None = None
    ) -> list[tuple[int, int]]:
        return await self._read(lambda r: r.get_pvids(), backend)

    async def get_lldp(self, *, backend: Backend | None = None) -> list[LLDPNeighbor]:
        return await self._read(lambda r: r.get_lldp(), backend)

    async def get_macs(self, *, backend: Backend | None = None) -> list[MacEntry]:
        require_mac_table(self.model)
        return await self._read(lambda r: r.get_macs(), backend)

    async def get_poe(self, *, backend: Backend | None = None) -> list[PoEStatus]:
        return await self._read(lambda r: r.get_poe(), backend)

    async def get_sensors(self, *, backend: Backend | None = None) -> list[Sensor]:
        return await self._read(lambda r: r.get_sensors(), backend)

    async def get_mgmt_ip(self, *, backend: Backend | None = None) -> MgmtIpConfig:
        return await self._read(lambda r: r.get_mgmt_ip(), backend)

    async def get_syslog(self, *, backend: Backend | None = None) -> SyslogConfig:
        """Async twin of ``SyncSwitch.get_syslog`` -- see there."""
        return await self._read(lambda r: r.get_syslog(), backend)

    async def get_users(self, *, backend: Backend | None = None) -> list[SwitchUser]:
        """Async twin of ``SyncSwitch.get_users``.

        AsyncSwitch has no CLI backend, so this refuses on every model -- the
        same honest refusal every async CLI read gives.
        """
        return await self._read(lambda r: r.get_users(), backend)

    async def get_services(
        self, *, backend: Backend | None = None
    ) -> list[ServiceStatus]:
        """Async twin of ``SyncSwitch.get_services`` -- CLI only, see there."""
        return await self._read(lambda r: r.get_services(), backend)

    async def get_hostname(self, *, backend: Backend | None = None) -> str:
        """Async twin of ``SyncSwitch.get_hostname`` -- see there."""
        return await self._read(lambda r: r.get_hostname(), backend)

    async def nsdp_device(self) -> NsdpDevice:
        """Async twin of ``SyncSwitch.nsdp_device`` -- see there."""
        reader = self._reader_for(Backend.NSDP)
        assert isinstance(reader, AsyncNsdpReader)
        return await reader.get_device()

    async def identify(self) -> DetectedModel:
        """Async twin of ``SyncSwitch.identify`` -- see there."""
        client = self._snmp_client
        if client is None:
            client = build_async_snmp_client(self.host, self._snmp_community)
        return await async_read_system_info(client)

    async def snapshot(self, *, backend: Backend | None = None) -> SwitchData:
        """Async twin of ``SyncSwitch.snapshot``: every read op over ONE backend
        (named, or this model's default), with a field that backend cannot serve
        degrading to ()/None rather than being re-read over another protocol."""

        async def _opt(
            op: Callable[
                [AsyncSnmpReader | AsyncNsdpReader | AsyncHttpReader],
                Awaitable[list[Any]],
            ],
        ) -> tuple[Any, ...]:
            try:
                return tuple(await self._read(op, backend))
            except UnsupportedCapabilityError:
                return ()

        try:
            mgmt: MgmtIpConfig | None = await self._read(
                lambda r: r.get_mgmt_ip(), backend
            )
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

    async def set_poe(
        self,
        port: int,
        on: bool,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(lambda w: w.set_poe(port, on, force=force), backend)

    async def set_port_enabled(
        self,
        port: int,
        enabled: bool,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(
            lambda w: w.set_port_enabled(port, enabled, force=force), backend
        )

    async def set_port_description(
        self,
        port: int,
        description: str,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Async twin of ``SyncSwitch.set_port_description`` -- see it."""
        await self._write(
            lambda w: w.set_port_description(port, description, force=force), backend
        )

    async def set_port_speed(
        self,
        port: int,
        speed: PortSpeed,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Async twin of ``SyncSwitch.set_port_speed`` -- see it.

        Every async backend refuses this: the operation is served over the
        FASTPATH CLI, and all three CLI transports (paramiko SSH, telnet,
        pyserial console) are synchronous, so ``AsyncSwitch`` has no CLI
        backend at all. Kept present so the refusal names the backend rather
        than surfacing as ``AttributeError``.
        """
        await self._write(lambda w: w.set_port_speed(port, speed, force=force), backend)

    async def set_flow_control(
        self,
        port: int,
        enabled: bool,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Async twin of ``SyncSwitch.set_flow_control`` -- see it.

        Like ``set_port_speed``, every async backend refuses: this op is served
        over the CLI, whose three transports are all synchronous.
        """
        await self._write(
            lambda w: w.set_flow_control(port, enabled, force=force), backend
        )

    async def set_pvid(
        self,
        port: int,
        vlan: int,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(lambda w: w.set_pvid(port, vlan, force=force), backend)

    async def set_vlan_membership(
        self,
        vlan: int,
        port: int,
        mode: VlanMode,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(
            lambda w: w.set_vlan_membership(vlan, port, mode, force=force), backend
        )

    async def create_vlan(
        self,
        vlan: int,
        name: str,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(lambda w: w.create_vlan(vlan, name, force=force), backend)

    async def delete_vlan(
        self, vlan: int, *, force: bool = False, backend: Backend | None = None
    ) -> None:
        # SAFETY RAIL: mirrors SyncSwitch.delete_vlan (see its docstring) --
        # neither the HTTP nor the NSDP writer guards protected member ports for
        # a VLAN delete, so the facade does it for every backend, reading over
        # the SAME backend the delete will use.
        await self._guard_vlan_delete_members(vlan, force=force, backend=backend)
        await self._write(lambda w: w.delete_vlan(vlan, force=force), backend)

    async def _guard_vlan_delete_members(
        self, vlan: int, *, force: bool, backend: Backend | None
    ) -> None:
        if force:
            return
        try:
            vlans = await self._read(lambda r: r.get_vlans(), backend)
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
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        backend: Backend | None = None,
    ) -> None:
        await self._write(
            lambda w: w.cycle_poe(port, force=force, timeouts=timeouts), backend
        )

    async def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
        backend: Backend | None = None,
    ) -> None:
        await self._write(
            lambda w: w.clear_poe_fault(port, force=force, timeouts=timeouts), backend
        )

    async def set_syslog_enabled(
        self,
        enabled: bool,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Turn remote syslog on or off.

        Served over SNMP here. The CLI serves it too, but not asynchronously --
        all three CLI transports are synchronous, so ``AsyncSwitch`` has no CLI
        backend.
        """
        await self._write(lambda w: w.set_syslog_enabled(enabled, force=force), backend)

    async def add_syslog_collector(
        self,
        host: str,
        *,
        port: int = 514,
        severity: int = 6,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Async twin of ``SyncSwitch.add_syslog_collector`` -- see it.

        Every async backend refuses: this op is served over the CLI, whose
        transports are all synchronous.
        """
        await self._write(
            lambda w: w.add_syslog_collector(
                host, port=port, severity=severity, force=force
            ),
            backend,
        )

    async def remove_syslog_collector(
        self,
        host: str,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        """Async twin of ``SyncSwitch.remove_syslog_collector`` -- see it."""
        await self._write(
            lambda w: w.remove_syslog_collector(host, force=force), backend
        )

    async def set_hostname(
        self, name: str, *, force: bool = False, backend: Backend | None = None
    ) -> None:
        """Async twin of ``SyncSwitch.set_hostname`` -- see there.

        Note AsyncSwitch has no CLI backend at all, so on this facade the write
        resolves over SNMP or not at all.
        """
        await self._write(lambda w: w.set_hostname(name, force=force), backend)

    async def set_mgmt_ip(
        self,
        address: str,
        netmask: str,
        gateway: str,
        *,
        force: bool = False,
        backend: Backend | None = None,
    ) -> None:
        await self._write(
            lambda w: w.set_mgmt_ip(address, netmask, gateway, force=force), backend
        )

    def _cert_writer(self) -> AsyncHttpWriter:
        # See SyncSwitch._cert_writer: cert upload bypasses both the
        # http_reads_supported gate and the SNMP-first _write dispatch.
        return AsyncHttpWriter(
            _LazyAsyncHttpSession(self._http_session),
            self.model,
            protected_ports=self.protected_ports,
        )

    async def upload_certificate(
        self, cert_pem: str, key_pem: str, *, force: bool = False
    ) -> None:
        """Async twin of ``SyncSwitch.upload_certificate`` -- see there."""
        _reject_known_unimplemented_cert_upload(self.model.key)
        require_http_backend(self.model)
        await self._cert_writer().upload_certificate(cert_pem, key_pem, force=force)

    async def upload_certificate_scp(
        self,
        *,
        scp_source: str,
        scp_password: str,
        remote_dir: str,
        chain: bool = False,
    ) -> None:
        """Async twin of ``SyncSwitch.upload_certificate_scp`` (FASTPATH SCP cert
        deploy). The op is CLI/SCP-based, and CLI transports are SYNCHRONOUS --
        the async facade has no CLI backend (the same reason async CLI reads and
        writes are unavailable). The method EXISTS for API-surface parity but
        honestly raises ``UnsupportedCapabilityError`` rather than silently
        lacking it: use ``SyncSwitch.upload_certificate_scp`` for this op.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: upload_certificate_scp is CLI/SCP-based "
            "and the async facade has no CLI backend (CLI is synchronous) -- "
            "use SyncSwitch.upload_certificate_scp"
        )
