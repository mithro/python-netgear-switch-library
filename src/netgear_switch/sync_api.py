"""Public synchronous read/write facade: SyncSwitch."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, TypeVar

from ._dispatch import (
    build_sync_cli_client,
    build_sync_http_client,
    build_sync_nsdp_client,
    build_sync_snmp_client,
    build_sync_snmp_write_client,
    cli_reads_supported,
    http_reads_supported,
    require_http_backend,
    require_mac_table,
)
from .cli_read import CliReader
from .cli_write import deploy_certificate_scp
from .errors import CredentialError, ProtectedPortError, UnsupportedCapabilityError
from .http_read import HttpReader
from .http_write import HttpWriter, _reject_known_unimplemented_cert_upload
from .models import SwitchData
from .nsdp_read import NsdpReader
from .nsdp_write import NsdpWriter
from .registry import Backend
from .snmp_read import SnmpReader, read_system_info
from .snmp_write import PoeCycleTimeouts, SnmpWriter

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()

_R = TypeVar("_R")
# Per-op backend preference: try SNMP, then NSDP, then HTTP; the first backend
# whose reader/writer serves an op wins. HTTP joins this fallback only when a
# higher-priority backend's reader/writer CONSTRUCTION raises
# UnsupportedCapabilityError, or the op method itself explicitly raises it
# (e.g. NSDP's get_macs/get_lldp/get_sensors/get_poe -- see nsdp_read.py's
# "_NO_*" constants). NSDP's get_stats/get_mgmt_ip are NOT such ops: they
# always return a (possibly sparse) result rather than raising
# UnsupportedCapabilityError, so for a {NSDP, HTTP} model (e.g. gs110emx)
# those two ops are ALWAYS served by NSDP through this facade -- their real
# HTTP implementations in http_read.py are unreachable here; only a
# directly-constructed HttpReader ever exercises them. Do not read this
# preference order as "HTTP only fills gaps" more broadly than that.
_BACKEND_PREFERENCE = (Backend.SNMP, Backend.NSDP, Backend.HTTP, Backend.SSH)

# The four reader backends a SyncSwitch may build (SNMP/NSDP/HTTP/CLI).
_AnyReader = SnmpReader | NsdpReader | HttpReader | CliReader


class _Unset:
    """Sentinel type for "write community not yet resolved" (see
    SyncSwitch._resolved_write_community): a resolved value of None (no
    community configured) must stay distinguishable from "never resolved"."""


_UNSET = _Unset()


class _LazyHttpSession:
    """Wraps ``SyncSwitch._http_session`` so building the real HttpSession
    (which needs a resolved password) is deferred until an op that genuinely
    reaches the wire (``login``/``get_page``/``post_form``) is called. Ops an
    HttpReader/HttpWriter refuses honestly WITHOUT ever touching the session
    (e.g. ``get_macs``, ``set_mgmt_ip``) must never trigger HTTP password
    resolution or a live connection -- only per-op routing that HTTP actually
    ends up serving should pay that cost."""

    def __init__(self, resolve: Callable[[], HttpSession]) -> None:
        self._resolve = resolve

    def login(self) -> None:
        self._resolve().login()

    def get_page(self, path: str) -> str:
        return self._resolve().get_page(path)

    def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._resolve().post_form(path, data)

    def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        return self._resolve().post_multipart(path, data, file)

    def post_xml(self, path: str, body: str) -> str:
        return self._resolve().post_xml(path, body)


class _LazyCliSession:
    """Wraps CLI-transport construction so building the real SSH session (which
    needs a resolved password and raises ``CredentialError`` if none is set) is
    deferred until an op actually RUNS a command. Ops a ``CliReader`` refuses
    WITHOUT touching the session -- e.g. ``get_poe`` on a non-PoE model, which
    raises ``UnsupportedCapabilityError`` before any ``run()`` -- must never
    trigger CLI password resolution or a live connection. Without this, the
    facade's SSH fall-through for such an op raised ``CredentialError`` instead
    of the honest ``UnsupportedCapabilityError`` (and diverged from AsyncSwitch,
    which never builds a CLI client)."""

    def __init__(self, resolve: Callable[[], CliSession]) -> None:
        self._resolve = resolve
        self._session: CliSession | None = None

    def _live(self) -> CliSession:
        if self._session is None:
            self._session = self._resolve()
        return self._session

    def run(self, command: str) -> str:
        return self._live().run(command)

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        return self._live().run_scp_copy(command, scp_password)

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        return self._live().run_write_memory(command, prestuff=prestuff)

    def close(self) -> None:
        if self._session is not None:
            self._session.close()


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
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
    from .protocols.http.session import HttpSession, MultipartFile
    from .protocols.nsdp.client import NsdpClient, NsdpWriteClient
    from .protocols.nsdp.types import NsdpDevice
    from .protocols.snmp.client import SnmpClient, SnmpWriteClient
    from .registry import SwitchModel
    from .transport.cli.session import CliSession
    from .transport.http.client import HttpClient


def detect_model(
    host: str, *, community: str | None = None, client: SnmpClient | None = None
) -> DetectedModel:
    """Identify a switch's model over SNMP, WITHOUT already knowing/hardcoding
    it -- the discovery entry point a caller (e.g. gdoc2netcfg) uses BEFORE it
    can construct a ``SyncSwitch`` at all: call this first, then
    ``registry.get_model(detected.key)`` + ``SyncSwitch(...)`` once
    ``detected.key`` is not ``None``. See ``models.DetectedModel`` /
    ``protocols.snmp.parse.detect_model_from_sysdescr`` for exactly how (and
    why) an unmatched sysDescr honestly yields ``key=None`` rather than a
    guess.

    Builds the default net-snmp CLI client from ``host``/``community`` unless
    ``client`` is injected (tests, or an already-open connection).
    """
    if client is None:
        client = build_sync_snmp_client(host, community)
    return read_system_info(client)


class SyncSwitch:
    """Synchronous, model-driven read/write facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: SnmpClient | None = None,
        snmp_write_community: str | None = None,
        snmp_write_client: SnmpWriteClient | None = None,
        snmp_write_community_resolver: Callable[[], str | None] | None = None,
        nsdp_interface: str | None = None,
        nsdp_client: NsdpClient | None = None,
        nsdp_write_client: NsdpWriteClient | None = None,
        nsdp_password: str | None = None,
        nsdp_password_resolver: Callable[[], str | None] | None = None,
        http_client: HttpSession | None = None,
        http_password: str | None = None,
        http_password_resolver: Callable[[], str | None] | None = None,
        cli_client: CliSession | None = None,
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
        # An injected CLI session (tests use VirtualSwitch.cli_session(); a live
        # caller lets the facade build the SSH transport on demand). Only the
        # CLI cert-deploy path uses it today.
        self._cli_client = cli_client
        # A self-built HttpClient is the ONLY backend that holds a persistent
        # connection worth closing (SNMP/NSDP clients are built fresh per call
        # and need no equivalent teardown). Tracked separately from
        # `_http_client` so `close()` only ever tears down a client THIS facade
        # built -- never one the caller injected and therefore owns.
        self._built_http_client: HttpClient | None = None
        self._reader_cache: dict[Backend, _AnyReader] = {}
        self._writer_cache: dict[Backend, SnmpWriter | NsdpWriter | HttpWriter] = {}
        self.protected_ports = protected_ports

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release the HTTP client THIS facade built (never one injected by
        the caller). Safe to call even when no HTTP op was ever dispatched."""
        if self._built_http_client is not None:
            self._built_http_client.close()
            self._built_http_client = None

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> SyncSwitch:
        # Resolve the SNMP write community LAZILY (on first write), never here.
        # A read-only consumer whose env lacks a resolvable write-community spec
        # (e.g. ``${UNSET_VAR}``) must still be able to construct the facade and
        # read; only an actual write attempt may raise CredentialError/ConfigError
        # (review item 4). We stash a closure that reads the spec + env on demand.
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

    def _http_session(self) -> HttpSession:
        if self._http_client is not None:
            return self._http_client
        if self._built_http_client is None:
            self._built_http_client = build_sync_http_client(
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

    def _reader_for(self, backend: Backend) -> _AnyReader:
        cached = self._reader_cache.get(backend)
        if cached is not None:
            return cached
        reader: _AnyReader
        if backend is Backend.SNMP:
            client = self._snmp_client
            if client is None:
                client = build_sync_snmp_client(self.host, self._snmp_community)
            reader = SnmpReader(client, self.model)
        elif backend is Backend.NSDP:
            nsdp = self._nsdp_client
            if nsdp is None:
                nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
            reader = NsdpReader(nsdp, self.model)
        elif backend is Backend.HTTP:
            # UNVERIFIED-reads models (gsm7228ps cheetah) refuse HERE -- before
            # any session build -- so the per-op loop sees a plain
            # UnsupportedCapabilityError, NOT a CredentialError from resolving a
            # web password this backend will never use. (gs110emx's HTTP reads
            # are grounded -- see protocols/http/endpoints.py -- but NSDP is
            # still authoritative for every op it serves, and NSDP's
            # get_stats/get_mgmt_ip never raise UnsupportedCapabilityError, so
            # this HTTP reader is only ever reached here for ops NSDP
            # genuinely lacks -- see _BACKEND_PREFERENCE's comment above.)
            if not http_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} HTTP reads are "
                    "UNVERIFIED-pending-capture"
                )
            reader = HttpReader(_LazyHttpSession(self._http_session), self.model)
        else:  # a CLI backend (SSH/telnet/console)
            # CLI reads are gated like HTTP: a model whose CLI spec is
            # reads_verified=False (not yet CLI<->SNMP cross-verified) raises
            # here. The FASTPATH models (m4300-24x/-16x, gsm7252ps) ARE verified,
            # so a real SSH CliReader is built for them (reusing the web-admin
            # password as the CLI password by default). The session is LAZY: the
            # SSH connection + password (CredentialError if unset) are deferred
            # to the first command, so an op the reader refuses without a command
            # -- e.g. get_poe on a non-PoE m4300-24x -- raises the honest
            # UnsupportedCapabilityError, never CredentialError, matching every
            # other backend and the async facade. The mock CLI face is exercised
            # separately via VirtualSwitch.cli_session(), not through here.
            if not cli_reads_supported(self.model):
                raise UnsupportedCapabilityError(
                    f"model {self.model.key!r} CLI reads are "
                    "UNVERIFIED-pending cross-verify"
                )
            reader = CliReader(
                _LazyCliSession(
                    lambda: build_sync_cli_client(
                        self.host,
                        "admin",
                        self._resolve_http_password(),
                        self.model,
                    )
                ),
                self.model,
            )
        self._reader_cache[backend] = reader
        return reader

    def _writer_for(self, backend: Backend) -> SnmpWriter | NsdpWriter | HttpWriter:
        cached = self._writer_cache.get(backend)
        if cached is not None:
            return cached
        writer: SnmpWriter | NsdpWriter | HttpWriter
        if backend is Backend.SNMP:
            client = self._snmp_write_client
            if client is None:
                client = build_sync_snmp_write_client(
                    self.host, self._resolve_write_community()
                )
            writer = SnmpWriter(
                client, self.model, protected_ports=self.protected_ports
            )
        elif backend is Backend.NSDP:
            nsdp = self._nsdp_write_client
            if nsdp is None:
                nsdp = build_sync_nsdp_client(self.host, self._nsdp_interface)
            password = self._resolve_nsdp_password()
            if password is None:
                raise CredentialError(
                    f"no NSDP admin password configured for {self.host!r}"
                )
            writer = NsdpWriter(
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
            writer = HttpWriter(
                _LazyHttpSession(self._http_session),
                self.model,
                protected_ports=self.protected_ports,
            )
        else:  # a CLI backend (SSH/telnet/console)
            # This slice adds CLI READS only; there is no CLI writer yet, so any
            # write dispatched to a CLI backend is honestly unsupported (SNMP
            # remains the write path for every FASTPATH model).
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} has no CLI write backend"
            )
        self._writer_cache[backend] = writer
        return writer

    def _read(self, op: Callable[[_AnyReader], _R]) -> _R:
        # Try each backend the model has, in preference order (SNMP > NSDP >
        # HTTP), returning the first whose reader serves the op. A backend that
        # cannot be built (construction raises UnsupportedCapabilityError) OR
        # whose method raises it is skipped; if none serve the op, re-raise the
        # last UnsupportedCapabilityError. A CredentialError (e.g. a missing NSDP
        # write password) is NOT swallowed -- it propagates.
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
                return op(reader)
            except UnsupportedCapabilityError as exc:
                last = exc
        if last is not None:
            raise last
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} has no backend supporting this operation"
        )

    def _write(
        self, op: Callable[[SnmpWriter | NsdpWriter | HttpWriter], None]
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
                op(writer)
                return
            except UnsupportedCapabilityError as exc:
                last = exc
        if last is not None:
            raise last
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r} has no backend supporting this operation"
        )

    def get_ports(self) -> list[PortStatus]:
        return self._read(lambda r: r.get_ports())

    def get_stats(self) -> list[PortStats]:
        return self._read(lambda r: r.get_stats())

    def get_vlans(self) -> list[VLANInfo]:
        return self._read(lambda r: r.get_vlans())

    def get_pvids(self) -> list[tuple[int, int]]:
        return self._read(lambda r: r.get_pvids())

    def get_lldp(self) -> list[LLDPNeighbor]:
        return self._read(lambda r: r.get_lldp())

    def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return self._read(lambda r: r.get_macs())

    def get_poe(self) -> list[PoEStatus]:
        return self._read(lambda r: r.get_poe())

    def get_sensors(self) -> list[Sensor]:
        return self._read(lambda r: r.get_sensors())

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return self._read(lambda r: r.get_mgmt_ip())

    def nsdp_device(self) -> NsdpDevice:
        """Return the COMPLETE raw ``NsdpDevice`` for this switch: model, MAC,
        hostname, mgmt IP, firmware, DHCP mode, port count, serial number,
        VLAN engine, raw per-port status (speed byte NOT pre-converted to
        Mbps -- see ``protocols.nsdp.types.NsdpPortStatus.speed``) and
        statistics, VLAN membership, PVIDs, plus QoS engine/mirroring/IGMP
        snooping/broadcast filtering/loop detection.

        Unlike every other read op, this deliberately bypasses the
        SNMP/NSDP/HTTP backend-preference dispatch (``_read``): NSDP is the
        ONLY backend that can serve it, so a model without an NSDP backend
        raises ``UnsupportedCapabilityError`` directly (mirroring
        ``identify()``'s bypass of that dispatch below, and
        ``NsdpReader.__init__``'s own ``_require_nsdp`` guard).
        """
        reader = self._reader_for(Backend.NSDP)
        assert isinstance(reader, NsdpReader)
        return reader.get_device()

    def identify(self) -> DetectedModel:
        """Detect this switch's ACTUAL model via SNMP sysDescr, independent of
        ``self.model``.

        Unlike every other read/write op, this deliberately bypasses the
        per-op SNMP/NSDP/HTTP backend-preference dispatch (``_read``) AND the
        ``self.model`` SNMP-backend gate entirely: it exists precisely to
        confirm/discover a switch's real model when the caller does not yet
        trust the model this facade happens to have been constructed with
        (e.g. a placeholder used only to carry host/credentials). Reuses an
        injected ``snmp_client``/``snmp_community`` exactly like
        ``_reader_for(Backend.SNMP)`` would, but never requires
        ``self.model.backends`` to include SNMP.
        """
        client = self._snmp_client
        if client is None:
            client = build_sync_snmp_client(self.host, self._snmp_community)
        return read_system_info(client)

    def snapshot(self) -> SwitchData:
        """Aggregate every read op, routing each field to the first backend that
        supports it (SNMP > NSDP > HTTP). A field NO backend can serve degrades
        to ()/None; a field a backend DOES serve stays populated (gs305ep:
        ports/stats/vlans/pvids/mgmt via NSDP, poe via HTTP)."""

        def _opt(
            op: Callable[[_AnyReader], list[Any]],
        ) -> tuple[Any, ...]:
            try:
                return tuple(self._read(op))
            except UnsupportedCapabilityError:
                return ()

        try:
            mgmt: MgmtIpConfig | None = self._read(lambda r: r.get_mgmt_ip())
        except UnsupportedCapabilityError:
            mgmt = None

        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=_opt(lambda r: r.get_ports()),
            stats=_opt(lambda r: r.get_stats()),
            vlans=_opt(lambda r: r.get_vlans()),
            pvids=_opt(lambda r: r.get_pvids()),
            mgmt_ip=mgmt,
            poe=_opt(lambda r: r.get_poe()),
            lldp=_opt(lambda r: r.get_lldp()),
            sensors=_opt(lambda r: r.get_sensors()),
            macs=_opt(lambda r: r.get_macs()),
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

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        self._write(lambda w: w.set_poe(port, on, force=force))

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        self._write(lambda w: w.set_port_enabled(port, enabled, force=force))

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._write(lambda w: w.set_pvid(port, vlan, force=force))

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._write(lambda w: w.set_vlan_membership(vlan, port, mode, force=force))

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        self._write(lambda w: w.create_vlan(vlan, name, force=force))

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        # SAFETY RAIL: HttpWriter.delete_vlan does NOT itself guard protected
        # member ports (only its per-port ops carry an internal `_guard`; its
        # own docstring defers VLAN-delete disruptiveness to be "guarded per-
        # member elsewhere"). NsdpWriter.delete_vlan ALWAYS raises
        # UnsupportedCapabilityError (NSDP has no VLAN lifecycle ops at all),
        # so on any {NSDP, HTTP} model delete_vlan falls straight through to
        # HTTP -- meaning nothing would otherwise stand between force=False
        # and stripping a protected port's VLAN membership. Guard here,
        # mirroring SnmpWriter.delete_vlan's own protected-port check, so
        # EVERY backend gets the same safety rail regardless of which one
        # actually ends up serving the delete.
        self._guard_vlan_delete_members(vlan, force=force)
        self._write(lambda w: w.delete_vlan(vlan, force=force))

    def _guard_vlan_delete_members(self, vlan: int, *, force: bool) -> None:
        if force:
            return
        try:
            vlans = self._read(lambda r: r.get_vlans())
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

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        self._write(lambda w: w.cycle_poe(port, force=force, timeouts=timeouts))

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        self._write(lambda w: w.clear_poe_fault(port, force=force, timeouts=timeouts))

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        self._write(lambda w: w.set_mgmt_ip(address, netmask, gateway, force=force))

    def _cert_writer(self) -> HttpWriter:
        # Cert upload is a GROUNDED web-UI write flow that is INDEPENDENT of read
        # verification, so it deliberately bypasses _writer_for's
        # http_reads_supported gate: gsm7228ps has reads_verified=False yet a
        # fully-grounded cert-upload flow (see http_write / endpoints). It also
        # bypasses the SNMP-first _write dispatch because cert upload is
        # HTTP-only.
        return HttpWriter(
            _LazyHttpSession(self._http_session),
            self.model,
            protected_ports=self.protected_ports,
        )

    def upload_certificate(
        self, cert_pem: str, key_pem: str, *, force: bool = False
    ) -> None:
        """Upload an HTTPS SSL server certificate + private key to the switch.

        Implemented for gsm7228ps/S3300 (grounded multipart web-UI upload).
        Disruptive (replaces the running certificate), so ``force=True`` is
        required. A model whose real mechanism is known but not yet implemented
        (m4300 SCP, gs728tpp XML-API) raises NotImplementedError naming the
        mechanism -- NOT UnsupportedCapabilityError, since the hardware can do
        it; a model with no HTTP backend and no known mechanism raises
        UnsupportedCapabilityError.
        """
        # Checked here FIRST so gs728tpp (which has no HTTP backend at all, so
        # require_http_backend would wrongly say "unsupported") still reports
        # the honest known-but-unimplemented mechanism.
        _reject_known_unimplemented_cert_upload(self.model.key)
        require_http_backend(self.model)
        self._cert_writer().upload_certificate(cert_pem, key_pem, force=force)

    def _cli_session(self) -> CliSession:
        """Return a ready CLI session: the injected one, else a freshly-built SSH
        transport (username ``admin``, reusing the web-admin password as the CLI
        password by default -- exactly like ``_reader_for(CLI)``)."""
        if self._cli_client is not None:
            return self._cli_client
        return build_sync_cli_client(
            self.host, "admin", self._resolve_http_password(), self.model
        )

    def upload_certificate_scp(
        self,
        *,
        scp_source: str,
        scp_password: str,
        remote_dir: str,
        chain: bool = False,
    ) -> None:
        """Deploy an HTTPS SSL server certificate to a FASTPATH switch over SCP.

        For the Fully Managed FASTPATH line (M4300 / GSM7252PS) only, whose
        firmware pulls the certificate with ``copy scp://<src> nvram:sslpem-server``
        rather than an HTTP form. Runs the disable-HTTPS -> copy(server) ->
        optional copy(root chain) -> re-enable-HTTPS -> save-config sequence over
        the library's existing CLI transport (SSH by default). Re-enabling HTTPS
        loads the new certificate in place; the switch is NOT rebooted.

        The CALLER must have STAGED the PEM(s) on the SCP source first: the switch
        pulls ``<host-with-dots-as-dashes>-server.pem`` (and, when ``chain`` is
        set, ``<...>-root.pem``) from ``remote_dir`` on ``scp_source`` (a
        ``user@host[:port]`` string). This library only SENDS the copy commands
        (per the design decision) -- it does not run the staging SCP server.

        Dispatched ONLY for FASTPATH models with a known copy-scp profile
        (m4300-24x/-16x, gsm7252ps); every other model -- including FASTPATH
        gsm7228ps, whose cert upload is HTTP multipart -- raises
        ``UnsupportedCapabilityError``.

        HONESTY: GROUNDED in the certbot-hook ``FastpathScpUpdater`` prior art and
        MOCK-TESTED end-to-end, but NOT live-verified (a real run is a production
        write needing a staging SCP server, which CI lacks) -- see
        ``cli_write.deploy_certificate_scp``.
        """
        from .protocols.cli.commands import scp_cert_profile

        # Raises UnsupportedCapabilityError for any non-FASTPATH-SCP model,
        # BEFORE building a session -- so a wrong model never opens a connection.
        profile = scp_cert_profile(self.model)
        # Base name of the staged PEM: the dot-sanitised host, mirroring the
        # certbot hook (FASTPATH's copy-scp caps the remote path length and
        # rejects dots in the filename, so "10.1.5.22" -> "10-1-5-22").
        base = self.host.replace(".", "-")
        session = self._cli_session()
        try:
            deploy_certificate_scp(
                session,
                scp_source=scp_source,
                scp_password=scp_password,
                remote_dir=remote_dir,
                base=base,
                chain=chain,
                writemem_stuff=profile.writemem_stuff,
            )
        finally:
            # Only tear down a session THIS facade built; never one injected.
            if self._cli_client is None:
                session.close()
