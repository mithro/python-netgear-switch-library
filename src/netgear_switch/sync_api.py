"""Public synchronous read/write facade: SyncSwitch."""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ._dispatch import (
    build_sync_snmp_client,
    build_sync_snmp_write_client,
    require_mac_table,
    require_snmp_backend,
)
from .models import SwitchData
from .snmp_read import SnmpReader
from .snmp_write import PoeCycleTimeouts, SnmpWriter

_DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts()


class _Unset:
    """Sentinel type for "write community not yet resolved" (see
    SyncSwitch._resolved_write_community): a resolved value of None (no
    community configured) must stay distinguishable from "never resolved"."""


_UNSET = _Unset()

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

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
    from .protocols.snmp.client import SnmpClient, SnmpWriteClient
    from .registry import SwitchModel


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
        self.protected_ports = protected_ports

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> SyncSwitch:
        # Resolve the SNMP write community LAZILY (on first write), never here.
        # A read-only consumer whose env lacks a resolvable write-community spec
        # (e.g. ``${UNSET_VAR}``) must still be able to construct the facade and
        # read; only an actual write attempt may raise CredentialError/ConfigError
        # (review item 4). We stash a closure that reads the spec + env on demand.
        def _resolve_write_community() -> str | None:
            return cfg.snmp_write_community(env=env if env is not None else os.environ)

        return cls(
            cfg.model, cfg.host,
            snmp_community=cfg.snmp_community,
            snmp_write_community_resolver=_resolve_write_community,
            protected_ports=cfg.protected_ports,
        )

    def _reader(self) -> SnmpReader:
        # Backend-resolution seam: today only SNMP is wired. NSDP/HTTP-only
        # (Plus) models raise here; Slices 5/6 extend this without changing any
        # public method below.
        require_snmp_backend(self.model)
        client = self._snmp_client
        if client is None:
            client = build_sync_snmp_client(self.host, self._snmp_community)
        return SnmpReader(client, self.model)

    def get_ports(self) -> list[PortStatus]:
        return self._reader().get_ports()

    def get_stats(self) -> list[PortStats]:
        return self._reader().get_stats()

    def get_vlans(self) -> list[VLANInfo]:
        return self._reader().get_vlans()

    def get_pvids(self) -> list[tuple[int, int]]:
        return self._reader().get_pvids()

    def get_lldp(self) -> list[LLDPNeighbor]:
        return self._reader().get_lldp()

    def get_macs(self) -> list[MacEntry]:
        require_mac_table(self.model)
        return self._reader().get_macs()

    def get_poe(self) -> list[PoEStatus]:
        return self._reader().get_poe()

    def get_sensors(self) -> list[Sensor]:
        return self._reader().get_sensors()

    def get_mgmt_ip(self) -> MgmtIpConfig:
        return self._reader().get_mgmt_ip()

    def snapshot(self) -> SwitchData:
        """Aggregate every read op the model supports into one SwitchData."""
        reader = self._reader()
        macs = reader.get_macs() if self.model.has_mac_table else []
        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=tuple(reader.get_ports()),
            poe=tuple(reader.get_poe()),
            vlans=tuple(reader.get_vlans()),
            pvids=tuple(reader.get_pvids()),
            lldp=tuple(reader.get_lldp()),
            macs=tuple(macs),
            sensors=tuple(reader.get_sensors()),
            stats=tuple(reader.get_stats()),
            mgmt_ip=reader.get_mgmt_ip(),
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

    def _writer(self) -> SnmpWriter:
        require_snmp_backend(self.model)
        client = self._snmp_write_client
        if client is None:
            community = self._resolve_write_community()
            client = build_sync_snmp_write_client(self.host, community)
        return SnmpWriter(client, self.model, protected_ports=self.protected_ports)

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        self._writer().set_poe(port, on, force=force)

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        self._writer().set_port_enabled(port, enabled, force=force)

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._writer().set_pvid(port, vlan, force=force)

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._writer().set_vlan_membership(vlan, port, mode, force=force)

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        self._writer().create_vlan(vlan, name, force=force)

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        self._writer().delete_vlan(vlan, force=force)

    def cycle_poe(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        self._writer().cycle_poe(port, force=force, timeouts=timeouts)

    def clear_poe_fault(
        self, port: int, *, force: bool = False,
        timeouts: PoeCycleTimeouts = _DEFAULT_POE_TIMEOUTS,
    ) -> None:
        self._writer().clear_poe_fault(port, force=force, timeouts=timeouts)

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        self._writer().set_mgmt_ip(address, netmask, gateway, force=force)
