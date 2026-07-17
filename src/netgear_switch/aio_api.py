"""Public asynchronous read facade: AsyncSwitch (mirror of SyncSwitch)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._dispatch import (
    build_async_snmp_client,
    require_mac_table,
    require_snmp_backend,
)
from .models import SwitchData
from .snmp_read import AsyncSnmpReader

if TYPE_CHECKING:
    from collections.abc import Mapping

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
    )
    from .protocols.snmp.client import AsyncSnmpClient
    from .registry import SwitchModel


class AsyncSwitch:
    """Asynchronous, model-driven read facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: AsyncSnmpClient | None = None,
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> AsyncSwitch:
        # env is reserved for secret-resolving backends (Slices 4-6); SNMP
        # reads use the literal read community on the config, so env is unused.
        _ = env
        return cls(cfg.model, cfg.host, snmp_community=cfg.snmp_community)

    def _reader(self) -> AsyncSnmpReader:
        # Backend-resolution seam mirroring SyncSwitch._reader.
        require_snmp_backend(self.model)
        client = self._snmp_client
        if client is None:
            client = build_async_snmp_client(self.host, self._snmp_community)
        return AsyncSnmpReader(client, self.model)

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
        """Aggregate every read op the model supports into one SwitchData."""
        reader = self._reader()
        macs = await reader.get_macs() if self.model.has_mac_table else []
        return SwitchData(
            model=self.model.key,
            host=self.host,
            ports=tuple(await reader.get_ports()),
            poe=tuple(await reader.get_poe()),
            vlans=tuple(await reader.get_vlans()),
            pvids=tuple(await reader.get_pvids()),
            lldp=tuple(await reader.get_lldp()),
            macs=tuple(macs),
            sensors=tuple(await reader.get_sensors()),
            stats=tuple(await reader.get_stats()),
            mgmt_ip=await reader.get_mgmt_ip(),
        )
