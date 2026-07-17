"""Public synchronous read facade: SyncSwitch."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ._dispatch import (
    build_sync_snmp_client,
    require_mac_table,
    require_snmp_backend,
)
from .models import SwitchData
from .snmp_read import SnmpReader

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
    from .protocols.snmp.client import SnmpClient
    from .registry import SwitchModel


class SyncSwitch:
    """Synchronous, model-driven read facade over one switch."""

    def __init__(
        self,
        model: SwitchModel,
        host: str,
        *,
        snmp_community: str | None = None,
        snmp_client: SnmpClient | None = None,
    ) -> None:
        self.model = model
        self.host = host
        self._snmp_community = snmp_community
        self._snmp_client = snmp_client

    @classmethod
    def from_config(
        cls, cfg: SwitchConfig, *, env: Mapping[str, str] | None = None
    ) -> SyncSwitch:
        # env is reserved for backends that resolve secrets (SNMP write
        # community / HTTP password in Slices 4-6); SNMP reads use the literal
        # read community stored on the config, so env is unused here.
        _ = env
        return cls(cfg.model, cfg.host, snmp_community=cfg.snmp_community)

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
