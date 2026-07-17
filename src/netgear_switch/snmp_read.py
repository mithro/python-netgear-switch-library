# src/netgear_switch/snmp_read.py
"""Model-driven SNMP read operations over a sync or async client."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import UnsupportedCapabilityError
from .protocols.snmp import oids, parse
from .registry import Backend

if TYPE_CHECKING:
    # Only used in type annotations (return types / parameter types), never
    # instantiated or referenced at runtime here -- kept behind
    # TYPE_CHECKING so ruff's TC rules stay clean (see oids.py for the same
    # pattern).
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
    from .protocols.snmp.client import AsyncSnmpClient, SnmpClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


class SnmpReader:
    def __init__(self, client: SnmpClient, model: SwitchModel) -> None:
        # _require_snmp is the single capability gate: it raises for any model
        # without an SNMP backend (i.e. Plus). Vendor OIDs are resolved lazily,
        # only in the ops that need the vendor subtree (get_poe/get_sensors/
        # get_mgmt_ip), so constructing a reader never touches vendor_oids.
        _require_snmp(model)
        self.client = client
        self.model = model

    def get_ports(self) -> list[PortStatus]:
        w = self.client.walk
        return parse.parse_port_status(
            w(oids.IF_ADMIN_STATUS), w(oids.IF_OPER_STATUS),
            w(oids.IF_HIGH_SPEED), w(oids.IF_NAME),
        )

    def get_stats(self) -> list[PortStats]:
        w = self.client.walk
        return parse.parse_port_stats(
            in_octets=w(oids.IF_HC_IN_OCTETS), out_octets=w(oids.IF_HC_OUT_OCTETS),
            in_ucast=w(oids.IF_HC_IN_UCAST), out_ucast=w(oids.IF_HC_OUT_UCAST),
            in_errors=w(oids.IF_IN_ERRORS), out_errors=w(oids.IF_OUT_ERRORS),
        )

    def get_vlans(self) -> list[VLANInfo]:
        w = self.client.walk
        return parse.parse_vlans(
            w(oids.DOT1Q_VLAN_STATIC_NAME), w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
        )

    def get_pvids(self) -> list[tuple[int, int]]:
        return parse.parse_pvids(self.client.walk(oids.DOT1Q_PVID))

    def get_lldp(self) -> list[LLDPNeighbor]:
        return parse.parse_lldp(self.client.walk(oids.LLDP_REM_TABLE))

    def get_macs(self) -> list[MacEntry]:
        # No has_mac_table guard here: has_mac_table == (Backend.SNMP in
        # backends), which __init__'s _require_snmp already enforced. (The
        # registry.has_mac_table property stays for external callers.)
        w = self.client.walk
        return parse.parse_macs(
            w(oids.DOT1Q_TP_FDB_PORT), w(oids.DOT1D_BASE_PORT_IF_INDEX)
        )

    def get_poe(self) -> list[PoEStatus]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_poe(
            w(oids.PETH_PSE_PORT_TABLE), w(vendor.poe_power_mw)
        )

    def get_sensors(self) -> list[Sensor]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        columns = [
            ("fan", "RPM", w(vendor.box_fan)),
            ("power", "W", w(vendor.box_psu_power)),
            ("temperature", "C", w(vendor.box_temp)),
        ]
        return parse.parse_box_sensors(columns)

    def get_mgmt_ip(self) -> MgmtIpConfig:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_mgmt_ip(
            w(oids.IP_ADENT_ADDR), w(oids.IP_ADENT_NETMASK),
            w(oids.IP_ROUTE_DEST), w(oids.IP_ROUTE_NEXTHOP),
            w(vendor.dhcp_mode_unverified),  # single named UNVERIFIED OID (Task 4)
        )


class AsyncSnmpReader:
    def __init__(self, client: AsyncSnmpClient, model: SwitchModel) -> None:
        # Same contract as SnmpReader: _require_snmp gates construction; vendor
        # OIDs resolved lazily in get_poe/get_sensors/get_mgmt_ip only.
        _require_snmp(model)
        self.client = client
        self.model = model

    async def get_ports(self) -> list[PortStatus]:
        w = self.client.walk
        return parse.parse_port_status(
            await w(oids.IF_ADMIN_STATUS), await w(oids.IF_OPER_STATUS),
            await w(oids.IF_HIGH_SPEED), await w(oids.IF_NAME),
        )

    async def get_stats(self) -> list[PortStats]:
        w = self.client.walk
        return parse.parse_port_stats(
            in_octets=await w(oids.IF_HC_IN_OCTETS),
            out_octets=await w(oids.IF_HC_OUT_OCTETS),
            in_ucast=await w(oids.IF_HC_IN_UCAST),
            out_ucast=await w(oids.IF_HC_OUT_UCAST),
            in_errors=await w(oids.IF_IN_ERRORS),
            out_errors=await w(oids.IF_OUT_ERRORS),
        )

    async def get_vlans(self) -> list[VLANInfo]:
        w = self.client.walk
        return parse.parse_vlans(
            await w(oids.DOT1Q_VLAN_STATIC_NAME),
            await w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            await w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
        )

    async def get_pvids(self) -> list[tuple[int, int]]:
        return parse.parse_pvids(await self.client.walk(oids.DOT1Q_PVID))

    async def get_lldp(self) -> list[LLDPNeighbor]:
        return parse.parse_lldp(await self.client.walk(oids.LLDP_REM_TABLE))

    async def get_macs(self) -> list[MacEntry]:
        # No has_mac_table guard: _require_snmp in __init__ already enforced it.
        w = self.client.walk
        return parse.parse_macs(
            await w(oids.DOT1Q_TP_FDB_PORT),
            await w(oids.DOT1D_BASE_PORT_IF_INDEX),
        )

    async def get_poe(self) -> list[PoEStatus]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_poe(
            await w(oids.PETH_PSE_PORT_TABLE), await w(vendor.poe_power_mw)
        )

    async def get_sensors(self) -> list[Sensor]:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        columns = [
            ("fan", "RPM", await w(vendor.box_fan)),
            ("power", "W", await w(vendor.box_psu_power)),
            ("temperature", "C", await w(vendor.box_temp)),
        ]
        return parse.parse_box_sensors(columns)

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        vendor = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_mgmt_ip(
            await w(oids.IP_ADENT_ADDR), await w(oids.IP_ADENT_NETMASK),
            await w(oids.IP_ROUTE_DEST), await w(oids.IP_ROUTE_NEXTHOP),
            await w(vendor.dhcp_mode_unverified),  # single named UNVERIFIED OID
        )
