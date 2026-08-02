# src/netgear_switch/snmp_read.py
"""Model-driven SNMP read operations over a sync or async client."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import UnsupportedCapabilityError
from .models import DetectedModel
from .protocols.snmp import oids, parse
from .registry import MODELS, Backend

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
        ServiceStatus,
        SwitchUser,
        SyslogConfig,
        VLANInfo,
    )
    from .protocols.snmp.client import AsyncSnmpClient, SnmpClient
    from .registry import SwitchModel


def _require_snmp(model: SwitchModel) -> None:
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no SNMP backend")


def read_system_info(client: SnmpClient) -> DetectedModel:
    """Identify a switch's model via SNMP: sysObjectID first, then sysDescr.

    Deliberately NOT a method on ``SnmpReader``: every other read in this
    module requires a already-known ``SwitchModel`` (``_require_snmp`` gates
    the reader's construction), but model identification exists precisely
    for the case where the caller does NOT yet know/trust the model -- so
    this takes a bare, unbound ``SnmpClient`` instead. A real-capture-confirmed
    sysObjectID (``parse.detect_model_from_sysobjectid``) wins when present;
    otherwise the sysDescr text heuristic (``parse.detect_model_from_sysdescr``)
    is tried. Both are honesty-constrained (never guess; ``key=None`` means
    genuinely unidentified -- an unregistered model or a non-Netgear device).
    """
    rows = client.get([oids.SYS_DESCR, oids.SYS_OBJECT_ID])
    sys_descr, sys_object_id = parse.parse_system_info(rows)
    key = parse.detect_model_from_sysobjectid(
        sys_object_id, MODELS
    ) or parse.detect_model_from_sysdescr(sys_descr, MODELS)
    return DetectedModel(key=key, sys_descr=sys_descr, sys_object_id=sys_object_id)


async def async_read_system_info(client: AsyncSnmpClient) -> DetectedModel:
    """Async twin of ``read_system_info`` -- see there."""
    rows = await client.get([oids.SYS_DESCR, oids.SYS_OBJECT_ID])
    sys_descr, sys_object_id = parse.parse_system_info(rows)
    key = parse.detect_model_from_sysobjectid(
        sys_object_id, MODELS
    ) or parse.detect_model_from_sysdescr(sys_descr, MODELS)
    return DetectedModel(key=key, sys_descr=sys_descr, sys_object_id=sys_object_id)


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
            w(oids.IF_ADMIN_STATUS),
            w(oids.IF_OPER_STATUS),
            w(oids.IF_HIGH_SPEED),
            w(oids.IF_NAME),
            w(oids.IF_ALIAS),
            w(oids.IF_TYPE),
        )

    def get_stats(self) -> list[PortStats]:
        w = self.client.walk
        return parse.parse_port_stats(
            in_octets=w(oids.IF_HC_IN_OCTETS),
            out_octets=w(oids.IF_HC_OUT_OCTETS),
            in_ucast=w(oids.IF_HC_IN_UCAST),
            out_ucast=w(oids.IF_HC_OUT_UCAST),
            in_errors=w(oids.IF_IN_ERRORS),
            out_errors=w(oids.IF_OUT_ERRORS),
            if_types=w(oids.IF_TYPE),
        )

    def get_vlans(self) -> list[VLANInfo]:
        # ifType keeps LAG bridge-ports out of the membership bitmaps, and the
        # current table supplies VLANs the static table omits -- the GS728TPP's
        # VLAN 1 has no static row at all. See parse.parse_vlans for the live
        # evidence behind both.
        w = self.client.walk
        return parse.parse_vlans(
            w(oids.DOT1Q_VLAN_STATIC_NAME),
            w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
            w(oids.IF_TYPE),
            w(oids.DOT1Q_VLAN_CURRENT_EGRESS),
            w(oids.DOT1Q_VLAN_CURRENT_UNTAGGED),
        )

    def get_pvids(self) -> list[tuple[int, int]]:
        w = self.client.walk
        return parse.parse_pvids(w(oids.DOT1Q_PVID), w(oids.IF_TYPE))

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
        # A model with zero PSE ports (m4300-24x) has no PoE at all: raise
        # UnsupportedCapabilityError BEFORE walking, mirroring CliReader.get_poe
        # and HttpReader.get_poe, so PoE is reported unsupported CONSISTENTLY
        # across every backend rather than SNMP silently returning [] from an
        # empty pethPsePortTable while CLI/HTTP raise.
        if self.model.poe_port_count == 0:
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} has no PoE (no PSE ports)"
            )
        # Per-port PoE status is the STANDARD RFC3621 pethPsePortTable on every
        # SNMP model. The per-port delivered-power (mW) is a Netgear VENDOR
        # column; a model with no vendor subtree (gs728tpp -- serves everything
        # via standard MIBs) has no such column, so power_mw is honestly None.
        w = self.client.walk
        power = (
            w(oids.vendor_oids(self.model).poe_power_mw)
            if oids.has_vendor_oids(self.model)
            else []
        )
        return parse.parse_poe(w(oids.PETH_PSE_PORT_TABLE), power)

    def get_sensors(self) -> list[Sensor]:
        w = self.client.walk
        if not oids.has_vendor_oids(self.model):
            # No vendor subtree (gs728tpp): the fan/PSU components live only in
            # the standard ENTITY-MIB physical inventory, with no live value.
            return parse.parse_entity_sensors(
                w(oids.ENT_PHYSICAL_CLASS),
                w(oids.ENT_PHYSICAL_NAME),
                w(oids.ENT_PHYSICAL_DESCR),
            )
        vendor = oids.vendor_oids(self.model)
        columns = [
            ("fan", "RPM", w(vendor.box_fan)),
            ("power", "W", w(vendor.box_psu_power)),
            ("temperature", "C", w(vendor.box_temp)),
        ]
        if not any(rows for _kind, _unit, rows in columns):
            # The model CLAIMS a vendor sensor subtree (snmp_vendor_base set) but
            # every vendor sensor column walked EMPTY (agent answered
            # noSuchObject). Returning [] here would be the exact silent-empty
            # the parity contract forbids -- and the mechanism that hid the
            # gs728tpp vendor-OID mismatch. Raise honestly instead.
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} declares vendor sensor OIDs "
                f"({self.model.snmp_vendor_base}) but the vendor fan/PSU/"
                "temperature walk returned nothing"
            )
        return parse.parse_box_sensors(columns)

    def get_mgmt_ip(self) -> MgmtIpConfig:
        # Address/netmask/gateway/base-MAC are all STANDARD MIBs. Only the
        # DHCP-vs-static mode is a Netgear VENDOR OID (UNVERIFIED); a model
        # with no vendor subtree (gs728tpp) has no such OID -> mode UNKNOWN.
        w = self.client.walk
        dhcp = (
            w(oids.vendor_oids(self.model).dhcp_mode_unverified)
            if oids.has_vendor_oids(self.model)
            else []
        )
        return parse.parse_mgmt_ip(
            w(oids.IP_ADENT_ADDR),
            w(oids.IP_ADENT_NETMASK),
            w(oids.IP_ROUTE_DEST),
            w(oids.IP_ROUTE_NEXTHOP),
            dhcp,
            w(oids.DOT1D_BASE_BRIDGE_ADDRESS),  # standard BRIDGE-MIB scalar
            w(oids.IP_ADDRESS_IFINDEX),  # RFC-4293 fallback (M4300)
        )

    def get_hostname(self) -> str:
        """The switch's host name, from the standard MIB-II ``sysName`` scalar.

        Standard, so this works on every SNMP model -- including ``gs728tpp``,
        which publishes no Netgear vendor subtree at all.
        """
        return parse.parse_hostname(self.client.get([oids.SYS_NAME]))

    def get_syslog(self) -> SyslogConfig:
        """Remote-logging configuration: whether it is on, and where it sends.

        VENDOR columns, so a model with no Netgear subtree cannot serve this.
        ``gs728tpp`` is exactly that model -- a walk of ``1.3.6.1.4.1.4526``
        answers ``noSuchObject`` -- and it is refused by name rather than
        returned empty, which would read as "no collectors configured".
        """
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only; an empty "
                "result here would be indistinguishable from a switch with no "
                "syslog collectors configured"
            )
        vo = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_syslog(
            self.client.get([vo.syslog_admin_mode]),
            self.client.get([vo.syslog_local_port]),
            w(vo.syslog_host_addr),
            w(vo.syslog_host_port),
            w(vo.syslog_host_severity),
            w(vo.syslog_host_status),
            addr_base=vo.syslog_host_addr,
            port_base=vo.syslog_host_port,
            severity_base=vo.syslog_host_severity,
            status_base=vo.syslog_host_status,
        )

    def get_system_info(self) -> DetectedModel:
        """Identify this switch's model via sysDescr (see ``read_system_info``).

        Reuses this reader's already-connected client. Unlike every other
        method here, the result does NOT depend on ``self.model`` matching
        the real device -- useful to confirm/discover a switch's real model
        via a reader that was (possibly wrongly) constructed against a
        different model key.
        """
        return read_system_info(self.client)

    def get_users(self) -> list[SwitchUser]:
        """This backend does not serve local user accounts.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "local user accounts (no such tag/page/table on this backend)"
        )

    def get_services(self) -> list[ServiceStatus]:
        """This backend does not serve management-service state.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "management-service state (http/https/telnet/ssh)"
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
            await w(oids.IF_ADMIN_STATUS),
            await w(oids.IF_OPER_STATUS),
            await w(oids.IF_HIGH_SPEED),
            await w(oids.IF_NAME),
            await w(oids.IF_ALIAS),
            await w(oids.IF_TYPE),
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
            if_types=await w(oids.IF_TYPE),
        )

    async def get_vlans(self) -> list[VLANInfo]:
        # See SnmpReader.get_vlans: ifType drops LAG bridge-ports, and the
        # current table carries VLANs (e.g. the GS728TPP's VLAN 1) that have no
        # dot1qVlanStaticTable row.
        w = self.client.walk
        return parse.parse_vlans(
            await w(oids.DOT1Q_VLAN_STATIC_NAME),
            await w(oids.DOT1Q_VLAN_STATIC_EGRESS),
            await w(oids.DOT1Q_VLAN_STATIC_UNTAGGED),
            await w(oids.IF_TYPE),
            await w(oids.DOT1Q_VLAN_CURRENT_EGRESS),
            await w(oids.DOT1Q_VLAN_CURRENT_UNTAGGED),
        )

    async def get_pvids(self) -> list[tuple[int, int]]:
        w = self.client.walk
        return parse.parse_pvids(await w(oids.DOT1Q_PVID), await w(oids.IF_TYPE))

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
        # See SnmpReader.get_poe: zero-PSE models raise (consistent with CLI/
        # HTTP) BEFORE walking; standard pethPsePortTable otherwise; per-port mW
        # is a vendor column, absent (-> None) on a model with no vendor subtree.
        if self.model.poe_port_count == 0:
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} has no PoE (no PSE ports)"
            )
        w = self.client.walk
        power = (
            await w(oids.vendor_oids(self.model).poe_power_mw)
            if oids.has_vendor_oids(self.model)
            else []
        )
        return parse.parse_poe(await w(oids.PETH_PSE_PORT_TABLE), power)

    async def get_sensors(self) -> list[Sensor]:
        w = self.client.walk
        if not oids.has_vendor_oids(self.model):
            # No vendor subtree (gs728tpp): standard ENTITY-MIB inventory only.
            return parse.parse_entity_sensors(
                await w(oids.ENT_PHYSICAL_CLASS),
                await w(oids.ENT_PHYSICAL_NAME),
                await w(oids.ENT_PHYSICAL_DESCR),
            )
        vendor = oids.vendor_oids(self.model)
        columns = [
            ("fan", "RPM", await w(vendor.box_fan)),
            ("power", "W", await w(vendor.box_psu_power)),
            ("temperature", "C", await w(vendor.box_temp)),
        ]
        if not any(rows for _kind, _unit, rows in columns):
            # See SnmpReader.get_sensors: a claimed vendor sensor subtree that
            # walks empty must raise, not silently return [] (the gs728tpp bug
            # class).
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} declares vendor sensor OIDs "
                f"({self.model.snmp_vendor_base}) but the vendor fan/PSU/"
                "temperature walk returned nothing"
            )
        return parse.parse_box_sensors(columns)

    async def get_mgmt_ip(self) -> MgmtIpConfig:
        # See SnmpReader.get_mgmt_ip: standard MIBs for addr/mask/gw/base-MAC;
        # the DHCP-mode vendor OID is absent (-> UNKNOWN) with no vendor subtree.
        w = self.client.walk
        dhcp = (
            await w(oids.vendor_oids(self.model).dhcp_mode_unverified)
            if oids.has_vendor_oids(self.model)
            else []
        )
        return parse.parse_mgmt_ip(
            await w(oids.IP_ADENT_ADDR),
            await w(oids.IP_ADENT_NETMASK),
            await w(oids.IP_ROUTE_DEST),
            await w(oids.IP_ROUTE_NEXTHOP),
            dhcp,
            await w(oids.DOT1D_BASE_BRIDGE_ADDRESS),  # standard BRIDGE-MIB scalar
            await w(oids.IP_ADDRESS_IFINDEX),  # RFC-4293 fallback (M4300)
        )

    async def get_syslog(self) -> SyslogConfig:
        """Async twin of ``SnmpReader.get_syslog`` -- see there."""
        if not oids.has_vendor_oids(self.model):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r} registers no Netgear vendor OID "
                "subtree, and the logging columns are vendor-only; an empty "
                "result here would be indistinguishable from a switch with no "
                "syslog collectors configured"
            )
        vo = oids.vendor_oids(self.model)
        w = self.client.walk
        return parse.parse_syslog(
            await self.client.get([vo.syslog_admin_mode]),
            await self.client.get([vo.syslog_local_port]),
            await w(vo.syslog_host_addr),
            await w(vo.syslog_host_port),
            await w(vo.syslog_host_severity),
            await w(vo.syslog_host_status),
            addr_base=vo.syslog_host_addr,
            port_base=vo.syslog_host_port,
            severity_base=vo.syslog_host_severity,
            status_base=vo.syslog_host_status,
        )

    async def get_hostname(self) -> str:
        """Async twin of ``SnmpReader.get_hostname`` -- see there."""
        return parse.parse_hostname(await self.client.get([oids.SYS_NAME]))

    async def get_system_info(self) -> DetectedModel:
        """Async twin of ``SnmpReader.get_system_info`` -- see there."""
        return await async_read_system_info(self.client)

    async def get_users(self) -> list[SwitchUser]:
        """This backend does not serve local user accounts.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "local user accounts (no such tag/page/table on this backend)"
        )

    async def get_services(self) -> list[ServiceStatus]:
        """This backend does not serve management-service state.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "management-service state (http/https/telnet/ssh)"
        )
