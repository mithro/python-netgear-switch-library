"""SNMP OID constants and per-model vendor OID tables."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...errors import UnsupportedCapabilityError

if TYPE_CHECKING:
    # Imported only for the vendor_oids() type annotation; keep it behind
    # TYPE_CHECKING so ruff's TC rules stay clean and the pure layer stays light.
    from ...registry import SwitchModel


# Standard-MIB OID constants
# MIB-II System group scalars (Task 2 model detection): both are full,
# instance-qualified (".0") leaf OIDs, fetched with a plain exact-OID GET
# (unlike the walk-based base-OIDs below) -- see snmp_read.read_system_info.
SYS_DESCR = "1.3.6.1.2.1.1.1.0"       # sysDescr: text incl. the model name
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"   # sysObjectID: read-only signal, unused
# for matching (no known OID->model table exists -- see parse.py's
# detect_model_from_sysdescr docstring).
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"        # ifAdminStatus (1=up,2=down)
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"        # ifOperStatus  (1=up,2=down)
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_IN_UCAST = "1.3.6.1.2.1.31.1.1.1.7"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HC_OUT_UCAST = "1.3.6.1.2.1.31.1.1.1.11"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"    # Mbps
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
DOT1D_BASE_BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1"  # scalar (.0); BRIDGE-MIB base MAC
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # MAC table, port column ONLY
DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
DOT1Q_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
DOT1Q_VLAN_STATIC_ROW_STATUS = "1.3.6.1.2.1.17.7.1.4.3.1.5"  # dot1qVlanStaticRowStatus
ROW_STATUS_CREATE_AND_GO = 4  # RowStatus createAndGo
ROW_STATUS_DESTROY = 6        # RowStatus destroy
# ENTITY-MIB entPhysicalTable columns (RFC 4133/2737). Some Netgear agents
# (verified: the GS728TPP, whose SNMP agent implements ZERO 4526 vendor OIDs)
# expose their fan/PSU sensor components ONLY as this standard physical
# inventory -- entPhysicalClass says what a row is, entPhysicalName/Descr name
# it -- with NO live status/value anywhere in SNMP. See parse_entity_sensors.
ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"   # int enum; 6=powerSupply,7=fan
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_CLASS_POWER_SUPPLY = 6
ENT_CLASS_FAN = 7
# columns 5=chassis,7=portId,8=portDesc,9=sysName
LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1"
# RFC3621; col3=admin, col6=detect
PETH_PSE_PORT_TABLE = "1.3.6.1.2.1.105.1.1.1"
# ipAddrTable (snmp_common.py:36 base .4.20)
IP_ADENT_ADDR = "1.3.6.1.2.1.4.20.1.1"
IP_ADENT_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_ADENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"
IP_ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"       # ipRouteDest
# ipRouteNextHop (gateway where dest=0.0.0.0)
IP_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"


# (kind, unit, column suffix under {base}.43.1)
BOX_SENSOR_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("fan", "RPM", "6.1.4"),
    ("power", "W", "8.1.5"),
    ("temperature", "C", "15.1.3"),
)

DHCP_MODE_OID_SUFFIX = "99.1"
"""UNVERIFIED — this Netgear private OID for DHCP-vs-static management-IP mode.

This is an unconfirmed guess used only so the mock and reader agree under
test; it MUST be confirmed against real hardware via the capture utility
(Slice 7) before it is trusted. Until then get_mgmt_ip returns IpMode.UNKNOWN
when this OID is absent.
"""


@dataclass(frozen=True)
class VendorOids:
    """Per-model Netgear vendor-specific OID table."""

    base: str
    poe_power_mw: str
    box_fan: str
    box_psu_power: str
    box_temp: str
    dhcp_mode_unverified: str
    """The ONE symbol every call site uses for the DHCP-mode OID. See
    DHCP_MODE_OID_SUFFIX above — UNVERIFIED, best-effort read only. No call site
    may hard-code a ``.99.1`` literal; they all reference this field."""
    mgmt_write_addr_unverified: str
    mgmt_write_netmask_unverified: str
    mgmt_write_gateway_unverified: str
    """UNVERIFIED writable management-IP OIDs — placeholders pending Slice 7
    hardware capture. They are NEVER trusted on real hardware (set_mgmt_ip is
    force-gated and documented UNVERIFIED); they exist so the mutable mock and
    the writer agree under test, mirroring the ``dhcp_mode_unverified``
    precedent above. No call site may hard-code these literals."""


def has_vendor_oids(model: SwitchModel) -> bool:
    """True when this model's SNMP agent implements the Netgear vendor OID
    subtree (``snmp_vendor_base`` set), so ``vendor_oids`` is safe to call.

    False for a model whose agent serves EVERYTHING via standard MIBs and
    registers no 4526 vendor OIDs at all (verified: the GS728TPP -- a walk of
    ``1.3.6.1.4.1.4526`` answers ``noSuchObject``). Such a model's PoE, box
    sensors and DHCP-mode reads use the standard-MIB code paths in
    ``snmp_read`` instead of the vendor columns; see there.
    """
    return model.snmp_vendor_base is not None


def unimplemented_roots(model: SwitchModel) -> list[str]:
    """OID roots this model's real SNMP agent does NOT register at all.

    Real Netgear firmware only instantiates a MIB module when the underlying
    hardware capability actually exists: the RFC3621 PoE MIB
    (``PETH_PSE_PORT_TABLE``) -- and Netgear's own vendor PoE-power column --
    is entirely ABSENT, not merely empty, on a non-PoE model such as the
    M4300-24X. Verified live: a GETNEXT/bulkwalk of the PoE MIB root on that
    switch answers a single ``noSuchObject``, never silently falls through to
    whatever unrelated OID happens to sort next (see ``is_oid_implemented``
    and ``virtual/faces/mibview.py``). Every other MIB group this library
    reads (system/if/ifX/BRIDGE/Q-BRIDGE/IP/LLDP) is implemented by every
    currently-registered SNMP-backend model, so only the PoE-gated roots are
    tracked here; extend this list if a future model is found to lack some
    other subtree entirely.
    """
    if model.poe_port_count > 0:
        return []
    roots = [PETH_PSE_PORT_TABLE]
    if model.snmp_vendor_base is not None:
        roots.append(vendor_oids(model).poe_power_mw)
    return roots


def is_oid_implemented(model: SwitchModel, oid: str) -> bool:
    """False if ``oid`` falls under a subtree root ``unimplemented_roots``
    says this model's agent has no registration for at all; True otherwise.

    This is deliberately narrower than "does this OID have a value right
    now": a table that IS registered but simply has no rows yet (or an
    instance that's absent) is a completely different, honest case already
    handled by ``StateMibView``'s normal ``noSuchInstance``/``endOfMibView``
    responses. Only a whole MIB module the device never registers gets
    ``noSuchObject`` here.
    """
    dotted = oid.lstrip(".")
    for root in unimplemented_roots(model):
        if dotted == root or dotted.startswith(root + "."):
            return False
    return True


def vendor_oids(model: SwitchModel) -> VendorOids:
    """Resolve vendor OIDs for a switch model.

    Args:
        model: A SwitchModel instance with snmp_vendor_base set.

    Returns:
        VendorOids dataclass populated with vendor-specific OID strings.

    Raises:
        UnsupportedCapabilityError: If the model has no SNMP vendor base.
    """
    base = model.snmp_vendor_base
    if base is None:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no SNMP vendor OID subtree"
        )
    return VendorOids(
        base=base,
        poe_power_mw=f"{base}.15.1.1.1.2",
        box_fan=f"{base}.43.1.6.1.4",
        box_psu_power=f"{base}.43.1.8.1.5",
        box_temp=f"{base}.43.1.15.1.3",
        dhcp_mode_unverified=f"{base}.{DHCP_MODE_OID_SUFFIX}",
        mgmt_write_addr_unverified=f"{base}.98.1",
        mgmt_write_netmask_unverified=f"{base}.98.2",
        mgmt_write_gateway_unverified=f"{base}.98.3",
    )
