"""Internal backend-resolution seam shared by SyncSwitch and AsyncSwitch.

Only SNMP is wired in this slice. Model-driven dispatch lives here so the two
facades stay identical and Slices 5/6 can add NSDP/HTTP backends without
touching the public facade surface. Transport imports are function-local so
``import netgear_switch`` never requires net-snmp binaries or pysnmp.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import CredentialError, UnsupportedCapabilityError
from .registry import Backend

if TYPE_CHECKING:
    from .protocols.snmp.client import AsyncSnmpClient, SnmpClient
    from .registry import SwitchModel

BACKEND_NOT_IMPLEMENTED = (
    "model {key!r} has no SNMP backend; NSDP/HTTP read backends are not "
    "implemented yet (Slices 5-6)"
)


def require_snmp_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes an SNMP read backend."""
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(
            BACKEND_NOT_IMPLEMENTED.format(key=model.key)
        )


def require_mac_table(model: SwitchModel) -> None:
    """Raise unless the model has a readable MAC/FDB table."""
    if not model.has_mac_table:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no MAC/FDB table"
        )


def _require_community(host: str, community: str | None) -> str:
    if community is None:
        raise CredentialError(
            f"no SNMP read community configured for {host!r}"
        )
    return community


def build_sync_snmp_client(host: str, community: str | None) -> SnmpClient:
    """Default sync SNMP client (net-snmp CLI). Imported lazily."""
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    return NetsnmpCliClient(host, _require_community(host, community))


def build_async_snmp_client(host: str, community: str | None) -> AsyncSnmpClient:
    """Default async SNMP client (pysnmp). Imported lazily."""
    from .transport.aio.snmp_pysnmp import PysnmpClient

    return PysnmpClient(host, _require_community(host, community))
