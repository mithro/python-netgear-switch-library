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
    from .protocols.http.endpoints import HttpModelSpec
    from .protocols.nsdp.client import AsyncNsdpWriteClient, NsdpWriteClient
    from .protocols.snmp.client import (
        AsyncSnmpClient,
        AsyncSnmpWriteClient,
        SnmpClient,
        SnmpWriteClient,
    )
    from .registry import SwitchModel
    from .transport.cli.session import CliSession
    from .transport.http.client import AsyncHttpClient, HttpClient

BACKEND_NOT_IMPLEMENTED = (
    "model {key!r} has no SNMP backend; its NSDP backend is used instead. "
    "(An HTTP-only capability is not implemented until Slice 6.)"
)


def require_snmp_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes an SNMP read backend."""
    if Backend.SNMP not in model.backends:
        raise UnsupportedCapabilityError(BACKEND_NOT_IMPLEMENTED.format(key=model.key))


def require_mac_table(model: SwitchModel) -> None:
    """Raise unless the model has a readable MAC/FDB table."""
    if not model.has_mac_table:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no MAC/FDB table")


def require_nsdp_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes an NSDP backend."""
    if Backend.NSDP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no NSDP backend")


def _require_community(host: str, community: str | None) -> str:
    if community is None:
        raise CredentialError(f"no SNMP read community configured for {host!r}")
    return community


def build_sync_snmp_client(host: str, community: str | None) -> SnmpClient:
    """Default sync SNMP client (net-snmp CLI). Imported lazily."""
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    return NetsnmpCliClient(host, _require_community(host, community))


def build_async_snmp_client(host: str, community: str | None) -> AsyncSnmpClient:
    """Default async SNMP client (pysnmp). Imported lazily."""
    from .transport.aio.snmp_pysnmp import PysnmpClient

    return PysnmpClient(host, _require_community(host, community))


def _require_write_community(host: str, community: str | None) -> str:
    # An empty string must be rejected too, not just None -- otherwise an
    # unresolved/blank write-community spec could silently flow through to
    # `snmpset -c ""` instead of raising (carry-forward review fix).
    if not community:
        raise CredentialError(f"no SNMP write community configured for {host!r}")
    return community


def build_sync_snmp_write_client(
    host: str, write_community: str | None
) -> SnmpWriteClient:
    """Default sync SNMP write client (net-snmp CLI). Imported lazily."""
    from .transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    return NetsnmpCliClient(host, _require_write_community(host, write_community))


def build_async_snmp_write_client(
    host: str, write_community: str | None
) -> AsyncSnmpWriteClient:
    """Default async SNMP write client (pysnmp). Imported lazily."""
    from .transport.aio.snmp_pysnmp import PysnmpClient

    return PysnmpClient(host, _require_write_community(host, write_community))


def build_sync_nsdp_client(host: str, interface: str | None) -> NsdpWriteClient:
    """Default sync NSDP client (UDP). One client does read AND write, so the
    return is annotated with the richer ``NsdpWriteClient`` protocol (the
    concrete ``UdpNsdpClient`` satisfies it; ``NsdpWriteClient`` extends
    ``NsdpClient`` so a read-only caller can still use it). Lazy import."""
    from .transport.sync.nsdp_udp import UdpNsdpClient

    return UdpNsdpClient(host, interface=interface)


def build_async_nsdp_client(host: str, interface: str | None) -> AsyncNsdpWriteClient:
    """Default async NSDP client (asyncio UDP). Read AND write; annotated with
    the richer ``AsyncNsdpWriteClient`` protocol (``AsyncUdpNsdpClient`` satisfies
    it and it extends ``AsyncNsdpClient``, so ``_reader()`` can still accept it).
    Lazy import."""
    from .transport.aio.nsdp_udp import AsyncUdpNsdpClient

    return AsyncUdpNsdpClient(host, interface=interface)


def require_http_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes an HTTP web-UI backend."""
    if Backend.HTTP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no HTTP backend")


def http_reads_supported(model: SwitchModel) -> bool:
    """True only if the model's web reads/writes are grounded (reads_verified).

    The facade uses this to decide whether HTTP may join the per-op backend
    fallback. An UNVERIFIED-pending-capture model (gsm7228ps cheetah) returns
    False: its HTTP path is never used for read/write dispatch (SNMP stays
    authoritative; HTTP is reserved for firmware/reboot). gs110emx's Gambit
    login + sysInfo/interface_stats reads ARE grounded (see
    ``protocols/http/endpoints.py``), so this returns True for it -- but NSDP
    is still authoritative for every op it serves (ports/VLANs/PVIDs/stats/
    mgmt-IP). In practice this means gs110emx's HTTP get_stats/get_mgmt_ip
    are NEVER actually reached through the SyncSwitch/AsyncSwitch facade:
    NSDP's own get_stats/get_mgmt_ip always return a result rather than
    raising ``UnsupportedCapabilityError`` (unlike get_macs/get_lldp/
    get_sensors/get_poe, which NSDP genuinely doesn't have and does raise for),
    so the facade's per-op backend loop never falls through to HTTP for those
    two ops -- only a directly-constructed ``HttpReader``/``AsyncHttpReader``
    exercises them. The lazy import keeps ``import netgear_switch`` clear of
    the endpoints module on the hot path (endpoints is pure, but this mirrors
    the other lazy builders).
    """
    if Backend.HTTP not in model.backends:
        return False
    from .protocols.http.endpoints import HTTP_SPECS

    spec = HTTP_SPECS.get(model.key)
    return spec is not None and spec.reads_verified


def require_cli_backend(model: SwitchModel) -> None:
    """Raise unless the model exposes a CLI (SSH/telnet/console) backend."""
    from .protocols.cli.commands import CLI_BACKENDS

    if not (CLI_BACKENDS & model.backends):
        raise UnsupportedCapabilityError(f"model {model.key!r} has no CLI backend")


def cli_reads_supported(model: SwitchModel) -> bool:
    """True only once a model's CLI reads are cross-verified (reads_verified).

    Mirrors ``http_reads_supported``. A CLI spec with ``reads_verified=False``
    (CLI reader output not yet cross-verified against SNMP on live hardware)
    gates OFF. The FASTPATH models (m4300-24x/-16x, gsm7252ps) are now verified
    and return True; other models return False and the facade never dispatches
    a live read to their CLI backend. The parsers and the in-process mock CLI
    face are exercised independently of this gate.
    """
    from .protocols.cli.commands import CLI_BACKENDS, CLI_SPECS

    if not (CLI_BACKENDS & model.backends):
        return False
    spec = CLI_SPECS.get(model.key)
    return spec is not None and spec.reads_verified


def build_sync_cli_client(
    host: str,
    username: str,
    password: str | None,
    model: SwitchModel,
) -> CliSession:
    """Default sync CLI session: the SSH transport (paramiko). Imported lazily.

    The other two transports (telnet/console) exist for direct construction but
    SSH is the facade's default network CLI transport.
    """
    from .protocols.cli.commands import cli_spec
    from .transport.cli.ssh import SshCliTransport

    if not password:
        raise CredentialError(f"no CLI password configured for {host!r}")
    return SshCliTransport(host, username, password, cli_spec(model))


def _require_http_password(host: str, password: str | None) -> str:
    if not password:
        raise CredentialError(f"no HTTP password configured for {host!r}")
    return password


def _http_host(host: str, spec: HttpModelSpec) -> str:
    """The web-UI host[:port] for ``spec``: the bare IP for a standard-port
    model, or ``<ip>:<web_port>`` for one on a non-standard port (m4300-16x on
    :49152). ``host`` is the switch IP, never already carrying a port."""
    return f"{host}:{spec.web_port}" if spec.web_port is not None else host


def build_sync_http_client(
    host: str, password: str | None, model: SwitchModel
) -> HttpClient:
    """Default sync web-UI client (httpx). Imported lazily."""
    from .protocols.http.endpoints import http_spec
    from .transport.http.client import HttpClient

    spec = http_spec(model)
    return HttpClient(
        _http_host(host, spec),
        _require_http_password(host, password),
        spec,
        secure=spec.secure,
    )


def build_async_http_client(
    host: str, password: str | None, model: SwitchModel
) -> AsyncHttpClient:
    """Default async web-UI client (httpx). Imported lazily."""
    from .protocols.http.endpoints import http_spec
    from .transport.http.client import AsyncHttpClient

    spec = http_spec(model)
    return AsyncHttpClient(
        _http_host(host, spec),
        _require_http_password(host, password),
        spec,
        secure=spec.secure,
    )
