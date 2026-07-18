from __future__ import annotations

import pytest

from netgear_switch import _dispatch
from netgear_switch.errors import CredentialError, UnsupportedCapabilityError
from netgear_switch.registry import get_model


def test_require_snmp_backend_passes_for_snmp_model() -> None:
    # gsm7252ps has {SNMP}; must not raise.
    _dispatch.require_snmp_backend(get_model("gsm7252ps"))


def test_require_snmp_backend_raises_for_plus_model() -> None:
    with pytest.raises(UnsupportedCapabilityError) as exc:
        _dispatch.require_snmp_backend(get_model("gs305ep"))  # {NSDP, HTTP}
    msg = str(exc.value)
    assert "gs305ep" in msg
    assert "not" in msg
    assert "implemented" in msg


def test_require_mac_table_passes_for_snmp_model() -> None:
    _dispatch.require_mac_table(get_model("gsm7252ps"))


def test_require_mac_table_raises_for_plus_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        _dispatch.require_mac_table(get_model("gs305ep"))


def test_build_sync_client_requires_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_sync_snmp_client("sw.example", None)


def test_build_async_client_requires_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_async_snmp_client("sw.example", None)


def test_build_sync_client_returns_netsnmp_cli_client() -> None:
    from netgear_switch.transport.sync.snmp_netsnmp_cli import NetsnmpCliClient

    client = _dispatch.build_sync_snmp_client("sw.example", "public")
    assert isinstance(client, NetsnmpCliClient)
    assert client.host == "sw.example"
    assert client.community == "public"


def test_build_async_client_returns_pysnmp_client() -> None:
    from netgear_switch.transport.aio.snmp_pysnmp import PysnmpClient

    client = _dispatch.build_async_snmp_client("sw.example", "public")
    assert isinstance(client, PysnmpClient)
    assert client.host == "sw.example"
    assert client.community == "public"


def test_build_sync_write_client_requires_write_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_sync_snmp_write_client("host", None)
    client = _dispatch.build_sync_snmp_write_client("host", "wcomm")
    assert client.community == "wcomm"


def test_build_sync_write_client_rejects_empty_community() -> None:
    # An empty string must be rejected too, not just None -- an unresolved
    # write-community spec must never silently flow to `snmpset -c ""`.
    with pytest.raises(CredentialError):
        _dispatch.build_sync_snmp_write_client("host", "")


def test_build_async_write_client_requires_write_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_async_snmp_write_client("host", None)
    client = _dispatch.build_async_snmp_write_client("host", "wcomm")
    assert client.community == "wcomm"


def test_build_async_write_client_rejects_empty_community() -> None:
    with pytest.raises(CredentialError):
        _dispatch.build_async_snmp_write_client("host", "")


def test_require_nsdp_backend_passes_for_plus_model() -> None:
    _dispatch.require_nsdp_backend(get_model("gs110emx"))


def test_require_nsdp_backend_raises_for_snmp_only_model() -> None:
    with pytest.raises(UnsupportedCapabilityError):
        _dispatch.require_nsdp_backend(get_model("gsm7252ps"))


def test_build_sync_nsdp_client_returns_udp_client() -> None:
    from netgear_switch.transport.sync.nsdp_udp import UdpNsdpClient

    client = _dispatch.build_sync_nsdp_client("10.1.5.20", None)
    assert isinstance(client, UdpNsdpClient)
    assert client.host == "10.1.5.20"


def test_build_async_nsdp_client_returns_async_udp_client() -> None:
    from netgear_switch.transport.aio.nsdp_udp import AsyncUdpNsdpClient

    client = _dispatch.build_async_nsdp_client("10.1.5.20", "eth0")
    assert isinstance(client, AsyncUdpNsdpClient)
    assert client.host == "10.1.5.20"
