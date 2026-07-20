from __future__ import annotations

import asyncio

import pytest

from netgear_switch._dispatch import (
    build_async_http_client,
    build_sync_http_client,
    http_reads_supported,
    require_http_backend,
)
from netgear_switch.errors import CredentialError, UnsupportedCapabilityError
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import AsyncHttpClient, HttpClient


def test_require_http_backend() -> None:
    require_http_backend(get_model("gs305ep"))  # no raise
    with pytest.raises(UnsupportedCapabilityError):
        require_http_backend(get_model("m4300-24x"))


def test_http_reads_supported() -> None:
    # gs305ep and gs110emx's web reads are both grounded (gs110emx: login +
    # sysInfo/interface_stats only -- see protocols/http/endpoints.py); NSDP
    # stays authoritative for the ops it already serves (see
    # sync_api.py/aio_api.py's per-op backend preference), so this flag only
    # ever matters for the ops NSDP genuinely can't serve.
    assert http_reads_supported(get_model("gs305ep")) is True    # NSDP+HTTP, grounded
    assert http_reads_supported(get_model("gsm7228ps")) is False  # SNMP-authoritative
    assert http_reads_supported(get_model("gs110emx")) is True    # Gambit, grounded
    assert http_reads_supported(get_model("m4300-24x")) is False  # no HTTP backend


def test_build_sync_http_client_requires_password() -> None:
    with pytest.raises(CredentialError):
        build_sync_http_client("sw.example", None, get_model("gs305ep"))
    client = build_sync_http_client("sw.example", "pw", get_model("gs305ep"))
    assert isinstance(client, HttpClient)
    client.close()


def test_build_async_http_client_requires_password() -> None:
    with pytest.raises(CredentialError):
        build_async_http_client("sw.example", None, get_model("gs305ep"))
    client = build_async_http_client("sw.example", "pw", get_model("gs305ep"))
    assert isinstance(client, AsyncHttpClient)
    asyncio.run(client.aclose())
