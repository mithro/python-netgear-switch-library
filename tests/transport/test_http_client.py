from __future__ import annotations

import asyncio

import httpx
import pytest

from netgear_switch.errors import HttpAuthError
from netgear_switch.protocols.http.crypt import merge_hash_md5
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import (
    AsyncHttpClient,
    HttpClient,
    _login_body,
)

_SPEC = http_spec(get_model("gs305ep"))
_RAND = "9917"
_PASSWORD = "s3cr3t"
_LOGIN_HTML = f'<input id="rand" name="rand" value="{_RAND}">'


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login.cgi" and request.method == "GET":
        return httpx.Response(200, html=_LOGIN_HTML)
    if request.url.path == "/login.cgi" and request.method == "POST":
        body = dict(httpx.QueryParams(request.content.decode()))
        expected = merge_hash_md5(_PASSWORD, _RAND)
        if body.get("password") != expected:
            return httpx.Response(200, html="Login failed")
        return httpx.Response(
            200, html="OK", headers={"set-cookie": "SID=deadbeef; path=/"}
        )
    if request.url.path == "/dashboard.cgi":
        # Only reachable with the SID cookie set.
        if "SID=deadbeef" not in request.headers.get("cookie", ""):
            return httpx.Response(200, html="Redirect to login")
        return httpx.Response(200, html="<tr class='portID'><td>x</td></tr>")
    return httpx.Response(404)


def test_login_body_uses_merge_hash() -> None:
    body = _login_body(_SPEC, _PASSWORD, _LOGIN_HTML)
    assert body == {"password": merge_hash_md5(_PASSWORD, _RAND)}


def test_sync_login_then_get_page() -> None:
    client = HttpClient(
        "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
    )
    client.login()
    page = client.get_page("/dashboard.cgi")
    assert "portID" in page
    client.close()


def test_sync_login_wrong_password_raises_auth() -> None:
    client = HttpClient(
        "sw.example", "wrong", _SPEC, transport=httpx.MockTransport(_handler)
    )
    with pytest.raises(HttpAuthError):
        client.login()
    client.close()


def test_async_login_then_get_page() -> None:
    async def run() -> str:
        client = AsyncHttpClient(
            "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
        )
        await client.login()
        page = await client.get_page("/dashboard.cgi")
        await client.aclose()
        return page

    assert "portID" in asyncio.run(run())
