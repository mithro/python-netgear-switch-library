from __future__ import annotations

import asyncio

import httpx
import pytest

from netgear_switch.errors import (
    HttpAuthError,
    HttpError,
    HttpUnexpectedPageError,
)
from netgear_switch.protocols.http.crypt import merge_hash_md5
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import (
    AsyncHttpClient,
    HttpClient,
    _login_body,
)

# Fail this module's tests if they leak a ResourceWarning (e.g. an
# un-closed httpx.Client/AsyncClient) — a full-suite warning gate is
# deferred to the packaging slice, but this module can enforce it on
# itself now that Fix 2 makes the close-guarantee real.
pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

_SPEC = http_spec(get_model("gs305ep"))
_CHEETAH_SPEC = http_spec(get_model("gsm7228ps"))
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
    if request.url.path == "/8021qCf.cgi" and request.method == "POST":
        # Only reachable with the SID cookie set; echoes the posted vlan.
        if "SID=deadbeef" not in request.headers.get("cookie", ""):
            return httpx.Response(200, html="Redirect to login")
        body = dict(httpx.QueryParams(request.content.decode()))
        return httpx.Response(200, html=f"applied vlan={body.get('vlan')}")
    return httpx.Response(404)


def _error_handler(request: httpx.Request) -> httpx.Response:
    """Every request — including login — returns HTTP 500."""
    return httpx.Response(500, html="internal error")


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


# -- Fix 1/2: context-manager support + the underlying httpx client really closes --


def test_sync_close_closes_underlying_httpx_client() -> None:
    client = HttpClient(
        "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
    )
    assert client._client.is_closed is False
    client.close()
    assert client._client.is_closed is True


def test_sync_context_manager_closes_underlying_httpx_client() -> None:
    with HttpClient(
        "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
    ) as client:
        client.login()
        assert client._client.is_closed is False
    assert client._client.is_closed is True


def test_async_aclose_closes_underlying_httpx_client() -> None:
    async def run() -> AsyncHttpClient:
        client = AsyncHttpClient(
            "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
        )
        assert client._client.is_closed is False
        await client.aclose()
        return client

    client = asyncio.run(run())
    assert client._client.is_closed is True


def test_async_context_manager_closes_underlying_httpx_client() -> None:
    async def run() -> AsyncHttpClient:
        async with AsyncHttpClient(
            "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
        ) as client:
            await client.login()
            assert client._client.is_closed is False
        return client

    client = asyncio.run(run())
    assert client._client.is_closed is True


# -- Fix 3/4: shared validation helper + login() status-checks its own GET/POST --


def test_sync_login_transport_error_status_names_path_and_status() -> None:
    client = HttpClient(
        "sw.example",
        _PASSWORD,
        _SPEC,
        transport=httpx.MockTransport(_error_handler),
    )
    with pytest.raises(HttpError, match=r"GET /login\.cgi returned HTTP 500"):
        client.login()
    client.close()


def test_async_login_transport_error_status_names_path_and_status() -> None:
    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example",
            _PASSWORD,
            _SPEC,
            transport=httpx.MockTransport(_error_handler),
        )
        try:
            with pytest.raises(HttpError, match=r"GET /login\.cgi returned HTTP 500"):
                await client.login()
        finally:
            await client.aclose()

    asyncio.run(run())


# -- Fix 5: coverage for post_form, CHEETAH_FORM, missing rand, stale session --


def test_sync_post_form_posts_cookie_and_returns_body() -> None:
    client = HttpClient(
        "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
    )
    client.login()
    page = client.post_form("/8021qCf.cgi", {"vlan": "10"})
    assert page == "applied vlan=10"
    client.close()


def test_async_post_form_posts_cookie_and_returns_body() -> None:
    async def run() -> str:
        client = AsyncHttpClient(
            "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
        )
        await client.login()
        page = await client.post_form("/8021qCf.cgi", {"vlan": "10"})
        await client.aclose()
        return page

    assert asyncio.run(run()) == "applied vlan=10"


def test_login_body_cheetah_form_posts_plaintext_password() -> None:
    body = _login_body(_CHEETAH_SPEC, _PASSWORD, login_page_html="<html></html>")
    assert body == {"pwd": _PASSWORD}


def test_login_body_needs_rand_but_missing_raises_unexpected_page() -> None:
    with pytest.raises(HttpUnexpectedPageError):
        _login_body(_SPEC, _PASSWORD, login_page_html="<html>no rand here</html>")


def test_sync_get_page_mid_session_redirect_to_login_raises_auth() -> None:
    client = HttpClient(
        "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
    )
    # Skip login() so no SID cookie is set; the handler serves the
    # "redirect to login" page as it would for a server-expired session.
    client._logged_in = True
    with pytest.raises(
        HttpAuthError, match=r"session lost fetching /dashboard\.cgi"
    ):
        client.get_page("/dashboard.cgi")
    client.close()


def test_async_get_page_mid_session_redirect_to_login_raises_auth() -> None:
    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example", _PASSWORD, _SPEC, transport=httpx.MockTransport(_handler)
        )
        client._logged_in = True
        try:
            with pytest.raises(
                HttpAuthError, match=r"session lost fetching /dashboard\.cgi"
            ):
                await client.get_page("/dashboard.cgi")
        finally:
            await client.aclose()

    asyncio.run(run())
