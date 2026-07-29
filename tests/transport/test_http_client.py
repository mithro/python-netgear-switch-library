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
    _extract_session_token,
    _login_body,
    _token_form_field,
    _token_params,
)

# Fail this module's tests if they leak a ResourceWarning (e.g. an
# un-closed httpx.Client/AsyncClient) — a full-suite warning gate is
# deferred to the packaging slice, but this module can enforce it on
# itself now that Fix 2 makes the close-guarantee real.
pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

_SPEC = http_spec(get_model("gs305ep"))
_CHEETAH_SPEC = http_spec(get_model("gsm7228ps"))
_GAMBIT_SPEC = http_spec(get_model("gs110emx"))
_RAND = "9917"
_PASSWORD = "s3cr3t"
_LOGIN_HTML = f'<input id="rand" name="rand" value="{_RAND}">'

_GAMBIT_RAND = "4242"
_GAMBIT_PASSWORD = "gambitpass"
_GAMBIT_TOKEN = "realtoken789"
_GAMBIT_LOGIN_HTML = f'<input id="rand" name="rand" value="{_GAMBIT_RAND}">'


def _gambit_handler(request: httpx.Request) -> httpx.Response:
    """Minimal GAMBIT (gs110emx-shaped) token-session server: GET "/" for
    `rand`, POST hashed password to /redirect.html for a Gambit token, then
    require ?Gambit=<token> on every subsequent GET -- mirrors the real
    scheme (see protocols/http/endpoints.py's _GS110EMX) without depending on
    the virtual mock (VirtualHttpFace)."""
    if request.url.path == _GAMBIT_SPEC.login_path and request.method == "GET":
        return httpx.Response(200, html=_GAMBIT_LOGIN_HTML)
    if request.url.path == _GAMBIT_SPEC.login_post_path and request.method == "POST":
        body = dict(httpx.QueryParams(request.content.decode()))
        expected = merge_hash_md5(_GAMBIT_PASSWORD, _GAMBIT_RAND)
        if body.get("LoginPassword") != expected:
            return httpx.Response(
                200, html='<input type="hidden" name="Gambit" value="">'
            )
        return httpx.Response(
            200, html=f'<input type="hidden" name="Gambit" value="{_GAMBIT_TOKEN}">'
        )
    if request.url.path == _GAMBIT_SPEC.sysinfo_path:
        if request.url.params.get("Gambit") != _GAMBIT_TOKEN:
            return httpx.Response(200, html="Redirect to login")
        return httpx.Response(200, html="<html>sysinfo ok</html>")
    return httpx.Response(404)


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


def _post_error_handler(request: httpx.Request) -> httpx.Response:
    """Login GET succeeds, but POST returns HTTP 500."""
    if request.url.path == "/login.cgi" and request.method == "GET":
        return httpx.Response(200, html=_LOGIN_HTML)
    if request.url.path == "/login.cgi" and request.method == "POST":
        return httpx.Response(500, html="internal error")
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


def test_sync_login_post_transport_error_status_names_path_and_status() -> None:
    client = HttpClient(
        "sw.example",
        _PASSWORD,
        _SPEC,
        transport=httpx.MockTransport(_post_error_handler),
    )
    with pytest.raises(HttpError, match=r"POST /login\.cgi returned HTTP 500"):
        client.login()
    client.close()


def test_async_login_post_transport_error_status_names_path_and_status() -> None:
    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example",
            _PASSWORD,
            _SPEC,
            transport=httpx.MockTransport(_post_error_handler),
        )
        try:
            with pytest.raises(HttpError, match=r"POST /login\.cgi returned HTTP 500"):
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


# -- Gap 3: token-session (GAMBIT) transport-unit coverage ------------------


def test_extract_session_token_returns_token_when_present() -> None:
    html = f'<input type="hidden" name="Gambit" value="{_GAMBIT_TOKEN}">'
    assert _extract_session_token(_GAMBIT_SPEC, html) == _GAMBIT_TOKEN


def test_extract_session_token_raises_auth_error_when_empty() -> None:
    html = '<input type="hidden" name="Gambit" value="">'
    with pytest.raises(HttpAuthError):
        _extract_session_token(_GAMBIT_SPEC, html)


def test_extract_session_token_raises_auth_error_when_field_absent() -> None:
    with pytest.raises(HttpAuthError):
        _extract_session_token(_GAMBIT_SPEC, "<html>no token field here</html>")


def test_token_params_carries_field_for_token_session_spec() -> None:
    assert _token_params(_GAMBIT_SPEC, _GAMBIT_TOKEN) == {"Gambit": _GAMBIT_TOKEN}


def test_token_params_none_for_cookie_session_spec() -> None:
    # gs305ep is cookie-session (session_token_field is None) -- no query
    # params are added; the SID cookie carries the session instead.
    assert _token_params(_SPEC, "unused") is None


def test_token_form_field_carries_field_for_token_session_spec() -> None:
    assert _token_form_field(_GAMBIT_SPEC, _GAMBIT_TOKEN) == {
        "Gambit": _GAMBIT_TOKEN
    }


def test_token_form_field_empty_for_cookie_session_spec() -> None:
    assert _token_form_field(_SPEC, "unused") == {}


def test_sync_gambit_login_gets_login_path_but_posts_to_login_post_path() -> None:
    # GAMBIT's rand nonce is scraped from a GET of login_path ("/"), but the
    # hashed password is POSTed to a DIFFERENT path (login_post_path,
    # "/redirect.html") -- unlike gs305ep/gsm7228ps, where POST goes back to
    # login_path itself (login_post_path is None there).
    assert _GAMBIT_SPEC.login_path == "/"
    assert _GAMBIT_SPEC.login_post_path == "/redirect.html"
    client = HttpClient(
        "sw.example", _GAMBIT_PASSWORD, _GAMBIT_SPEC,
        transport=httpx.MockTransport(_gambit_handler),
    )
    try:
        client.login()
        assert client._token == _GAMBIT_TOKEN
        page = client.get_page(_GAMBIT_SPEC.sysinfo_path)
        assert "sysinfo ok" in page
    finally:
        client.close()


def test_sync_gambit_wrong_password_raises_auth_error() -> None:
    client = HttpClient(
        "sw.example", "wrong-password", _GAMBIT_SPEC,
        transport=httpx.MockTransport(_gambit_handler),
    )
    try:
        with pytest.raises(HttpAuthError):
            client.login()
    finally:
        client.close()


def test_async_gambit_wrong_password_raises_auth_error() -> None:
    """Async twin of test_sync_gambit_wrong_password_raises_auth_error: a
    rejected Gambit token (empty value) must raise HttpAuthError, not be
    treated as a valid (empty-string) session."""

    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example", "wrong-password", _GAMBIT_SPEC,
            transport=httpx.MockTransport(_gambit_handler),
        )
        try:
            with pytest.raises(HttpAuthError):
                await client.login()
        finally:
            await client.aclose()

    asyncio.run(run())


def test_sync_get_page_mid_session_stale_gambit_token_raises_auth() -> None:
    """A token session that gets a login page back mid-read (a stale/
    invalidated token the server no longer honours) must raise HttpAuthError,
    not silently misparse the login page as if it were real content --
    mirrors the cookie path's test_sync_get_page_mid_session_redirect_to_
    login_raises_auth above."""
    client = HttpClient(
        "sw.example", _GAMBIT_PASSWORD, _GAMBIT_SPEC,
        transport=httpx.MockTransport(_gambit_handler),
    )
    client._logged_in = True
    client._token = "stale-token"  # the server no longer recognizes this
    try:
        with pytest.raises(
            HttpAuthError, match=r"session lost fetching /iss/specific/sysInfo\.html"
        ):
            client.get_page(_GAMBIT_SPEC.sysinfo_path)
    finally:
        client.close()


def test_async_get_page_mid_session_stale_gambit_token_raises_auth() -> None:
    """Async twin of the stale-token test above."""

    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example", _GAMBIT_PASSWORD, _GAMBIT_SPEC,
            transport=httpx.MockTransport(_gambit_handler),
        )
        client._logged_in = True
        client._token = "stale-token"
        try:
            with pytest.raises(
                HttpAuthError,
                match=r"session lost fetching /iss/specific/sysInfo\.html",
            ):
                await client.get_page(_GAMBIT_SPEC.sysinfo_path)
        finally:
            await client.aclose()

    asyncio.run(run())


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


# -- HTTPS transport: the `secure` flag flips base_url + Referer to https ----
# (the real M4300-16X Cheetah UI is HTTPS on :49152; see endpoints._M4300_16X).

_M4300_SPEC = http_spec(get_model("m4300-24x"))  # needs_referer=True


def test_secure_false_builds_http_base_url_and_referer() -> None:
    # Default (secure omitted): plain http base_url + http Referer -- the mock
    # HTTP face and every legacy Plus model rely on this staying unchanged.
    client = HttpClient("sw.example", _PASSWORD, _M4300_SPEC)
    try:
        assert str(client._client.base_url) == "http://sw.example"
        assert client._client.headers["Referer"] == "http://sw.example/"
    finally:
        client.close()


def test_secure_true_builds_https_base_url_and_referer() -> None:
    client = HttpClient(
        "sw.example:49152", _PASSWORD, _M4300_SPEC, secure=True
    )
    try:
        assert str(client._client.base_url) == "https://sw.example:49152"
        # Referer strips the port (host only), and its scheme tracks `secure`.
        assert client._client.headers["Referer"] == "https://sw.example/"
    finally:
        client.close()


def test_async_secure_true_builds_https_base_url_and_referer() -> None:
    async def run() -> None:
        client = AsyncHttpClient(
            "sw.example:49152", _PASSWORD, _M4300_SPEC, secure=True
        )
        try:
            assert str(client._client.base_url) == "https://sw.example:49152"
            assert client._client.headers["Referer"] == "https://sw.example/"
        finally:
            await client.aclose()

    asyncio.run(run())
