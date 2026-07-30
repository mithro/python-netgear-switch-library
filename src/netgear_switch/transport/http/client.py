"""httpx-backed web-UI clients implementing the session Protocols.

One codebase: all URL/crypto/parse logic lives in the pure ``protocols.http``
package; only the actual GET/POST differ between the sync ``httpx.Client`` and
async ``httpx.AsyncClient``. Legacy Plus switches are HTTP-only, so ``base_url``
defaults to ``http://``; the ``secure`` flag flips it to ``https://`` (and the
Referer scheme with it) for a model whose real UI is HTTPS -- the M4300-16X
Cheetah UI on :49152. TLS verification defaults off for the switches'
self-signed certs.

httpx is an optional dependency (``[http]`` extra); it is imported at module
top-level because this module lives under ``transport/http`` and is only ever
imported lazily by ``_dispatch`` (function-local imports), exactly like the
SNMP transports — ``import netgear_switch`` never reaches here.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import quote

import httpx

from ...errors import HttpAuthError, HttpError, HttpUnexpectedPageError
from ...protocols.http.crypt import merge_hash_md5
from ...protocols.http.endpoints import LoginScheme
from ...protocols.http.parse import parse_gambit_token, parse_login_rand

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from types import TracebackType
    from typing import Self

    from ...protocols.http.endpoints import HttpModelSpec
    from ...protocols.http.session import MultipartFile

_TIMEOUT = 15.0


# M4300 Cheetah login form CSRF field: ``<input ... name="CSRFToken"
# value="...">`` (attribute case/quoting varies by firmware). Match the token
# regardless of whether ``value`` precedes or follows ``name``.
_CHEETAH_CSRF_RE = re.compile(
    r'name=["\']?CSRFToken["\']?[^>]*?value=["\']([^"\']*)["\']'
    r'|value=["\']([^"\']*)["\'][^>]*?name=["\']?CSRFToken["\']?',
    re.IGNORECASE,
)


def _cheetah_csrf_token(login_page_html: str) -> str | None:
    """The M4300 Cheetah login form's ``CSRFToken`` value, or ``None`` if the
    form has no such field (older 24X firmware). Pure; shared sync+async."""
    m = _CHEETAH_CSRF_RE.search(login_page_html)
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def _login_body(
    spec: HttpModelSpec, password: str, login_page_html: str
) -> dict[str, str]:
    """Build the login POST body for ``spec`` (pure; shared sync+async).

    MERGE_HASH_CGI/GAMBIT hash the password with the page ``rand`` nonce;
    CHEETAH_FORM posts the plaintext password. Raises ``HttpUnexpectedPageError``
    if a required ``rand`` nonce is missing from the login page.
    """
    if spec.scheme is LoginScheme.CHEETAH_V1:
        # M4300 /v1: plaintext username + password, no nonce.
        body = {
            spec.username_field or "uname": spec.username,
            spec.password_field: password,
        }
        # The AV-era 16X firmware (HTTPS Cheetah on :49152) issues a per-page
        # CSRFToken hidden field and BINDS the session cookie to it: without the
        # token the login POST still returns a SIDSSL cookie, but every later
        # read 302-bounces to the login page (session unbound). Confirmed live by
        # isolation: token+port-Referer -> 200 data; drop the token -> 302. Older
        # 24X firmware has no such field, so include it only when present.
        token = _cheetah_csrf_token(login_page_html)
        if token is not None:
            body["CSRFToken"] = token
        return body
    if spec.scheme is LoginScheme.CHEETAH_FORM:
        # gsm7228ps posts the password alone; the gsm7252ps XE login form also
        # carries a username field (uname=admin, live-confirmed on 10.1.5.22)
        # which that firmware validates -- so send it whenever the spec names
        # one, and keep the password-only body when it does not.
        body = {spec.password_field: password}
        if spec.username_field is not None:
            body[spec.username_field] = spec.username
        return body
    rand = parse_login_rand(login_page_html) if spec.needs_rand else None
    if spec.needs_rand and not rand:
        raise HttpUnexpectedPageError(
            f"no login 'rand' nonce on {spec.login_path} — not a {spec.model_key}?"
        )
    hashed = merge_hash_md5(password, rand or "")
    return {spec.password_field: hashed}


# GS728TPP GoAhead XML_API: the login GET / 302-redirects to a per-session
# path (``/cs5f72b8e1/``); this pulls that opaque path token out of the
# ``Location`` header so every later read can be prefixed with it.
_XML_API_SESSION_PATH_RE = re.compile(r"/([A-Za-z0-9]+)/")


def _xml_api_session_path(resp: httpx.Response) -> str:
    """The per-session path from the login redirect's ``Location`` header, or
    raise ``HttpAuthError`` (pure; shared sync+async)."""
    location = resp.headers.get("Location", "")
    m = _XML_API_SESSION_PATH_RE.search(location)
    if not m:
        raise HttpAuthError(
            f"GS728TPP login: GET / gave no session-path redirect "
            f"(Location={location!r})"
        )
    return m.group(1)


def _xml_api_login_url(spec: HttpModelSpec, session_path: str, password: str) -> str:
    """The ``System.xml?action=login`` GET URL under the session path (pure)."""
    return (
        f"/{session_path}/System.xml?action=login"
        f"&user={quote(spec.username)}&password={quote(password)}"
    )


def _apply_xml_api_login(
    spec: HttpModelSpec, resp: httpx.Response, cookies: httpx.Cookies
) -> None:
    """Validate the ``System.xml`` login response and set the session cookies.

    Success is ``<statusCode>0</statusCode>`` in the body AND a ``sessionID``
    RESPONSE HEADER (never a Set-Cookie on this firmware); the client then sets
    ``userStatus=ok``/``usernme=<user>``/``sessionID=<hdr>`` as cookies. Raises
    ``HttpAuthError`` on either missing (wrong password / lock-out). Pure w.r.t.
    the cookie jar; shared sync+async."""
    if "<statusCode>0</statusCode>" not in resp.text:
        raise HttpAuthError(
            f"web-UI login failed for {spec.model_key} — no <statusCode>0</"
            "statusCode> (check password, or switch may be locked out)"
        )
    session_id = resp.headers.get("sessionID", "")
    if not session_id:
        raise HttpAuthError(
            f"web-UI login failed for {spec.model_key} — no sessionID response header"
        )
    cookies.set("userStatus", "ok")
    cookies.set("usernme", spec.username)
    cookies.set(spec.cookie_name, session_id)


def _check_authed(spec: HttpModelSpec, cookies: httpx.Cookies) -> None:
    if spec.cookie_name not in cookies:
        raise HttpAuthError(
            f"web-UI login failed for {spec.model_key} — no {spec.cookie_name} cookie "
            "(check password, or switch may be locked out)"
        )


def _extract_session_token(spec: HttpModelSpec, html: str) -> str:
    """Pull the post-login session token out of the login POST response body
    for a token-session model (only GAMBIT/gs110emx exists today). Raises
    ``HttpAuthError`` if the page carries no non-empty token -- a wrong
    password, or the switch is locked out (pure; shared sync+async)."""
    token = parse_gambit_token(html)
    if not token:
        raise HttpAuthError(
            f"web-UI login failed for {spec.model_key} — no "
            f"{spec.session_token_field} token returned (check password, or "
            "switch may be locked out)"
        )
    return token


def _token_params(spec: HttpModelSpec, token: str) -> dict[str, str] | None:
    """The ``?<field>=<token>`` query params a token-session GET must carry,
    or ``None`` for a cookie-session model (pure; shared sync+async)."""
    if spec.session_token_field is None:
        return None
    return {spec.session_token_field: token}


def _token_form_field(spec: HttpModelSpec, token: str) -> dict[str, str]:
    """The ``{<field>: token}`` form field a token-session POST must carry
    alongside its own data, or ``{}`` for a cookie-session model (pure;
    shared sync+async)."""
    if spec.session_token_field is None:
        return {}
    return {spec.session_token_field: token}


# Real Plus hardware (GS105PE confirmed live 2026-07-21, GS110EMX similar)
# aggressively closes idle keep-alive connections, so the FIRST request reusing
# a pooled connection can fail with "Server disconnected without sending a
# response" even though the switch is healthy. Retrying re-establishes the
# connection and succeeds. This is a transport-level nicety, NOT error hiding:
# only httpx.RemoteProtocolError (a dropped connection, never an HTTP error
# status) is retried, and ONLY on GET -- POST may be a write (see post_form).
# The final failure still propagates as HttpError.
_DROPPED_CONNECTION_RETRIES = 2

# Legacy Plus switches close idle keep-alive connections so aggressively that a
# pooled connection is usually already dead by the next request (a real GS105PE
# drops EVERY first POST after a GET, and httpx would just retry on the same
# dead pooled connection). Disabling keep-alive costs one TCP handshake per
# request against a LAN switch and makes reads reliable.
_LIMITS = httpx.Limits(max_keepalive_connections=0)


def _retry_on_dropped_connection(
    send: Callable[[], httpx.Response], context: str
) -> httpx.Response:
    """Call ``send()``, retrying a dropped keep-alive connection (sync)."""
    last: httpx.RemoteProtocolError | None = None
    for _ in range(_DROPPED_CONNECTION_RETRIES + 1):
        try:
            return send()
        except httpx.RemoteProtocolError as exc:
            last = exc
    raise HttpError(f"{context}: connection dropped by switch: {last}") from last


async def _aretry_on_dropped_connection(
    send: Callable[[], Awaitable[httpx.Response]], context: str
) -> httpx.Response:
    """Async twin of ``_retry_on_dropped_connection``."""
    last: httpx.RemoteProtocolError | None = None
    for _ in range(_DROPPED_CONNECTION_RETRIES + 1):
        try:
            return await send()
        except httpx.RemoteProtocolError as exc:
            last = exc
    raise HttpError(f"{context}: connection dropped by switch: {last}") from last


def _referer_headers(spec: HttpModelSpec, host: str, *, secure: bool) -> dict[str, str]:
    """Headers every request must carry for this model.

    The M4300 Cheetah /v1 UI answers **403 Forbidden** to any request that
    lacks a ``Referer`` naming the switch itself -- a CSRF guard. Confirmed
    live: identical requests differ only by this header (403 without, 200
    with). The Referer scheme must match the connection scheme (``https`` when
    ``secure`` -- the real M4300-16X Cheetah UI is HTTPS on :49152) AND must
    carry the same port: the 16X answers **403** to a Referer that drops the
    :49152 (origin-exact CSRF check), so the host is used verbatim -- port and
    all. Standard-port models have no port in ``host`` and so are unaffected.
    Models that do not need it get no extra headers."""
    if not spec.needs_referer:
        return {}
    scheme = "https" if secure else "http"
    return {"Referer": f"{scheme}://{host}/"}


def _validate_response(
    resp: httpx.Response, *, context: str, path: str | None = None
) -> None:
    """Raise on an HTTP-error status, or (if ``path`` given) a lost session.

    Pure; shared by every sync/async GET/POST call site so status-code and
    stale-session handling cannot drift between the two codebases.

    ``context`` names the request for the status-code error (e.g. ``"GET
    /login.cgi"``). ``path`` is only passed by mid-session reads that should
    also detect the web-UI silently redirecting back to the login page.
    """
    if resp.status_code >= 400:
        raise HttpError(f"{context} returned HTTP {resp.status_code}")
    if path is not None and "redirect to login" in resp.text.lower():
        raise HttpAuthError(f"session lost fetching {path}")


class HttpClient:
    """Synchronous httpx web-UI session (implements ``HttpSession``)."""

    def __init__(
        self,
        host: str,
        password: str,
        spec: HttpModelSpec,
        *,
        secure: bool = False,
        verify_tls: bool = False,
        transport: httpx.MockTransport | None = None,
    ) -> None:
        self._spec = spec
        self._password = password
        scheme = "https" if secure else "http"
        self._client = httpx.Client(
            base_url=f"{scheme}://{host}",
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,
            follow_redirects=True,
            limits=_LIMITS,
            headers=_referer_headers(spec, host, secure=secure),
        )
        self._logged_in = False
        self._token = ""
        self._session_path = ""

    def _read_url(self, path: str) -> str:
        """Prefix the captured session path for the GoAhead XML_API (whose read
        paths are wcd queries relative to ``/<sess>/``); pass others through."""
        if self._spec.scheme is LoginScheme.XML_API:
            return f"/{self._session_path}/{path}"
        return path

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def login(self) -> None:
        if self._spec.scheme is LoginScheme.XML_API:
            self._xml_api_login()
            return
        post_path = self._spec.login_post_path or self._spec.login_path
        try:
            page = self._client.get(self._spec.login_path)
            _validate_response(page, context=f"GET {self._spec.login_path}")
            body = _login_body(self._spec, self._password, page.text)
            resp = self._client.post(post_path, data=body)
            _validate_response(resp, context=f"POST {post_path}")
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        if self._spec.session_token_field is not None:
            self._token = _extract_session_token(self._spec, resp.text)
        else:
            _check_authed(self._spec, self._client.cookies)
        self._logged_in = True

    def _xml_api_login(self) -> None:
        """GS728TPP GoAhead three-step login (see ``LoginScheme.XML_API``)."""
        try:
            redirect = self._client.get(self._spec.login_path, follow_redirects=False)
            self._session_path = _xml_api_session_path(redirect)
            url = _xml_api_login_url(self._spec, self._session_path, self._password)
            resp = self._client.get(url)
            _validate_response(resp, context="GET System.xml?action=login")
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        _apply_xml_api_login(self._spec, resp, self._client.cookies)
        self._logged_in = True

    def get_page(self, path: str) -> str:
        if not self._logged_in:
            self.login()
        url = self._read_url(path)
        params = _token_params(self._spec, self._token)
        try:
            resp = _retry_on_dropped_connection(
                lambda: self._client.get(url, params=params), f"GET {path}"
            )
        except httpx.HTTPError as exc:
            raise HttpError(f"GET {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"GET {path}", path=path)
        return resp.text

    def post_form(self, path: str, data: dict[str, str]) -> str:
        if not self._logged_in:
            self.login()
        body = {**data, **_token_form_field(self._spec, self._token)}
        try:
            # NEVER retried: post_form also carries WRITES (set_poe, set_pvid,
            # VLAN create/delete, reboot -- see http_write.py). A dropped
            # connection does NOT prove the switch ignored the request; a
            # reboot POST is answered by dropping the link, so retrying would
            # re-issue the write against a switch that already applied it.
            resp = self._client.post(path, data=body)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        if not self._logged_in:
            self.login()
        body = {**data, **_token_form_field(self._spec, self._token)}
        files = {file.field: (file.filename, file.content, file.content_type)}
        try:
            # NEVER retried -- like post_form, this carries a WRITE (an SSL-cert
            # upload). A dropped connection does not prove the switch ignored it.
            resp = self._client.post(path, data=body, files=files)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    def post_xml(self, path: str, body: str) -> str:
        if not self._logged_in:
            self.login()
        # The GS728TPP GoAhead cert upload POSTs a raw XML body to the
        # session-path-prefixed ``wcd`` endpoint (``_read_url`` adds the
        # ``/<sess>/`` prefix, exactly like the reads).
        url = self._read_url(path)
        try:
            # NEVER retried -- this carries a WRITE (the SSL-cert import). A
            # dropped connection does not prove the switch ignored it.
            resp = self._client.post(
                url,
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/xml; charset=utf-8"},
            )
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    def close(self) -> None:
        self._client.close()


class AsyncHttpClient:
    """Asynchronous httpx web-UI session (implements ``AsyncHttpSession``)."""

    def __init__(
        self,
        host: str,
        password: str,
        spec: HttpModelSpec,
        *,
        secure: bool = False,
        verify_tls: bool = False,
        transport: httpx.MockTransport | None = None,
    ) -> None:
        self._spec = spec
        self._password = password
        scheme = "https" if secure else "http"
        self._client = httpx.AsyncClient(
            base_url=f"{scheme}://{host}",
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,
            follow_redirects=True,
            limits=_LIMITS,
            headers=_referer_headers(spec, host, secure=secure),
        )
        self._logged_in = False
        self._token = ""
        self._session_path = ""

    def _read_url(self, path: str) -> str:
        """Async twin of ``HttpClient._read_url`` (session-path prefixing)."""
        if self._spec.scheme is LoginScheme.XML_API:
            return f"/{self._session_path}/{path}"
        return path

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def login(self) -> None:
        if self._spec.scheme is LoginScheme.XML_API:
            await self._xml_api_login()
            return
        post_path = self._spec.login_post_path or self._spec.login_path
        try:
            page = await self._client.get(self._spec.login_path)
            _validate_response(page, context=f"GET {self._spec.login_path}")
            body = _login_body(self._spec, self._password, page.text)
            resp = await self._client.post(post_path, data=body)
            _validate_response(resp, context=f"POST {post_path}")
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        if self._spec.session_token_field is not None:
            self._token = _extract_session_token(self._spec, resp.text)
        else:
            _check_authed(self._spec, self._client.cookies)
        self._logged_in = True

    async def _xml_api_login(self) -> None:
        """Async twin of ``HttpClient._xml_api_login``."""
        try:
            redirect = await self._client.get(
                self._spec.login_path, follow_redirects=False
            )
            self._session_path = _xml_api_session_path(redirect)
            url = _xml_api_login_url(self._spec, self._session_path, self._password)
            resp = await self._client.get(url)
            _validate_response(resp, context="GET System.xml?action=login")
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        _apply_xml_api_login(self._spec, resp, self._client.cookies)
        self._logged_in = True

    async def get_page(self, path: str) -> str:
        if not self._logged_in:
            await self.login()
        url = self._read_url(path)
        params = _token_params(self._spec, self._token)
        try:
            resp = await _aretry_on_dropped_connection(
                lambda: self._client.get(url, params=params), f"GET {path}"
            )
        except httpx.HTTPError as exc:
            raise HttpError(f"GET {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"GET {path}", path=path)
        return resp.text

    async def post_form(self, path: str, data: dict[str, str]) -> str:
        if not self._logged_in:
            await self.login()
        body = {**data, **_token_form_field(self._spec, self._token)}
        try:
            # NEVER retried -- see the sync twin: POST also carries writes.
            resp = await self._client.post(path, data=body)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    async def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        if not self._logged_in:
            await self.login()
        body = {**data, **_token_form_field(self._spec, self._token)}
        files = {file.field: (file.filename, file.content, file.content_type)}
        try:
            # NEVER retried -- see the sync twin: this carries a cert-upload write.
            resp = await self._client.post(path, data=body, files=files)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    async def post_xml(self, path: str, body: str) -> str:
        if not self._logged_in:
            await self.login()
        # Async twin of HttpClient.post_xml (session-path-prefixed raw XML POST).
        url = self._read_url(path)
        try:
            # NEVER retried -- see the sync twin: this carries a cert-upload write.
            resp = await self._client.post(
                url,
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/xml; charset=utf-8"},
            )
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        _validate_response(resp, context=f"POST {path}")
        return resp.text

    async def aclose(self) -> None:
        await self._client.aclose()
