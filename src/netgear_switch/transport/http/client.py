"""httpx-backed web-UI clients implementing the session Protocols.

One codebase: all URL/crypto/parse logic lives in the pure ``protocols.http``
package; only the actual GET/POST differ between the sync ``httpx.Client`` and
async ``httpx.AsyncClient``. Legacy Plus switches are HTTP-only, so ``base_url``
is ``http://`` and TLS verification (when a model ever needs https) defaults to
off for permissive legacy behaviour.

httpx is an optional dependency (``[http]`` extra); it is imported at module
top-level because this module lives under ``transport/http`` and is only ever
imported lazily by ``_dispatch`` (function-local imports), exactly like the
SNMP transports — ``import netgear_switch`` never reaches here.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

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
        return {
            spec.username_field or "uname": spec.username,
            spec.password_field: password,
        }
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


def _referer_headers(spec: HttpModelSpec, host: str) -> dict[str, str]:
    """Headers every request must carry for this model.

    The M4300 Cheetah /v1 UI answers **403 Forbidden** to any request that
    lacks a ``Referer`` naming the switch itself -- a CSRF guard. Confirmed
    live: identical requests differ only by this header (403 without, 200
    with). Models that do not need it get no extra headers."""
    if not spec.needs_referer:
        return {}
    return {"Referer": f"http://{host.split(':', 1)[0]}/"}


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
        verify_tls: bool = False,
        transport: httpx.MockTransport | None = None,
    ) -> None:
        self._spec = spec
        self._password = password
        self._client = httpx.Client(
            base_url=f"http://{host}",
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,
            follow_redirects=True,
            limits=_LIMITS,
            headers=_referer_headers(spec, host),
        )
        self._logged_in = False
        self._token = ""

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

    def get_page(self, path: str) -> str:
        if not self._logged_in:
            self.login()
        params = _token_params(self._spec, self._token)
        try:
            resp = _retry_on_dropped_connection(
                lambda: self._client.get(path, params=params), f"GET {path}"
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
        verify_tls: bool = False,
        transport: httpx.MockTransport | None = None,
    ) -> None:
        self._spec = spec
        self._password = password
        self._client = httpx.AsyncClient(
            base_url=f"http://{host}",
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,
            follow_redirects=True,
            limits=_LIMITS,
            headers=_referer_headers(spec, host),
        )
        self._logged_in = False
        self._token = ""

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

    async def get_page(self, path: str) -> str:
        if not self._logged_in:
            await self.login()
        params = _token_params(self._spec, self._token)
        try:
            resp = await _aretry_on_dropped_connection(
                lambda: self._client.get(path, params=params), f"GET {path}"
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

    async def aclose(self) -> None:
        await self._client.aclose()
