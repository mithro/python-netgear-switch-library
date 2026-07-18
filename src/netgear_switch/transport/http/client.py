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
from ...protocols.http.parse import parse_login_rand

if TYPE_CHECKING:
    from ...protocols.http.endpoints import HttpModelSpec

_TIMEOUT = 15.0


def _login_body(
    spec: HttpModelSpec, password: str, login_page_html: str
) -> dict[str, str]:
    """Build the login POST body for ``spec`` (pure; shared sync+async).

    MERGE_HASH_CGI/GAMBIT hash the password with the page ``rand`` nonce;
    CHEETAH_FORM posts the plaintext password. Raises ``HttpUnexpectedPageError``
    if a required ``rand`` nonce is missing from the login page.
    """
    if spec.scheme is LoginScheme.CHEETAH_FORM:
        return {spec.password_field: password}
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
        self._base = f"http://{host}"
        self._client = httpx.Client(
            base_url=self._base,
            timeout=_TIMEOUT,
            verify=verify_tls,
            transport=transport,
            follow_redirects=True,
        )
        self._logged_in = False

    def login(self) -> None:
        try:
            page = self._client.get(self._spec.login_path)
            body = _login_body(self._spec, self._password, page.text)
            self._client.post(self._spec.login_path, data=body)
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        _check_authed(self._spec, self._client.cookies)
        self._logged_in = True

    def get_page(self, path: str) -> str:
        if not self._logged_in:
            self.login()
        try:
            resp = self._client.get(path)
        except httpx.HTTPError as exc:
            raise HttpError(f"GET {path} transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise HttpError(f"GET {path} returned HTTP {resp.status_code}")
        if "redirect to login" in resp.text.lower():
            raise HttpAuthError(f"session lost fetching {path}")
        return resp.text

    def post_form(self, path: str, data: dict[str, str]) -> str:
        if not self._logged_in:
            self.login()
        try:
            resp = self._client.post(path, data=data)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise HttpError(f"POST {path} returned HTTP {resp.status_code}")
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
        )
        self._logged_in = False

    async def login(self) -> None:
        try:
            page = await self._client.get(self._spec.login_path)
            body = _login_body(self._spec, self._password, page.text)
            await self._client.post(self._spec.login_path, data=body)
        except httpx.HTTPError as exc:
            raise HttpError(f"web-UI login transport error: {exc}") from exc
        _check_authed(self._spec, self._client.cookies)
        self._logged_in = True

    async def get_page(self, path: str) -> str:
        if not self._logged_in:
            await self.login()
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise HttpError(f"GET {path} transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise HttpError(f"GET {path} returned HTTP {resp.status_code}")
        if "redirect to login" in resp.text.lower():
            raise HttpAuthError(f"session lost fetching {path}")
        return resp.text

    async def post_form(self, path: str, data: dict[str, str]) -> str:
        if not self._logged_in:
            await self.login()
        try:
            resp = await self._client.post(path, data=data)
        except httpx.HTTPError as exc:
            raise HttpError(f"POST {path} transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise HttpError(f"POST {path} returned HTTP {resp.status_code}")
        return resp.text

    async def aclose(self) -> None:
        await self._client.aclose()
