"""A real ``http.server`` web-UI face serving a ``VirtualSwitchState``.

Binds a ``ThreadingHTTPServer`` to an ephemeral TCP port on ``127.0.0.1`` and
serves the login CGI + read/write CGI pages from device state via
``virtual.web``. Both httpx transport clients (sync + async) are exercised
end-to-end against it with no hardware.

A real switch never fabricates a 200 for a capability it doesn't have, so
this face 404s any request whose path is not one of this model's *populated*
``HttpModelSpec`` fields, before ever calling into ``virtual.web`` — that
module's ``render_page`` has a deliberately permissive catch-all (see its
docstring) that is only safe to reach for a path this spec actually
advertises.

Teardown is deterministic: ``stop()`` calls ``shutdown()`` (unblocks
``serve_forever``), joins the server thread, then ``server_close()`` closes the
listening socket — so nothing leaks under ``-W error::ResourceWarning``.
"""
from __future__ import annotations

import dataclasses
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from ...protocols.http.crypt import merge_hash_md5
from ...protocols.http.endpoints import HtmlDialect, HttpModelSpec, LoginScheme
from .. import (
    web,
    web_gs105pe,
    web_gs110emx,
    web_gs728tpp,
    web_gsm7252ps,
    web_m4300,
)

if TYPE_CHECKING:
    from ..state import VirtualSwitchState

# A virtual (non-real) session token issued to a token-session (GAMBIT)
# login on the mock face -- analogous to `_cookie` below for cookie-session
# models. Any non-empty string works: real hardware generates one per login,
# but the mock's job is proving the *shape* of the exchange (see
# `parse.parse_gambit_token`), not producing a cryptographically-real value.
_VIRTUAL_TOKEN = "virtual-gambit-session-token-0123456789abcdef"

# Every path-shaped field an HttpModelSpec may populate, other than
# login_path/login_post_path (both handled separately as the login
# handshake, never as a generically-servable read/write page). A model that
# leaves one of the rest None does not serve that endpoint at all.
#
# Derived from the dataclass itself (rather than hand-maintained) so a future
# spec field ending in "_path" is picked up automatically instead of silently
# 404ing forever.
_PATH_FIELDS: tuple[str, ...] = tuple(
    f.name
    for f in dataclasses.fields(HttpModelSpec)
    if f.name.endswith("_path") and f.name not in ("login_path", "login_post_path")
)


def _known_paths(spec: HttpModelSpec) -> set[str]:
    """The set of paths ``spec`` actually serves (populated fields only)."""
    return {
        value
        for name in _PATH_FIELDS
        if (value := getattr(spec, name)) is not None
    }


def _parse_multipart(
    raw: bytes, boundary: str
) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    """Minimal ``multipart/form-data`` parser for the mock face.

    Returns ``(fields, files)`` where ``fields`` maps each plain part's name to
    its text value and ``files`` maps each file part's name to
    ``(filename, content_bytes)``. Deliberately small (test infra only); it is
    enough to validate the field names and record the uploaded certificate.
    """
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    delim = b"--" + boundary.encode("latin-1")
    for chunk in raw.split(delim):
        # Trim only the ONE framing CRLF each side (never .strip(), which would
        # also eat an empty-value part's body separator -> the field would look
        # absent). The preamble ("") and the closing "--"/"--\r\n" have no
        # header block and fall through the ``\r\n\r\n`` check below.
        part = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        head, _, body = part.partition(b"\r\n\r\n")
        headers = head.decode("latin-1")
        name_m = re.search(r'name="([^"]*)"', headers)
        if name_m is None:
            continue
        name = name_m.group(1)
        file_m = re.search(r'filename="([^"]*)"', headers)
        if file_m is not None:
            files[name] = (file_m.group(1), body)
        else:
            fields[name] = body.decode("latin-1")
    return fields, files


class VirtualHttpFace:
    """A ``ThreadingHTTPServer`` web-UI face serving a ``VirtualSwitchState``."""

    def __init__(
        self,
        state: VirtualSwitchState,
        spec: HttpModelSpec,
        *,
        host: str = "127.0.0.1",
        password: str = "password",
        rand: str = "1234",
    ) -> None:
        self.state = state
        self.spec = spec
        self.host = host
        self.password = password
        self.rand = rand
        self._known_paths = _known_paths(spec)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._cookie = f"{spec.cookie_name}=virtualsid"
        self._token = _VIRTUAL_TOKEN
        # Fixed per-session path the GoAhead XML_API login redirect advertises
        # (real firmware mints a fresh one per login; the mock proves the shape,
        # not the randomness -- like ``_token`` for the GAMBIT scheme).
        self._session_path = "cs0000face"
        # ThreadingHTTPServer runs one thread per request; do_GET/do_POST
        # mutate shared VirtualSwitchState via web.render_page/apply_form
        # with no lock of their own, so two overlapping requests (e.g. a
        # sync and an async client hitting the same VirtualSwitch) would
        # race. Serialize just the render/apply critical section on this
        # single lock rather than the whole request.
        self._lock = threading.Lock()

    def start(self) -> int:
        face = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:  # silence stderr
                return

            def _raw(self) -> bytes:
                length = int(self.headers.get("Content-Length", "0"))
                return self.rfile.read(length) if length else b""

            def _body(self, raw: bytes) -> dict[str, str]:
                return {
                    k: v[0] for k, v in parse_qs(raw.decode("latin-1")).items()
                }

            def _send(
                self, text: str, status: int = 200, *, cookie: bool = False
            ) -> None:
                data = text.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                if cookie:
                    self.send_header("Set-Cookie", f"{face._cookie}; path=/")
                self.end_headers()
                self.wfile.write(data)

            def _referer_ok(self) -> bool:
                """Mirror real hardware's CSRF guard: a model with
                ``needs_referer`` (the M4300 /v1 UI) answers 403 to any request
                without a Referer, so a transport that stopped sending it would
                be caught here rather than passing silently."""
                if not face.spec.needs_referer:
                    return True
                return "Referer" in self.headers

            def _goahead_get(self) -> None:
                """Serve the GoAhead XML_API GET flow: GET / -> 302 to the
                session path; ``<sess>/System.xml?action=login`` -> statusCode +
                sessionID header; ``<sess>/wcd?{..}`` -> the rendered data
                block. Any other path 404s (the mock never fabricates a page)."""
                from urllib.parse import parse_qs, unquote

                path_only = self.path.split("?", 1)[0]
                query = self.path[len(path_only) + 1 :] if "?" in self.path else ""
                if path_only == "/":
                    self.send_response(302)
                    self.send_header("Location", f"/{face._session_path}/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path_only.endswith("/System.xml") and "action=login" in query:
                    params = {k: v[0] for k, v in parse_qs(query).items()}
                    ok = params.get("user") == face.spec.username and params.get(
                        "password"
                    ) == face.password
                    code = "0" if ok else "1"
                    body = (
                        '<?xml version="1.0" encoding="UTF-8" ?>'
                        f"<ResponseData><statusCode>{code}</statusCode>"
                        "</ResponseData>"
                    )
                    data = body.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/xml")
                    if ok:
                        self.send_header("sessionID", "virtualsid")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                decoded = unquote(self.path)
                if "wcd?" in decoded:
                    # Real hardware refuses an unauthenticated wcd read (it
                    # redirects to the login page); mirror that so the suite
                    # catches a client that reads before logging in. The
                    # transport sets sessionID=virtualsid as a cookie post-login.
                    if "sessionID=virtualsid" not in self.headers.get("Cookie", ""):
                        self.send_response(302)
                        self.send_header("Location", f"/{face._session_path}/")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    with face._lock:
                        page = web_gs728tpp.render_wcd(
                            face.state, decoded[decoded.find("wcd?") :]
                        )
                    if page is None:
                        self._send("<html><body>Not Found</body></html>", 404)
                    else:
                        self._send(page)
                    return
                self._send("<html><body>Not Found</body></html>", 404)

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if not self._referer_ok():
                    self._send("403 Forbidden", 403)
                    return
                if face.spec.html_dialect is HtmlDialect.GOAHEAD_XML:
                    self._goahead_get()
                    return
                if path == face.spec.login_path:
                    if face.spec.session_token_field is not None:
                        self._send(web_gs110emx.render_login(face.rand))
                    else:
                        self._send(web.render_login(face.rand))
                    return
                if path not in face._known_paths:
                    self._send("<html><body>Not Found</body></html>", 404)
                    return
                with face._lock:
                    if face.spec.session_token_field is not None:
                        page = face._render_token_page(path, {})
                    elif (gs105 := face._render_gs105pe_page(path, {})) is not None:
                        page = gs105
                    elif (m43 := face._render_m4300_page(path)) is not None:
                        page = m43
                    elif (xe := face._render_xe_page(path)) is not None:
                        page = xe
                    else:
                        page = web.render_page(face.state, face.spec, path, {})
                self._send(page)

            def do_POST(self) -> None:
                path = self.path.split("?", 1)[0]
                if not self._referer_ok():
                    self._send("403 Forbidden", 403)
                    return
                if face.spec.html_dialect is HtmlDialect.GOAHEAD_XML:
                    # The GoAhead read surface is GET-only; no write flow is
                    # wired for this model, so a POST is honestly Not Found.
                    self._send("<html><body>Not Found</body></html>", 404)
                    return
                raw = self._raw()
                content_type = self.headers.get("Content-Type", "")
                # SSL-cert upload: a multipart POST to this model's grounded
                # cert-upload endpoint. Handle it BEFORE the urlencoded body
                # parse (a multipart body is not urlencoded) so the mock records
                # the certificate exactly as real firmware would receive it.
                if (
                    path == face.spec.cert_upload_path
                    and content_type.startswith("multipart/form-data")
                ):
                    status, page = face._handle_cert_upload(content_type, raw)
                    self._send(page, status)
                    return
                form = self._body(raw)
                login_post_path = face.spec.login_post_path or face.spec.login_path
                if path == login_post_path:
                    ok = face._login_response(form) == "OK"
                    if face.spec.session_token_field is not None:
                        token = face._token if ok else ""
                        self._send(web_gs110emx.render_redirect(token))
                    else:
                        self._send("OK" if ok else "Login failed", cookie=ok)
                    return
                if path not in face._known_paths:
                    self._send("<html><body>Not Found</body></html>", 404)
                    return
                with face._lock:
                    if face.spec.session_token_field is not None:
                        page = face._render_token_page(path, form)
                    elif (gs105 := face._render_gs105pe_page(path, form)) is not None:
                        page = gs105
                    elif (m43 := face._render_m4300_page(path)) is not None:
                        page = m43
                    elif (xe := face._render_xe_page(path)) is not None:
                        page = xe
                    else:
                        web.apply_form(face.state, face.spec, path, form)
                        page = web.render_page(face.state, face.spec, path, form)
                self._send(page)

        server = ThreadingHTTPServer((self.host, 0), Handler)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="virtual-http-face", daemon=True
        )
        self._thread.start()
        return int(server.server_address[1])

    def _render_gs105pe_page(
        self, path: str, form: dict[str, str]
    ) -> str | None:
        """Render a GS105PE read page from state, or ``None`` if this model is
        not gs105pe (so the caller falls through to the generic renderer).

        Without this, a gs105pe VirtualSwitch fell through to ``web.render_page``
        whose permissive catch-all returns a fabricated 200 -- the mock silently
        reported every port DOWN while the seed had ports 3 and 5 UP, exactly
        the "mock must never fabricate" rule this face's docstring states.
        """
        from ...protocols.http.endpoints import HtmlDialect

        if self.spec.html_dialect is not HtmlDialect.GS105PE:
            return None
        if path == self.spec.dashboard_path:
            return web_gs105pe.render_status(self.state)
        if path == self.spec.stats_path:
            return web_gs105pe.render_port_statistics(self.state)
        if path == self.spec.pvid_path:
            return web_gs105pe.render_pvid(self.state)
        if path == self.spec.vlan_config_path:
            return web_gs105pe.render_vlan_config(self.state)
        if path == self.spec.sysinfo_path:
            return web_gs105pe.render_switch_info(self.state)
        if path == self.spec.vlan_membership_path:
            # A GET (no VLAN_ID) shows the lowest VLAN, matching real firmware;
            # a POST selects the requested one.
            vid = int(form.get("VLAN_ID", "0")) or min(self.state.vlans, default=1)
            return web_gs105pe.render_vlan_membership(self.state, vid)
        return None

    def _render_m4300_page(self, path: str) -> str | None:
        """Render an M4300 Cheetah /v1 read page from state, or ``None`` if
        this model is not an M4300 (so the caller falls through)."""
        from ...protocols.http.endpoints import HtmlDialect

        if self.spec.html_dialect is not HtmlDialect.M4300:
            return None
        if path == self.spec.dashboard_path:
            return web_m4300.render_ports(self.state)
        if path == self.spec.stats_path:
            return web_m4300.render_port_statistics(self.state)
        if path == self.spec.pvid_path:
            return web_m4300.render_pvids(self.state)
        if path == self.spec.vlan_config_path:
            return web_m4300.render_vlans(self.state)
        if path == self.spec.mac_table_path:
            return web_m4300.render_mac_table(self.state)
        if path == self.spec.sysinfo_path:
            return web_m4300.render_sysinfo(self.state)
        return None

    def _render_xe_page(self, path: str) -> str | None:
        """Render a GSM7252PS XE FASTPATH read page from state, or ``None`` if
        this model is not XE (so the caller falls through).

        Every path this model's spec advertises is rendered here: falling
        through to ``web.render_page``'s permissive catch-all would answer a
        fabricated 200 for a page the mock cannot actually build -- the exact
        failure that once made a gs105pe mock report every port down."""
        from ...protocols.http.endpoints import HtmlDialect

        if self.spec.html_dialect is not HtmlDialect.XE_FASTPATH:
            return None
        if path == self.spec.dashboard_path:
            return web_gsm7252ps.render_ports(self.state)
        if path == self.spec.stats_path:
            return web_gsm7252ps.render_port_statistics(self.state)
        if path == self.spec.pvid_path:
            return web_gsm7252ps.render_pvids(self.state)
        if path == self.spec.vlan_config_path:
            return web_gsm7252ps.render_vlans(self.state)
        if path == self.spec.mac_table_path:
            return web_gsm7252ps.render_mac_table(self.state)
        if path == self.spec.poe_status_path:
            return web_gsm7252ps.render_poe(self.state)
        if path == self.spec.lldp_path:
            return web_gsm7252ps.render_lldp(self.state)
        if path == self.spec.sysinfo_path:
            return web_gsm7252ps.render_sysinfo(self.state)
        return None

    def _render_token_page(self, path: str, form: dict[str, str]) -> str:
        """Render one of a token-session model's known GET/POST paths from
        state, so the gs110emx HTTP face serves the FULL NSDP read surface
        (ports/stats/VLANs/PVIDs/mgmt-IP) that real hardware does -- see
        ``web_gs110emx.render_*``. ``form`` carries the VLAN_ID for a
        vlanMembership POST. Any path not populated in the spec 404s honestly
        (``_known_paths`` already gates on the spec's populated fields)."""
        if path == self.spec.sysinfo_path:
            return web_gs110emx.render_sysinfo(self.state, self._token)
        if path == self.spec.stats_path:
            return web_gs110emx.render_interface_stats(self.state, self._token)
        if path == self.spec.dashboard_path:
            return web_gs110emx.render_port_settings(self.state, self._token)
        if path == self.spec.pvid_path:
            return web_gs110emx.render_pvid(self.state, self._token)
        if path == self.spec.vlan_config_path:
            return web_gs110emx.render_cf8021q(self.state, self._token)
        if path == self.spec.vlan_membership_path:
            vid = int(form.get("VLAN_ID", "1"))
            return web_gs110emx.render_vlan_membership(self.state, self._token, vid)
        return "<html><body>Not Found</body></html>"

    def _handle_cert_upload(
        self, content_type: str, raw: bytes
    ) -> tuple[int, str]:
        """Accept a multipart SSL-cert upload, validate the field names the
        real S3300 form carries, and record the received certificate on state.

        Returns ``(status, page)``. A missing boundary, missing file field, or
        any missing required form field yields 400 -- so a transport regression
        that dropped a field would be caught here rather than passing silently,
        exactly like the login-field validation in ``_login_response``.
        """
        match = re.search(r"boundary=([^;]+)", content_type)
        if match is None:
            return 400, "<html><body>missing multipart boundary</body></html>"
        boundary = match.group(1).strip().strip('"')
        fields, files = _parse_multipart(raw, boundary)
        file_field = self.spec.cert_upload_file_field
        if file_field is None or file_field not in files:
            return 400, "<html><body>missing cert file field</body></html>"
        missing = [k for k in self.spec.cert_upload_form_fields if k not in fields]
        if missing:
            return 400, f"<html><body>missing fields: {missing}</body></html>"
        _filename, content = files[file_field]
        with self._lock:
            self.state.uploaded_cert = content.decode("latin-1")
        return 200, "<html><body>File transfer in progress</body></html>"

    def _login_response(self, form: dict[str, str]) -> str:
        field = self.spec.password_field
        supplied = form.get(field, "")
        if self.spec.scheme in (LoginScheme.CHEETAH_FORM, LoginScheme.CHEETAH_V1):
            # Both post the password in plaintext. A spec that names a username
            # field (M4300 /v1, and the gsm7252ps XE login form) also sends a
            # username, which the real UI validates alongside the password --
            # so the mock validates it too, or a transport regression that
            # dropped it would pass CI while failing on hardware.
            ok = supplied == self.password
            if self.spec.username_field is not None:
                ok = ok and form.get(self.spec.username_field, "") == (
                    self.spec.username
                )
        else:
            ok = supplied == merge_hash_md5(self.password, self.rand)
        return "OK" if ok else "Login failed"

    def stop(self) -> None:
        """Stop the serve thread and close the listening socket deterministically."""
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._server is not None:
            self._server.server_close()
            self._server = None
