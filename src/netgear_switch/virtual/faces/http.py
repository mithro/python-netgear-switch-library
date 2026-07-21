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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from ...protocols.http.crypt import merge_hash_md5
from ...protocols.http.endpoints import HttpModelSpec, LoginScheme
from .. import web, web_gs110emx

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

            def _body(self) -> dict[str, str]:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode() if length else ""
                return {k: v[0] for k, v in parse_qs(raw).items()}

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

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
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
                    else:
                        page = web.render_page(face.state, face.spec, path, {})
                self._send(page)

            def do_POST(self) -> None:
                path = self.path.split("?", 1)[0]
                form = self._body()
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

    def _login_response(self, form: dict[str, str]) -> str:
        field = self.spec.password_field
        supplied = form.get(field, "")
        if self.spec.scheme is LoginScheme.CHEETAH_FORM:
            ok = supplied == self.password
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
